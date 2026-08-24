#!/usr/bin/env bash
#
# harden_ubuntu24_cis_l1.sh
#
# CIS Level 1 style hardening for Ubuntu 24.04 LTS.
# Defaults to AUDIT ONLY. Pass --apply to make changes.
#
# Usage:
#   sudo ./harden_ubuntu24_cis_l1.sh [--apply] [--only sec1,sec2,...] [--list]
#
# See ../README.md and README.md in this directory for details and the
# control-by-control checklist.

set -uo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="/var/log/cis-hardening"
LOG_FILE="${LOG_DIR}/ubuntu-cis-l1-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cis-hardening/${TIMESTAMP}"

APPLY=0
ONLY=""
LIST_ONLY=0

PASS_COUNT=0
FIX_COUNT=0
WOULD_FIX_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# Ordered list of section function names, used for --list and --only.
ALL_SECTIONS=(
  filesystem_modules
  network_modules
  updates
  process_hardening
  apparmor
  banners
  services
  time_sync
  cron_at
  ssh
  pam
  access_control
  accounts
  file_perms
  sudo_logging
  kernel_params
  firewall
  auditd
  logging
  aide
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR" "$BACKUP_DIR" 2>/dev/null || true

log() {
  # log <LEVEL> <message>
  local level="$1"; shift
  local msg="$*"
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" | tee -a "$LOG_FILE" >/dev/null
}

say_pass()       { PASS_COUNT=$((PASS_COUNT+1));             printf '  \033[32mPASS\033[0m       %-8s %s\n' "$1" "$2"; log PASS "$1: $2"; }
say_fixed()      { FIX_COUNT=$((FIX_COUNT+1));                printf '  \033[36mFIXED\033[0m      %-8s %s\n' "$1" "$2"; log FIXED "$1: $2"; }
say_would_fix()  { WOULD_FIX_COUNT=$((WOULD_FIX_COUNT+1));    printf '  \033[33mWOULD FIX\033[0m  %-8s %s\n' "$1" "$2"; log WOULD_FIX "$1: $2"; }
say_skip()       { SKIP_COUNT=$((SKIP_COUNT+1));              printf '  \033[90mSKIP\033[0m       %-8s %s\n' "$1" "$2"; log SKIP "$1: $2"; }
say_error()      { ERROR_COUNT=$((ERROR_COUNT+1));            printf '  \033[31mERROR\033[0m      %-8s %s\n' "$1" "$2"; log ERROR "$1: $2"; }

# control <id> <description> <check_fn> <fix_fn>
# check_fn should return 0 if already compliant, 1 if not compliant, 2 if not applicable.
control() {
  local id="$1" desc="$2" check_fn="$3" fix_fn="$4"
  local rc
  "$check_fn" >/tmp/.cischeck.$$ 2>&1
  rc=$?
  case "$rc" in
    0) say_pass "$id" "$desc" ;;
    2) say_skip "$id" "$desc ($(cat /tmp/.cischeck.$$))" ;;
    1)
      if [[ "$APPLY" -eq 1 ]]; then
        if "$fix_fn" >/tmp/.cisfix.$$ 2>&1; then
          say_fixed "$id" "$desc"
        else
          say_error "$id" "$desc — fix failed: $(cat /tmp/.cisfix.$$)"
        fi
      else
        say_would_fix "$id" "$desc"
      fi
      ;;
    *) say_error "$id" "$desc — check failed: $(cat /tmp/.cischeck.$$)" ;;
  esac
  rm -f /tmp/.cischeck.$$ /tmp/.cisfix.$$
}

backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest"
}

# set_kv_space <file> <key> <value>  — "Key Value" style (sshd_config, etc.)
set_kv_space() {
  local file="$1" key="$2" value="$3"
  backup_file "$file"
  if grep -Eiq "^[[:space:]]*${key}[[:space:]]" "$file" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${key} ${value}|I" "$file"
  else
    printf '%s %s\n' "$key" "$value" >> "$file"
  fi
}

# set_sysctl <key> <value>
set_sysctl() {
  local key="$1" value="$2"
  local file="/etc/sysctl.d/60-cis-hardening.conf"
  backup_file "$file"
  touch "$file"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >> "$file"
  fi
  sysctl -w "${key}=${value}" >/dev/null 2>&1 || true
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }
svc_exists()    { systemctl list-unit-files 2>/dev/null | grep -q "^$1"; }
svc_enabled()   { systemctl is-enabled "$1" >/dev/null 2>&1; }
svc_active()    { systemctl is-active "$1" >/dev/null 2>&1; }

# is_container_host — detect whether this box runs Docker and/or Kubernetes.
# Several generic CIS Level 1 controls (IP forwarding, single-firewall-utility,
# flushing iptables to nftables) are actively wrong on such hosts: kube-proxy
# and CNI plugins (Calico/Flannel/Cilium/etc.) manage iptables/nftables rules
# directly, and IP forwarding is required for container/pod networking to
# work at all. Sections below check this once and adjust accordingly instead
# of silently "fixing" something that would break the cluster.
IS_CONTAINER_HOST=""
is_container_host() {
  if [[ -z "$IS_CONTAINER_HOST" ]]; then
    if svc_exists docker.service || svc_exists containerd.service || svc_exists kubelet.service || \
       svc_exists crio.service || command -v kubectl >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then
      IS_CONTAINER_HOST=1
    else
      IS_CONTAINER_HOST=0
    fi
  fi
  [[ "$IS_CONTAINER_HOST" -eq 1 ]]
}

GRUB_DEFAULT_FILE="/etc/default/grub"
# ensure_grub_cmdline_param <param> — append a kernel cmdline param (e.g.
# "audit=1") to GRUB_CMDLINE_LINUX in /etc/default/grub and regenerate
# grub.cfg. Does NOT reboot. Requires a reboot to actually take effect.
ensure_grub_cmdline_param() {
  local param="$1"
  [[ -f "$GRUB_DEFAULT_FILE" ]] || return 1
  backup_file "$GRUB_DEFAULT_FILE"
  if grep -Eq "^GRUB_CMDLINE_LINUX=.*${param}" "$GRUB_DEFAULT_FILE"; then
    : # already present
  elif grep -Eq '^GRUB_CMDLINE_LINUX=' "$GRUB_DEFAULT_FILE"; then
    sed -i -E "s/^GRUB_CMDLINE_LINUX=\"([^\"]*)\"/GRUB_CMDLINE_LINUX=\"\1 ${param}\"/" "$GRUB_DEFAULT_FILE"
  else
    printf 'GRUB_CMDLINE_LINUX="%s"\n' "$param" >> "$GRUB_DEFAULT_FILE"
  fi
  if command -v update-grub >/dev/null 2>&1; then
    update-grub >/dev/null 2>&1
  else
    grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
  fi
  log INFO "Added '$param' to GRUB_CMDLINE_LINUX — reboot required for it to take effect."
}
grub_cmdline_has_param() {
  local param="$1"
  grep -Eq "^GRUB_CMDLINE_LINUX=.*${param}" "$GRUB_DEFAULT_FILE" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 1. Filesystem — disable unneeded kernel modules
# ---------------------------------------------------------------------------
section_filesystem_modules() {
  echo "== 1. Filesystem: unused kernel modules =="
  local mods=(cramfs freevxfs jffs2 hfs hfsplus udf usb-storage)
  for m in "${mods[@]}"; do
    # usb-storage often needed on physical hosts (USB keyboards/installers via
    # USB mass storage are rare) — treat as SKIP by default, informational only.
    if [[ "$m" == "usb-storage" ]]; then
      control "FS.$m" "kernel module '$m' disabled (skipped by default — review manually)" \
        true_check_skip true_check_skip
      continue
    fi
    control "FS.$m" "kernel module '$m' is disabled and blacklisted" \
      "check_module_disabled_$m" "fix_module_disabled_$m"
  done
}
true_check_skip() { return 2; }

_module_disabled() {
  local m="$1"
  local conf="/etc/modprobe.d/cis-hardening-blacklist.conf"
  if lsmod | grep -q "^${m}[[:space:]]"; then
    return 1
  fi
  if [[ -f "$conf" ]] && grep -q "install ${m} /bin/false" "$conf" 2>/dev/null; then
    return 0
  fi
  # Not loaded and no explicit blacklist entry yet -> still needs the blacklist entry
  if [[ -f "$conf" ]] && grep -q "blacklist ${m}" "$conf" 2>/dev/null; then
    return 0
  fi
  return 1
}
_module_disable_fix() {
  local m="$1"
  local conf="/etc/modprobe.d/cis-hardening-blacklist.conf"
  backup_file "$conf"
  touch "$conf"
  grep -q "install ${m} /bin/false" "$conf" 2>/dev/null || echo "install ${m} /bin/false" >> "$conf"
  grep -q "blacklist ${m}" "$conf" 2>/dev/null || echo "blacklist ${m}" >> "$conf"
  modprobe -r "$m" 2>/dev/null || true
}
for _m in cramfs freevxfs jffs2 hfs hfsplus udf; do
  eval "check_module_disabled_${_m}() { _module_disabled ${_m}; }"
  eval "fix_module_disabled_${_m}() { _module_disable_fix ${_m}; }"
done

# ---------------------------------------------------------------------------
# 1b. Uncommon network protocol kernel modules (CIS 3.2.x)
# ---------------------------------------------------------------------------
# dccp/tipc/rds/sctp are rarely used protocols; disabling them shrinks the
# kernel attack surface. NOT used by standard Docker/Kubernetes networking
# (which relies on veth/bridge/overlay + iptables/nftables), so these are
# safe to disable even on a container host unless you know a workload
# specifically depends on one (e.g. SCTP-based Kubernetes Services, which
# require the SCTPSupport feature and are uncommon).
section_network_modules() {
  echo "== 1b. Uncommon network protocol kernel modules =="
  local mods=(dccp tipc rds sctp)
  for m in "${mods[@]}"; do
    control "NETMOD.$m" "kernel module '$m' is disabled and blacklisted" \
      "check_module_disabled_$m" "fix_module_disabled_$m"
  done
}
for _m in dccp tipc rds sctp; do
  eval "check_module_disabled_${_m}() { _module_disabled ${_m}; }"
  eval "fix_module_disabled_${_m}() { _module_disable_fix ${_m}; }"
done

# ---------------------------------------------------------------------------
# 2. Software updates
# ---------------------------------------------------------------------------
section_updates() {
  echo "== 2. Software updates =="
  control "UPD.unattended" "unattended-upgrades installed and enabled" \
    check_unattended check_unattended_fix
  control "UPD.gpgcheck" "APT GPG signature verification enforced" \
    check_apt_gpgcheck fix_apt_gpgcheck
}
check_unattended() {
  pkg_installed unattended-upgrades || return 1
  systemctl is-enabled unattended-upgrades.service >/dev/null 2>&1 || return 1
  grep -Eq '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' \
    /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || return 1
  return 0
}
check_unattended_fix() {
  apt-get update -qq && apt-get install -y -qq unattended-upgrades apt-listchanges
  systemctl enable --now unattended-upgrades.service
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}
check_apt_gpgcheck() {
  ! grep -Erq '^\s*(AllowUnauthenticated|Acquire::AllowInsecureRepositories)\s*"?(true|1)"?' /etc/apt/apt.conf.d/ 2>/dev/null
}
fix_apt_gpgcheck() {
  grep -Erl '^\s*(AllowUnauthenticated|Acquire::AllowInsecureRepositories)\s*"?(true|1)"?' /etc/apt/apt.conf.d/ 2>/dev/null | while read -r f; do
    backup_file "$f"
    sed -i -E 's/^\s*(AllowUnauthenticated|Acquire::AllowInsecureRepositories)\s*"?(true|1)"?;?/\1 "false";/' "$f"
  done
}

# ---------------------------------------------------------------------------
# 3. Process hardening
# ---------------------------------------------------------------------------
section_process_hardening() {
  echo "== 3. Process / kernel hardening =="
  control "PROC.aslr" "ASLR (kernel.randomize_va_space=2) enabled" \
    "check_sysctl_eq kernel.randomize_va_space 2" "fix_sysctl kernel.randomize_va_space 2"
  control "PROC.coredump_suid" "core dumps for setuid programs disabled (fs.suid_dumpable=0)" \
    "check_sysctl_eq fs.suid_dumpable 0" "fix_sysctl fs.suid_dumpable 0"
  control "PROC.coredump_limit" "core dumps disabled via limits.conf" \
    check_coredump_limits fix_coredump_limits
  control "PROC.coredump_systemd" "systemd-coredump storage disabled (Storage=none)" \
    check_coredump_systemd fix_coredump_systemd
  control "PROC.prelink" "prelink package not installed" \
    check_no_prelink fix_no_prelink
  control "PROC.apport" "Automatic Error Reporting (apport) disabled" \
    check_apport_disabled fix_apport_disabled
}
check_sysctl_eq() {
  local key="$1" want="$2"
  local cur
  cur="$(sysctl -n "$key" 2>/dev/null)" || return 1
  [[ "$cur" == "$want" ]]
}
fix_sysctl() { set_sysctl "$1" "$2"; }
check_coredump_limits() {
  grep -Eq '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.d/*.conf /etc/security/limits.conf 2>/dev/null
}
fix_coredump_limits() {
  local f="/etc/security/limits.d/60-cis-hardening.conf"
  backup_file "$f"
  printf '* hard core 0\n' >> "$f"
}
check_no_prelink() { ! pkg_installed prelink; }
fix_no_prelink() { apt-get purge -y -qq prelink 2>/dev/null || true; }
COREDUMP_CONF="/etc/systemd/coredump.conf"
check_coredump_systemd() {
  [[ -f "$COREDUMP_CONF" ]] || return 1
  grep -Eq '^\s*Storage\s*=\s*none' "$COREDUMP_CONF"
}
fix_coredump_systemd() {
  backup_file "$COREDUMP_CONF"
  mkdir -p /etc/systemd/coredump.conf.d
  touch "$COREDUMP_CONF"
  if grep -Eq '^\s*#?\s*Storage\s*=' "$COREDUMP_CONF"; then
    sed -i -E 's/^\s*#?\s*Storage\s*=.*/Storage=none/' "$COREDUMP_CONF"
  else
    printf '[Coredump]\nStorage=none\n' >> "$COREDUMP_CONF"
  fi
}
check_apport_disabled() {
  pkg_installed apport || return 0
  grep -Eq '^\s*enabled\s*=\s*0' /etc/default/apport 2>/dev/null
}
fix_apport_disabled() {
  backup_file /etc/default/apport
  if [[ -f /etc/default/apport ]]; then
    if grep -Eq '^\s*enabled\s*=' /etc/default/apport; then
      sed -i -E 's/^\s*enabled\s*=.*/enabled=0/' /etc/default/apport
    else
      echo 'enabled=0' >> /etc/default/apport
    fi
  fi
  systemctl stop apport.service 2>/dev/null || true
  systemctl disable apport.service 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 4. Mandatory Access Control — AppArmor
# ---------------------------------------------------------------------------
section_apparmor() {
  echo "== 4. AppArmor =="
  control "MAC.installed" "AppArmor installed" check_apparmor_installed fix_apparmor_installed
  control "MAC.bootloader" "AppArmor enabled via bootloader (apparmor=1 security=apparmor)" \
    check_apparmor_bootloader fix_apparmor_bootloader
  control "MAC.enabled" "AppArmor enabled and enforcing profiles present" check_apparmor_enforcing fix_apparmor_enforcing
}
check_apparmor_installed() { pkg_installed apparmor && pkg_installed apparmor-utils; }
fix_apparmor_installed() { apt-get update -qq && apt-get install -y -qq apparmor apparmor-utils; }
check_apparmor_enforcing() {
  command -v aa-status >/dev/null 2>&1 || return 1
  aa-status --enabled 2>/dev/null
  local rc=$?
  [[ $rc -eq 0 ]] || return 1
  aa-status 2>/dev/null | grep -q "profiles are in enforce mode" || return 1
  return 0
}
fix_apparmor_enforcing() {
  systemctl enable --now apparmor.service
  aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
}
check_apparmor_bootloader() {
  # Ubuntu's stock kernel already builds AppArmor in and enables it by
  # default (aa-status succeeding is sufficient evidence), so this is only
  # actually non-compliant on a custom kernel/cmdline that disabled it.
  aa-status >/dev/null 2>&1 && return 0
  [[ -f "$GRUB_DEFAULT_FILE" ]] || return 2   # not using GRUB (e.g. systemd-boot) — N/A
  grub_cmdline_has_param 'apparmor=1' && grub_cmdline_has_param 'security=apparmor'
}
fix_apparmor_bootloader() {
  ensure_grub_cmdline_param 'apparmor=1'
  ensure_grub_cmdline_param 'security=apparmor'
}

# ---------------------------------------------------------------------------
# 5. Warning banners
# ---------------------------------------------------------------------------
BANNER_TEXT='Authorized users only. All activity may be monitored and reported.'
section_banners() {
  echo "== 5. Warning banners =="
  for f in /etc/issue /etc/issue.net /etc/motd; do
    control "BANNER.${f##*/}" "$f contains an authorized-access warning banner" \
      "check_banner $f" "fix_banner $f"
  done
  control "BANNER.perms" "/etc/issue and /etc/issue.net are owned root:root, mode 0644" \
    check_banner_perms fix_banner_perms
}
check_banner() { local f="$1"; [[ -f "$f" ]] && grep -qi "authorized" "$f"; }
fix_banner() { local f="$1"; backup_file "$f"; printf '%s\n' "$BANNER_TEXT" > "$f"; }
check_banner_perms() {
  for f in /etc/issue /etc/issue.net; do
    [[ -f "$f" ]] || continue
    local o; o="$(stat -c '%U:%G:%a' "$f")"
    [[ "$o" == "root:root:644" ]] || return 1
  done
  return 0
}
fix_banner_perms() {
  for f in /etc/issue /etc/issue.net; do
    [[ -f "$f" ]] || continue
    chown root:root "$f"; chmod 644 "$f"
  done
}

# ---------------------------------------------------------------------------
# 6. Unnecessary network-facing services
# ---------------------------------------------------------------------------
section_services() {
  echo "== 6. Unnecessary services =="
  local svcs=(avahi-daemon cups isc-dhcp-server bind9 vsftpd slapd dovecot smbd nfs-server \
              ypserv rpcbind rsync snmpd tftpd-hpa squid nginx apache2 xinetd)
  for s in "${svcs[@]}"; do
    control "SVC.$s" "service '$s' not enabled (absent or explicitly disabled if not needed)" \
      "check_service_disabled $s" "fix_service_disabled $s"
  done

  control "SVC.telnet_client" "telnet client not installed" \
    "check_pkg_absent telnet" "fix_pkg_absent telnet"
  control "SVC.ftp_client" "ftp client not installed" \
    "check_pkg_absent ftp" "fix_pkg_absent ftp"
  control "SVC.xserver" "X window server packages not installed (servers should be headless)" \
    check_no_xserver fix_no_xserver
}
check_service_disabled() {
  local s="$1.service"
  svc_exists "$s" || return 2   # not installed -> N/A
  svc_enabled "$s" && return 1
  return 0
}
fix_service_disabled() {
  local s="$1.service"
  systemctl disable --now "$s" 2>/dev/null || true
}
check_pkg_absent() { ! pkg_installed "$1"; }
fix_pkg_absent() { apt-get purge -y -qq "$1" 2>/dev/null || true; }
check_no_xserver() { ! pkg_installed xserver-common; }
fix_no_xserver() {
  # Only meaningful on servers; if this is actually a workstation with a
  # desktop environment, skip this control via --only or edit the script.
  apt-get purge -y -qq xserver-common xserver-xorg-core 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 7. Time synchronization
# ---------------------------------------------------------------------------
CHRONY_CONF="/etc/chrony/chrony.conf"
section_time_sync() {
  echo "== 7. Time synchronization =="
  control "TIME.installed" "chrony or systemd-timesyncd installed and active" \
    check_time_sync fix_time_sync
  if pkg_installed chrony; then
    control "TIME.timeserver" "chrony has at least one server/pool configured" \
      check_chrony_timeserver fix_chrony_timeserver
    control "TIME.chronyuser" "chronyd runs as unprivileged user _chrony" \
      check_chrony_user fix_chrony_user
  fi
}
check_time_sync() {
  if pkg_installed chrony; then svc_active chronyd.service || svc_active chrony.service; return $?; fi
  svc_active systemd-timesyncd.service
}
fix_time_sync() {
  apt-get update -qq && apt-get install -y -qq chrony
  systemctl enable --now chronyd.service 2>/dev/null || systemctl enable --now chrony.service
}
check_chrony_timeserver() {
  [[ -f "$CHRONY_CONF" ]] || return 1
  grep -Eq '^\s*(server|pool)\s+\S+' "$CHRONY_CONF"
}
fix_chrony_timeserver() {
  # Adds Ubuntu's standard NTP pool as a safe, working default. If your org
  # runs internal time servers, replace this with your authorized source.
  backup_file "$CHRONY_CONF"
  touch "$CHRONY_CONF"
  cat >> "$CHRONY_CONF" <<'EOF'
pool ntp.ubuntu.com        iburst maxsources 4
pool 0.ubuntu.pool.ntp.org iburst maxsources 1
pool 1.ubuntu.pool.ntp.org iburst maxsources 1
pool 2.ubuntu.pool.ntp.org iburst maxsources 2
EOF
  systemctl restart chronyd.service 2>/dev/null || systemctl restart chrony.service 2>/dev/null || true
}
check_chrony_user() {
  svc_active chronyd.service 2>/dev/null || svc_active chrony.service 2>/dev/null || return 2
  local u
  u="$(ps -o user= -C chronyd 2>/dev/null | head -1 | tr -d '[:space:]')"
  [[ -z "$u" ]] && return 2
  [[ "$u" == "_chrony" ]]
}
fix_chrony_user() {
  local unit_dir
  if systemctl cat chronyd.service >/dev/null 2>&1; then unit_dir="/etc/systemd/system/chronyd.service.d"
  else unit_dir="/etc/systemd/system/chrony.service.d"; fi
  mkdir -p "$unit_dir"
  backup_file "${unit_dir}/override.conf"
  printf '[Service]\nUser=_chrony\n' > "${unit_dir}/override.conf"
  systemctl daemon-reload
  systemctl restart chronyd.service 2>/dev/null || systemctl restart chrony.service 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 8. cron/at restrictions
# ---------------------------------------------------------------------------
section_cron_at() {
  echo "== 8. cron / at =="
  control "CRON.svc" "cron service enabled and active" check_cron_active fix_cron_active
  control "CRON.perms" "cron config files owned root, not group/world writable" \
    check_cron_perms fix_cron_perms
  control "CRON.deny" "/etc/cron.deny and /etc/at.deny absent (allow-list model via cron.allow if used)" \
    check_cron_deny_absent fix_cron_deny_absent
}
check_cron_active() { svc_active cron.service; }
fix_cron_active() { systemctl enable --now cron.service; }
check_cron_perms() {
  for p in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [[ -e "$p" ]] || continue
    local perms; perms="$(stat -c '%a' "$p")"
    local owner; owner="$(stat -c '%U:%G' "$p")"
    [[ "$owner" == "root:root" ]] || return 1
    if [[ -d "$p" ]]; then [[ "$perms" -le 700 ]] || return 1
    else [[ "$perms" -le 600 ]] || return 1; fi
  done
  return 0
}
fix_cron_perms() {
  for p in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [[ -e "$p" ]] || continue
    chown root:root "$p"
    if [[ -d "$p" ]]; then chmod og-rwx "$p"; else chmod og-rwx "$p"; fi
  done
}
check_cron_deny_absent() { [[ ! -e /etc/cron.deny && ! -e /etc/at.deny ]]; }
fix_cron_deny_absent() { rm -f /etc/cron.deny /etc/at.deny; }

# ---------------------------------------------------------------------------
# 9. SSH server
# ---------------------------------------------------------------------------
SSHD_CONFIG="/etc/ssh/sshd_config"
section_ssh() {
  echo "== 9. SSH server hardening =="
  [[ -f "$SSHD_CONFIG" ]] || { say_skip "SSH.*" "openssh-server not installed"; return; }
  control "SSH.perms" "sshd_config owned root:root, mode 0600" check_sshd_perms fix_sshd_perms
  control "SSH.protocol" "Protocol 2 (implicit on modern openssh — no legacy Protocol line)" \
    check_ssh_no_legacy_protocol fix_ssh_no_legacy_protocol
  control "SSH.rootlogin" "PermitRootLogin no" "check_sshd_kv PermitRootLogin no" "fix_sshd_kv PermitRootLogin no"
  control "SSH.emptypass" "PermitEmptyPasswords no" "check_sshd_kv PermitEmptyPasswords no" "fix_sshd_kv PermitEmptyPasswords no"
  control "SSH.x11" "X11Forwarding no" "check_sshd_kv X11Forwarding no" "fix_sshd_kv X11Forwarding no"
  control "SSH.disableforwarding" "DisableForwarding yes" "check_sshd_kv DisableForwarding yes" "fix_sshd_kv DisableForwarding yes"
  control "SSH.maxstartups" "MaxStartups 10:30:60" check_ssh_maxstartups fix_ssh_maxstartups
  control "SSH.maxauth" "MaxAuthTries <= 4" check_ssh_maxauthtries fix_ssh_maxauthtries
  control "SSH.ignorerhosts" "IgnoreRhosts yes" "check_sshd_kv IgnoreRhosts yes" "fix_sshd_kv IgnoreRhosts yes"
  control "SSH.hostbased" "HostbasedAuthentication no" "check_sshd_kv HostbasedAuthentication no" "fix_sshd_kv HostbasedAuthentication no"
  control "SSH.userenv" "PermitUserEnvironment no" "check_sshd_kv PermitUserEnvironment no" "fix_sshd_kv PermitUserEnvironment no"
  control "SSH.clientalive" "ClientAliveInterval 300 / ClientAliveCountMax 3" check_ssh_clientalive fix_ssh_clientalive
  control "SSH.logingrace" "LoginGraceTime <= 60" check_ssh_logingrace fix_ssh_logingrace
  control "SSH.maxsessions" "MaxSessions <= 10" check_ssh_maxsessions fix_ssh_maxsessions
  control "SSH.loglevel" "LogLevel VERBOSE" "check_sshd_kv LogLevel VERBOSE" "fix_sshd_kv LogLevel VERBOSE"
  control "SSH.banner" "Banner /etc/issue.net" "check_sshd_kv Banner /etc/issue.net" "fix_sshd_kv Banner /etc/issue.net"
  control "SSH.ciphers" "Only strong Ciphers/MACs/KexAlgorithms configured" check_ssh_algos fix_ssh_algos
}
sshd_effective() { sshd -T 2>/dev/null; }
check_sshd_perms() {
  local perms; perms="$(stat -c '%a' "$SSHD_CONFIG")"
  local owner; owner="$(stat -c '%U:%G' "$SSHD_CONFIG")"
  [[ "$owner" == "root:root" && "$perms" -le 600 ]]
}
fix_sshd_perms() { chown root:root "$SSHD_CONFIG"; chmod 600 "$SSHD_CONFIG"; }
check_ssh_no_legacy_protocol() { ! grep -Eiq '^[[:space:]]*Protocol[[:space:]]+1' "$SSHD_CONFIG"; }
fix_ssh_no_legacy_protocol() { backup_file "$SSHD_CONFIG"; sed -i -E '/^[[:space:]]*Protocol[[:space:]]+1/d' "$SSHD_CONFIG"; }
check_sshd_kv() {
  local key="$1" want="$2"
  local val
  val="$(sshd_effective | awk -v k="$key" 'tolower($1)==tolower(k){print $2; found=1} END{if(!found) exit 1}')" || return 1
  [[ "${val,,}" == "${want,,}" ]]
}
fix_sshd_kv() { set_kv_space "$SSHD_CONFIG" "$1" "$2"; systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true; }
check_ssh_maxauthtries() {
  local v; v="$(sshd_effective | awk '$1=="maxauthtries"{print $2}')"
  [[ -n "$v" && "$v" -le 4 ]]
}
fix_ssh_maxauthtries() { set_kv_space "$SSHD_CONFIG" MaxAuthTries 4; }
check_ssh_clientalive() {
  local i c
  i="$(sshd_effective | awk '$1=="clientaliveinterval"{print $2}')"
  c="$(sshd_effective | awk '$1=="clientalivecountmax"{print $2}')"
  [[ -n "$i" && "$i" -gt 0 && "$i" -le 300 && -n "$c" && "$c" -le 3 ]]
}
fix_ssh_clientalive() { set_kv_space "$SSHD_CONFIG" ClientAliveInterval 300; set_kv_space "$SSHD_CONFIG" ClientAliveCountMax 3; }
check_ssh_logingrace() {
  local v; v="$(sshd_effective | awk '$1=="logingracetime"{print $2}')"
  [[ -n "$v" && "$v" -le 60 && "$v" != 0 ]]
}
fix_ssh_logingrace() { set_kv_space "$SSHD_CONFIG" LoginGraceTime 60; }
check_ssh_maxsessions() {
  local v; v="$(sshd_effective | awk '$1=="maxsessions"{print $2}')"
  [[ -n "$v" && "$v" -le 10 ]]
}
fix_ssh_maxsessions() { set_kv_space "$SSHD_CONFIG" MaxSessions 10; }
check_ssh_maxstartups() {
  local v; v="$(sshd_effective | awk '$1=="maxstartups"{print $2}')"
  [[ -n "$v" ]] || return 1
  local first="${v%%:*}"
  [[ "$first" -le 10 ]]
}
fix_ssh_maxstartups() { set_kv_space "$SSHD_CONFIG" MaxStartups "10:30:60"; }
check_ssh_algos() {
  grep -Eq '^[[:space:]]*Ciphers[[:space:]]' "$SSHD_CONFIG" && \
  grep -Eq '^[[:space:]]*MACs[[:space:]]' "$SSHD_CONFIG" && \
  grep -Eq '^[[:space:]]*KexAlgorithms[[:space:]]' "$SSHD_CONFIG"
}
fix_ssh_algos() {
  set_kv_space "$SSHD_CONFIG" Ciphers "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  set_kv_space "$SSHD_CONFIG" MACs "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
  set_kv_space "$SSHD_CONFIG" KexAlgorithms "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 10. PAM — password quality, lockout, history
# ---------------------------------------------------------------------------
section_pam() {
  echo "== 10. PAM: password quality / lockout / history =="
  control "PAM.pwquality_pkg" "libpam-pwquality installed" check_pwquality_pkg fix_pwquality_pkg
  control "PAM.minlen" "pwquality minlen >= 14" check_pwquality_minlen fix_pwquality_minlen
  control "PAM.complexity" "pwquality requires mixed character classes" check_pwquality_complexity fix_pwquality_complexity
  control "PAM.faillock" "faillock configured: deny<=5, unlock_time=900" check_faillock fix_faillock
  control "PAM.faillock_root" "faillock also locks out the root account" check_faillock_root fix_faillock_root
  control "PAM.remember" "password reuse remembered (remember=5)" check_pwhistory fix_pwhistory
  control "PAM.remember_root" "password history enforced for root too" check_pwhistory_root fix_pwhistory_root
  control "PAM.pwhistory_use_authtok" "pam_pwhistory uses use_authtok" check_pwhistory_use_authtok fix_pwhistory_use_authtok
  control "PAM.unix_nullok" "pam_unix does not permit empty passwords (no nullok)" check_pam_unix_nullok fix_pam_unix_nullok
  control "PAM.unix_use_authtok" "pam_unix uses use_authtok" check_pam_unix_use_authtok fix_pam_unix_use_authtok
}
PWQ_CONF="/etc/security/pwquality.conf"
check_pwquality_pkg() { pkg_installed libpam-pwquality; }
fix_pwquality_pkg() { apt-get update -qq && apt-get install -y -qq libpam-pwquality; }
check_pwquality_minlen() {
  [[ -f "$PWQ_CONF" ]] || return 1
  local v; v="$(grep -E '^\s*minlen' "$PWQ_CONF" | tail -1 | grep -Eo '[0-9]+')"
  [[ -n "$v" && "$v" -ge 14 ]]
}
fix_pwquality_minlen() {
  backup_file "$PWQ_CONF"; touch "$PWQ_CONF"
  if grep -Eq '^\s*minlen' "$PWQ_CONF"; then sed -i -E 's/^\s*minlen.*/minlen = 14/' "$PWQ_CONF"; else echo 'minlen = 14' >> "$PWQ_CONF"; fi
}
check_pwquality_complexity() {
  [[ -f "$PWQ_CONF" ]] || return 1
  grep -Eq '^\s*minclass\s*=\s*[3-4]' "$PWQ_CONF" 2>/dev/null && return 0
  for opt in dcredit ucredit lcredit ocredit; do
    grep -Eq "^\s*${opt}\s*=\s*-1" "$PWQ_CONF" 2>/dev/null || return 1
  done
  return 0
}
fix_pwquality_complexity() {
  backup_file "$PWQ_CONF"; touch "$PWQ_CONF"
  for kv in "dcredit -1" "ucredit -1" "lcredit -1" "ocredit -1"; do
    local k="${kv% *}" v="${kv#* }"
    if grep -Eq "^\s*${k}\s*=" "$PWQ_CONF"; then sed -i -E "s/^\s*${k}\s*=.*/${k} = ${v}/" "$PWQ_CONF"; else echo "${k} = ${v}" >> "$PWQ_CONF"; fi
  done
}
FAILLOCK_CONF="/etc/security/faillock.conf"
check_faillock() {
  pam-auth-update --package 2>/dev/null | grep -qi faillock 2>/dev/null || pkg_installed libpam-modules
  [[ -f "$FAILLOCK_CONF" ]] || return 1
  local deny unlock
  deny="$(grep -E '^\s*deny\s*=' "$FAILLOCK_CONF" | grep -Eo '[0-9]+' | tail -1)"
  unlock="$(grep -E '^\s*unlock_time\s*=' "$FAILLOCK_CONF" | grep -Eo '[0-9]+' | tail -1)"
  [[ -n "$deny" && "$deny" -le 5 && -n "$unlock" && "$unlock" -ge 900 ]]
}
fix_faillock() {
  backup_file "$FAILLOCK_CONF"; touch "$FAILLOCK_CONF"
  for kv in "deny 5" "unlock_time 900"; do
    local k="${kv% *}" v="${kv#* }"
    if grep -Eq "^\s*${k}\s*=" "$FAILLOCK_CONF"; then sed -i -E "s/^\s*${k}\s*=.*/${k} = ${v}/" "$FAILLOCK_CONF"; else echo "${k} = ${v}" >> "$FAILLOCK_CONF"; fi
  done
  # Ensure pam_faillock is wired into common-auth/common-account (pam-auth-update profile is the
  # supported mechanism on Debian/Ubuntu; left as a manual step if no profile is registered).
  log INFO "faillock.conf updated — verify pam_faillock is enabled via 'pam-auth-update' if not already."
}
check_pwhistory() {
  grep -Erq '^\s*password\s+.*pam_pwhistory\.so.*remember=([5-9]|[1-9][0-9])' /etc/pam.d/common-password 2>/dev/null
}
fix_pwhistory() {
  local f="/etc/pam.d/common-password"
  backup_file "$f"
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f"; then
    sed -i -E 's/^(\s*password\s+.*pam_pwhistory\.so.*)remember=[0-9]+/\1remember=5/' "$f"
  else
    log INFO "pam_pwhistory.so not found in $f — add it manually via pam-auth-update or your PAM profile."
    return 1
  fi
}
check_faillock_root() {
  [[ -f "$FAILLOCK_CONF" ]] || return 1
  grep -Eq '^\s*even_deny_root\b' "$FAILLOCK_CONF" && grep -Eq '^\s*root_unlock_time\s*=' "$FAILLOCK_CONF"
}
fix_faillock_root() {
  backup_file "$FAILLOCK_CONF"; touch "$FAILLOCK_CONF"
  grep -Eq '^\s*even_deny_root\b' "$FAILLOCK_CONF" || echo 'even_deny_root' >> "$FAILLOCK_CONF"
  if grep -Eq '^\s*root_unlock_time\s*=' "$FAILLOCK_CONF"; then
    sed -i -E 's/^\s*root_unlock_time\s*=.*/root_unlock_time = 900/' "$FAILLOCK_CONF"
  else
    echo 'root_unlock_time = 900' >> "$FAILLOCK_CONF"
  fi
}
check_pwhistory_root() {
  grep -Erq '^\s*password\s+.*pam_pwhistory\.so.*enforce_for_root' /etc/pam.d/common-password 2>/dev/null
}
fix_pwhistory_root() {
  local f="/etc/pam.d/common-password"
  backup_file "$f"
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f"; then
    grep -Eq '^\s*password\s+.*pam_pwhistory\.so.*enforce_for_root' "$f" || \
      sed -i -E 's|^(\s*password\s+.*pam_pwhistory\.so.*)$|\1 enforce_for_root|' "$f"
  else
    log INFO "pam_pwhistory.so not found in $f — add it manually via pam-auth-update or your PAM profile."
    return 1
  fi
}
check_pwhistory_use_authtok() {
  grep -Erq '^\s*password\s+.*pam_pwhistory\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null
}
fix_pwhistory_use_authtok() {
  local f="/etc/pam.d/common-password"
  backup_file "$f"
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f"; then
    grep -Eq '^\s*password\s+.*pam_pwhistory\.so.*use_authtok' "$f" || \
      sed -i -E 's|^(\s*password\s+.*pam_pwhistory\.so.*)$|\1 use_authtok|' "$f"
  else
    return 1
  fi
}
check_pam_unix_nullok() {
  ! grep -Erq '^\s*(password|auth)\s+.*pam_unix\.so.*\bnullok\b' /etc/pam.d/common-password /etc/pam.d/common-auth 2>/dev/null
}
fix_pam_unix_nullok() {
  for f in /etc/pam.d/common-password /etc/pam.d/common-auth; do
    [[ -f "$f" ]] || continue
    grep -Eq 'pam_unix\.so.*\bnullok\b' "$f" || continue
    backup_file "$f"
    sed -i -E 's/(\s*(password|auth)\s+.*pam_unix\.so.*)\s+nullok\b/\1/' "$f"
  done
}
check_pam_unix_use_authtok() {
  grep -Erq '^\s*password\s+.*pam_unix\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null
}
fix_pam_unix_use_authtok() {
  local f="/etc/pam.d/common-password"
  backup_file "$f"
  if grep -Eq '^\s*password\s+.*pam_unix\.so' "$f"; then
    grep -Eq '^\s*password\s+.*pam_unix\.so.*use_authtok' "$f" || \
      sed -i -E 's|^(\s*password\s+.*pam_unix\.so.*)$|\1 use_authtok|' "$f"
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# 10b. Access to the `su` command
# ---------------------------------------------------------------------------
section_access_control() {
  echo "== 10b. su command restriction =="
  control "ACL.su_restricted" "su restricted to members of the 'sudo' group (pam_wheel)" \
    check_su_restricted fix_su_restricted
}
check_su_restricted() {
  grep -Eq '^\s*auth\s+required\s+pam_wheel\.so\s+use_uid\s+group=sudo' /etc/pam.d/su 2>/dev/null
}
fix_su_restricted() {
  # Safety: only apply if the user who invoked sudo is themselves in the
  # 'sudo' group, so we don't lock the operator out of su on this box.
  local invoker="${SUDO_USER:-$(logname 2>/dev/null || true)}"
  if [[ -n "$invoker" ]] && ! id -nG "$invoker" 2>/dev/null | grep -qw sudo; then
    log INFO "Skipping su restriction: invoking user '$invoker' is not in the 'sudo' group — fix manually after confirming who needs su."
    return 1
  fi
  local f="/etc/pam.d/su"
  [[ -f "$f" ]] || return 1
  backup_file "$f"
  if grep -Eq '^\s*#?\s*auth\s+required\s+pam_wheel\.so' "$f"; then
    sed -i -E 's/^\s*#?\s*(auth\s+required\s+pam_wheel\.so).*/\1 use_uid group=sudo/' "$f"
  else
    sed -i '1i auth required pam_wheel.so use_uid group=sudo' "$f"
  fi
}

# ---------------------------------------------------------------------------
# 11. Account policy
# ---------------------------------------------------------------------------
section_accounts() {
  echo "== 11. Account expiration / umask =="
  control "ACC.maxdays" "PASS_MAX_DAYS <= 365 in /etc/login.defs" check_pass_max_days fix_pass_max_days
  control "ACC.mindays" "PASS_MIN_DAYS >= 1 in /etc/login.defs" check_pass_min_days fix_pass_min_days
  control "ACC.warnage" "PASS_WARN_AGE >= 7 in /etc/login.defs" check_pass_warn_age fix_pass_warn_age
  control "ACC.umask" "default UMASK 027 in /etc/login.defs" check_umask fix_umask
  control "ACC.inactive" "INACTIVE lock <= 30 days for new accounts (useradd defaults)" check_inactive fix_inactive
  control "ACC.tmout" "default interactive shell idle timeout (TMOUT) configured, <= 900s" \
    check_tmout fix_tmout
}
LOGIN_DEFS="/etc/login.defs"
check_pass_max_days() { local v; v="$(awk '$1=="PASS_MAX_DAYS"{print $2}' "$LOGIN_DEFS")"; [[ -n "$v" && "$v" -le 365 ]]; }
fix_pass_max_days() { backup_file "$LOGIN_DEFS"; sed -i -E 's/^(PASS_MAX_DAYS\s+).*/\1365/' "$LOGIN_DEFS"; grep -q '^PASS_MAX_DAYS' "$LOGIN_DEFS" || echo 'PASS_MAX_DAYS 365' >> "$LOGIN_DEFS"; }
check_pass_min_days() { local v; v="$(awk '$1=="PASS_MIN_DAYS"{print $2}' "$LOGIN_DEFS")"; [[ -n "$v" && "$v" -ge 1 ]]; }
fix_pass_min_days() { backup_file "$LOGIN_DEFS"; sed -i -E 's/^(PASS_MIN_DAYS\s+).*/\11/' "$LOGIN_DEFS"; grep -q '^PASS_MIN_DAYS' "$LOGIN_DEFS" || echo 'PASS_MIN_DAYS 1' >> "$LOGIN_DEFS"; }
check_pass_warn_age() { local v; v="$(awk '$1=="PASS_WARN_AGE"{print $2}' "$LOGIN_DEFS")"; [[ -n "$v" && "$v" -ge 7 ]]; }
fix_pass_warn_age() { backup_file "$LOGIN_DEFS"; sed -i -E 's/^(PASS_WARN_AGE\s+).*/\17/' "$LOGIN_DEFS"; grep -q '^PASS_WARN_AGE' "$LOGIN_DEFS" || echo 'PASS_WARN_AGE 7' >> "$LOGIN_DEFS"; }
check_umask() { grep -Eq '^\s*UMASK\s+027' "$LOGIN_DEFS"; }
fix_umask() { backup_file "$LOGIN_DEFS"; if grep -Eq '^\s*UMASK\s+' "$LOGIN_DEFS"; then sed -i -E 's/^\s*UMASK\s+.*/UMASK 027/' "$LOGIN_DEFS"; else echo 'UMASK 027' >> "$LOGIN_DEFS"; fi; }
check_inactive() { grep -Eq '^\s*INACTIVE=([0-9]|[1-2][0-9]|30)\s*$' /etc/default/useradd 2>/dev/null; }
fix_inactive() { backup_file /etc/default/useradd; if grep -Eq '^\s*INACTIVE=' /etc/default/useradd 2>/dev/null; then sed -i -E 's/^\s*INACTIVE=.*/INACTIVE=30/' /etc/default/useradd; else echo 'INACTIVE=30' >> /etc/default/useradd; fi; }
TMOUT_FILE="/etc/profile.d/60-cis-tmout.sh"
check_tmout() {
  [[ -f "$TMOUT_FILE" ]] || return 1
  local v; v="$(grep -Eo 'TMOUT=[0-9]+' "$TMOUT_FILE" | head -1 | cut -d= -f2)"
  [[ -n "$v" && "$v" -gt 0 && "$v" -le 900 ]]
}
fix_tmout() {
  backup_file "$TMOUT_FILE"
  printf 'TMOUT=900\nreadonly TMOUT\nexport TMOUT\n' > "$TMOUT_FILE"
  chmod 644 "$TMOUT_FILE"
}

# ---------------------------------------------------------------------------
# 12. Sensitive file permissions
# ---------------------------------------------------------------------------
section_file_perms() {
  echo "== 12. Sensitive file permissions =="
  control "PERM.passwd" "/etc/passwd mode 0644, owned root:root" "check_perm /etc/passwd 644 root root" "fix_perm /etc/passwd 644 root root"
  control "PERM.shadow" "/etc/shadow mode 0640 (or stricter), owned root:shadow" "check_perm_max /etc/shadow 640 root shadow" "fix_perm /etc/shadow 640 root shadow"
  control "PERM.group" "/etc/group mode 0644, owned root:root" "check_perm /etc/group 644 root root" "fix_perm /etc/group 644 root root"
  control "PERM.gshadow" "/etc/gshadow mode 0640 (or stricter), owned root:shadow" "check_perm_max /etc/gshadow 640 root shadow" "fix_perm /etc/gshadow 640 root shadow"
  control "PERM.opasswd" "/etc/security/opasswd mode 0600 (or stricter), owned root:root" \
    "check_perm_max /etc/security/opasswd 600 root root" "fix_perm /etc/security/opasswd 600 root root"
}
check_perm() {
  local f="$1" mode="$2" u="$3" g="$4"
  [[ -e "$f" ]] || return 2
  [[ "$(stat -c '%a' "$f")" == "$mode" && "$(stat -c '%U' "$f")" == "$u" && "$(stat -c '%G' "$f")" == "$g" ]]
}
check_perm_max() {
  local f="$1" mode="$2" u="$3" g="$4"
  [[ -e "$f" ]] || return 2
  [[ "$(stat -c '%a' "$f")" -le "$mode" && "$(stat -c '%U' "$f")" == "$u" && "$(stat -c '%G' "$f")" == "$g" ]]
}
fix_perm() {
  local f="$1" mode="$2" u="$3" g="$4"
  backup_file "$f"
  chmod "$mode" "$f"; chown "${u}:${g}" "$f"
}

# ---------------------------------------------------------------------------
# 13. sudo logging
# ---------------------------------------------------------------------------
section_sudo_logging() {
  echo "== 13. sudo =="
  control "SUDO.logfile" "sudo I/O log file configured (Defaults logfile)" check_sudo_logfile fix_sudo_logfile
  control "SUDO.use_pty" "sudo requires a pty (Defaults use_pty)" check_sudo_use_pty fix_sudo_use_pty
}
SUDOERS_DROPIN="/etc/sudoers.d/60-cis-hardening"
check_sudo_logfile() { grep -Rq 'Defaults\s\+logfile=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; }
fix_sudo_logfile() {
  backup_file "$SUDOERS_DROPIN"
  echo 'Defaults logfile="/var/log/sudo.log"' >> "$SUDOERS_DROPIN"
  chmod 440 "$SUDOERS_DROPIN"
  visudo -cf "$SUDOERS_DROPIN" >/dev/null
}
check_sudo_use_pty() { grep -Rq 'Defaults\s\+use_pty' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; }
fix_sudo_use_pty() {
  backup_file "$SUDOERS_DROPIN"
  echo 'Defaults use_pty' >> "$SUDOERS_DROPIN"
  chmod 440 "$SUDOERS_DROPIN"
  visudo -cf "$SUDOERS_DROPIN" >/dev/null
}

# ---------------------------------------------------------------------------
# 14. Kernel network parameters
# ---------------------------------------------------------------------------
section_kernel_params() {
  echo "== 14. Kernel network parameters (sysctl) =="

  if is_container_host; then
    control "SYSCTL.net.ipv4.ip_forward" "net.ipv4.ip_forward = 1 (Docker/Kubernetes detected — forwarding required for pod/container networking)" \
      check_ip_forward_on fix_ip_forward_on
  else
    control "SYSCTL.net.ipv4.ip_forward" "net.ipv4.ip_forward = 0" \
      "check_sysctl_eq net.ipv4.ip_forward 0" "fix_sysctl net.ipv4.ip_forward 0"
  fi

  local -A params=(
    [net.ipv4.conf.all.send_redirects]=0
    [net.ipv4.conf.default.send_redirects]=0
    [net.ipv4.conf.all.accept_source_route]=0
    [net.ipv4.conf.default.accept_source_route]=0
    [net.ipv4.conf.all.accept_redirects]=0
    [net.ipv4.conf.default.accept_redirects]=0
    [net.ipv4.conf.all.secure_redirects]=0
    [net.ipv4.conf.default.secure_redirects]=0
    [net.ipv4.conf.all.log_martians]=1
    [net.ipv4.conf.default.log_martians]=1
    [net.ipv4.icmp_echo_ignore_broadcasts]=1
    [net.ipv4.icmp_ignore_bogus_error_responses]=1
    [net.ipv4.conf.all.rp_filter]=1
    [net.ipv4.conf.default.rp_filter]=1
    [net.ipv4.tcp_syncookies]=1
    [net.ipv6.conf.all.accept_ra]=0
    [net.ipv6.conf.default.accept_ra]=0
    [net.ipv6.conf.all.accept_redirects]=0
    [net.ipv6.conf.default.accept_redirects]=0
  )
  for key in "${!params[@]}"; do
    control "SYSCTL.${key}" "${key} = ${params[$key]}" \
      "check_sysctl_eq $key ${params[$key]}" "fix_sysctl $key ${params[$key]}"
  done
  if is_container_host; then
    log INFO "Container platform detected: net.ipv4.conf.*.rp_filter=1 (strict reverse-path filtering) can drop traffic on some CNI/LoadBalancer setups that preserve source IPs — review if you use externalTrafficPolicy: Local or similar."
  fi
}
check_ip_forward_on() { check_sysctl_eq net.ipv4.ip_forward 1; }
fix_ip_forward_on() { fix_sysctl net.ipv4.ip_forward 1; }

# ---------------------------------------------------------------------------
# 15. Firewall
# ---------------------------------------------------------------------------
section_firewall() {
  echo "== 15. Host firewall =="
  if is_container_host; then
    say_skip "FW.*" "Docker/Kubernetes detected — kube-proxy and/or your CNI plugin manage iptables/nftables rules directly. Enabling ufw, forcing a default-deny policy, or flushing iptables to nftables here can break pod networking, Services, and NetworkPolicies. Firewall this host at the cloud security-group / perimeter layer, or via Kubernetes NetworkPolicies, instead."
    return
  fi
  control "FW.installed" "ufw installed" check_ufw_installed fix_ufw_installed
  control "FW.enabled" "ufw enabled and active" check_ufw_enabled fix_ufw_enabled
  control "FW.default_deny" "ufw default incoming policy is deny" check_ufw_default_deny fix_ufw_default_deny
}
check_ufw_installed() { command -v ufw >/dev/null 2>&1; }
fix_ufw_installed() { apt-get update -qq && apt-get install -y -qq ufw; }
check_ufw_enabled() { ufw status 2>/dev/null | grep -qi "^Status: active"; }
fix_ufw_enabled() {
  # Keep SSH reachable before enabling, to avoid locking out the current session.
  ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1
}
check_ufw_default_deny() { ufw status verbose 2>/dev/null | grep -qi "Default: deny (incoming)"; }
fix_ufw_default_deny() { ufw default deny incoming >/dev/null 2>&1; ufw default allow outgoing >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 16. Auditd
# ---------------------------------------------------------------------------
section_auditd() {
  echo "== 16. Audit logging (auditd) =="
  control "AUDIT.installed" "auditd installed and enabled" check_auditd_installed fix_auditd_installed
  control "AUDIT.maxlogfile" "audit log max size configured (>= 32 MB)" check_audit_maxlogfile fix_audit_maxlogfile
  control "AUDIT.keep_logs" "audit logs retained (max_log_file_action=keep_logs)" check_audit_keep_logs fix_audit_keep_logs
  control "AUDIT.backlog" "audit_backlog_limit set on kernel cmdline (>= 8192)" check_audit_backlog fix_audit_backlog
  control "AUDIT.early" "auditing enabled for processes started before auditd (audit=1 on kernel cmdline)" \
    check_audit_early fix_audit_early
  control "AUDIT.tool_owner" "audit tool binaries owned root:root, mode 0755 or stricter" \
    check_audit_tool_owner fix_audit_tool_owner
}
check_auditd_installed() { pkg_installed auditd && svc_active auditd.service; }
fix_auditd_installed() { apt-get update -qq && apt-get install -y -qq auditd audispd-plugins; systemctl enable --now auditd.service; }
AUDITD_CONF="/etc/audit/auditd.conf"
check_audit_maxlogfile() {
  [[ -f "$AUDITD_CONF" ]] || return 1
  local v
  v="$(awk -F= '/^max_log_file[ \t]*=/{gsub(/ /,"",$2); print $2}' "$AUDITD_CONF")"
  [[ -n "$v" && "$v" -ge 32 ]]
}
fix_audit_maxlogfile() { backup_file "$AUDITD_CONF"; if grep -q '^max_log_file' "$AUDITD_CONF"; then sed -i -E 's/^max_log_file\s*=.*/max_log_file = 32/' "$AUDITD_CONF"; else echo 'max_log_file = 32' >> "$AUDITD_CONF"; fi; }
check_audit_keep_logs() { [[ -f "$AUDITD_CONF" ]] && grep -Eq '^max_log_file_action\s*=\s*keep_logs' "$AUDITD_CONF"; }
fix_audit_keep_logs() { backup_file "$AUDITD_CONF"; if grep -q '^max_log_file_action' "$AUDITD_CONF"; then sed -i -E 's/^max_log_file_action\s*=.*/max_log_file_action = keep_logs/' "$AUDITD_CONF"; else echo 'max_log_file_action = keep_logs' >> "$AUDITD_CONF"; fi; }
check_audit_backlog() {
  [[ -f "$GRUB_DEFAULT_FILE" ]] || return 2
  grep -Eq 'audit_backlog_limit=([0-9]{4,})' "$GRUB_DEFAULT_FILE"
}
fix_audit_backlog() { ensure_grub_cmdline_param 'audit_backlog_limit=8192'; }
check_audit_early() {
  [[ -f "$GRUB_DEFAULT_FILE" ]] || return 2
  grub_cmdline_has_param 'audit=1'
}
fix_audit_early() { ensure_grub_cmdline_param 'audit=1'; }
check_audit_tool_owner() {
  local tools=(/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd \
               /sbin/augenrules /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch \
               /usr/sbin/autrace /usr/sbin/auditd /usr/sbin/augenrules)
  local found=0
  for t in "${tools[@]}"; do
    [[ -e "$t" ]] || continue
    found=1
    local perms owner
    perms="$(stat -c '%a' "$t")"
    owner="$(stat -c '%U:%G' "$t")"
    [[ "$owner" == "root:root" && "$perms" -le 755 ]] || return 1
  done
  [[ "$found" -eq 1 ]] || return 2
  return 0
}
fix_audit_tool_owner() {
  local tools=(/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd \
               /sbin/augenrules /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch \
               /usr/sbin/autrace /usr/sbin/auditd /usr/sbin/augenrules)
  for t in "${tools[@]}"; do
    [[ -e "$t" ]] || continue
    chown root:root "$t"; chmod 755 "$t"
  done
}

# ---------------------------------------------------------------------------
# 17. System logging
# ---------------------------------------------------------------------------
section_logging() {
  echo "== 17. rsyslog / journald =="
  control "LOG.rsyslog" "rsyslog installed and enabled" check_rsyslog fix_rsyslog
  control "LOG.journald_persist" "systemd-journald configured for persistent storage" check_journald_persist fix_journald_persist
  control "LOG.journald_rotate" "systemd-journald rotation configured (SystemMaxUse set)" \
    check_journald_rotate fix_journald_rotate
  if pkg_installed rsyslog; then
    control "LOG.rsyslog_filemode" "rsyslog log file creation mode 0640 or stricter" \
      check_rsyslog_filemode fix_rsyslog_filemode
  fi
}
check_rsyslog() { pkg_installed rsyslog && svc_active rsyslog.service; }
fix_rsyslog() { apt-get update -qq && apt-get install -y -qq rsyslog; systemctl enable --now rsyslog.service; }
check_journald_rotate() { grep -Eq '^\s*SystemMaxUse\s*=\s*\S+' /etc/systemd/journald.conf 2>/dev/null; }
fix_journald_rotate() {
  local f=/etc/systemd/journald.conf
  backup_file "$f"
  if grep -Eq '^\s*#?\s*SystemMaxUse\s*=' "$f"; then
    sed -i -E 's/^\s*#?\s*SystemMaxUse\s*=.*/SystemMaxUse=500M/' "$f"
  else
    echo 'SystemMaxUse=500M' >> "$f"
  fi
  systemctl restart systemd-journald
}
RSYSLOG_CONF="/etc/rsyslog.conf"
check_rsyslog_filemode() {
  [[ -f "$RSYSLOG_CONF" ]] || return 1
  local v; v="$(grep -Eo '\$FileCreateMode\s+[0-7]{3,4}' "$RSYSLOG_CONF" | tail -1 | awk '{print $2}')"
  [[ -n "$v" && "$v" -le 640 ]]
}
fix_rsyslog_filemode() {
  backup_file "$RSYSLOG_CONF"
  if grep -Eq '^\s*\$FileCreateMode' "$RSYSLOG_CONF"; then
    sed -i -E 's/^\s*\$FileCreateMode\s+[0-7]{3,4}/\$FileCreateMode 0640/' "$RSYSLOG_CONF"
  else
    echo '$FileCreateMode 0640' >> "$RSYSLOG_CONF"
  fi
  systemctl restart rsyslog.service 2>/dev/null || true
}
check_journald_persist() { grep -Eq '^\s*Storage=persistent' /etc/systemd/journald.conf 2>/dev/null; }
fix_journald_persist() {
  local f=/etc/systemd/journald.conf
  backup_file "$f"
  if grep -Eq '^\s*#?\s*Storage=' "$f"; then sed -i -E 's/^\s*#?\s*Storage=.*/Storage=persistent/' "$f"; else echo 'Storage=persistent' >> "$f"; fi
  systemctl restart systemd-journald
}

# ---------------------------------------------------------------------------
# 18. File integrity (AIDE)
# ---------------------------------------------------------------------------
section_aide() {
  echo "== 18. File integrity monitoring (AIDE) =="
  control "AIDE.installed" "AIDE installed and initialized" check_aide_installed fix_aide_installed
  control "AIDE.cron" "AIDE integrity check scheduled (cron/systemd timer)" check_aide_cron fix_aide_cron
}
check_aide_installed() { pkg_installed aide && [[ -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.db ]]; }
fix_aide_installed() {
  apt-get update -qq && apt-get install -y -qq aide aide-common
  aideinit -y -f >/dev/null 2>&1 || (aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null)
}
check_aide_cron() { [[ -f /etc/cron.d/aide || -n "$(systemctl list-timers 2>/dev/null | grep -i aide)" ]]; }
fix_aide_cron() {
  local f=/etc/cron.d/aide
  backup_file "$f"
  echo "0 5 * * * root /usr/bin/aide.wrapper --check | mail -s \"AIDE check $(hostname)\" root" > "$f"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: sudo $SCRIPT_NAME [--apply] [--only sec1,sec2,...] [--list] [-h]

  (no flags)     Audit only — report PASS/WOULD FIX/SKIP, no changes made.
  --apply        Apply fixes for anything not already compliant.
  --only LIST    Comma-separated subset of sections to run. See --list.
  --list         List available section names and exit.
EOF
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=1 ;;
      --only) ONLY="$2"; shift ;;
      --list) LIST_ONLY=1 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
    shift
  done

  if [[ "$LIST_ONLY" -eq 1 ]]; then
    printf '%s\n' "${ALL_SECTIONS[@]}"
    exit 0
  fi

  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
  fi

  echo "CIS Level 1 hardening — Ubuntu 24.04 LTS"
  if [[ "$APPLY" -eq 1 ]]; then
    echo "Mode: APPLY (changes will be made). Backups: $BACKUP_DIR"
  else
    echo "Mode: AUDIT ONLY (no changes will be made). Pass --apply to fix."
  fi
  echo "Log: $LOG_FILE"
  if is_container_host; then
    echo "Detected: Docker/Kubernetes on this host — the firewall section will be skipped and"
    echo "          net.ipv4.ip_forward will be kept ON. See README.md, 'Docker/Kubernetes hosts'."
  fi
  echo

  local run_list=("${ALL_SECTIONS[@]}")
  if [[ -n "$ONLY" ]]; then
    IFS=',' read -r -a run_list <<< "$ONLY"
  fi

  for sec in "${run_list[@]}"; do
    if declare -F "section_${sec}" >/dev/null; then
      "section_${sec}"
      echo
    else
      echo "Unknown section: $sec (see --list)" >&2
    fi
  done

  echo "-------------------------------------------------------------"
  echo "PASS: $PASS_COUNT   FIXED: $FIX_COUNT   WOULD FIX: $WOULD_FIX_COUNT   SKIP: $SKIP_COUNT   ERROR: $ERROR_COUNT"
  echo "Full log: $LOG_FILE"
  [[ "$APPLY" -eq 1 ]] && echo "Backups of modified files: $BACKUP_DIR"

  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    exit 2
  elif [[ "$APPLY" -eq 0 && "$WOULD_FIX_COUNT" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
