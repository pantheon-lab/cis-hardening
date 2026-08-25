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
  extra_fs_modules
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
  audit_rules
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
# check_fn/fix_fn are single strings like "check_sysctl_eq kernel.randomize_va_space 2"
# — function name plus its arguments — and are deliberately left UNQUOTED below so
# bash word-splits them into "command arg1 arg2 ..." instead of trying to run the
# whole string as one literal command name. Every call site in this script passes
# plain, space-separated tokens (no embedded spaces within a single argument), so
# this is safe. shellcheck disable=SC2086
# check_fn should return 0 if already compliant, 1 if not compliant, 2 if not applicable.
control() {
  local id="$1" desc="$2" check_fn="$3" fix_fn="$4"
  local rc
  $check_fn >/tmp/.cischeck.$$ 2>&1
  rc=$?
  case "$rc" in
    0) say_pass "$id" "$desc" ;;
    2) say_skip "$id" "$desc ($(cat /tmp/.cischeck.$$))" ;;
    1)
      if [[ "$APPLY" -eq 1 ]]; then
        if $fix_fn >/tmp/.cisfix.$$ 2>&1; then
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
# 1c. Additional unused filesystem kernel modules (CIS 1.1.1.10)
# ---------------------------------------------------------------------------
# CIS 1.1.1.10 covers a longer module list than the classic 1.1.1.1-1.1.1.9
# set. Several of these are filesystems container storage can genuinely
# depend on: `cifs`/`nfs_common`/`nfsd` back SMB/NFS-backed PersistentVolumes,
# `fuse` backs rootless containers, sshfs, and some CSI drivers, and `ceph`
# backs RBD/CephFS volumes (e.g. Rook). Blacklisting one of these on a node
# that needs it doesn't just fail silently — it makes the module permanently
# unloadable (modprobe runs /bin/false instead), breaking volume mounts in a
# confusing way. So on a detected container host, those five are reviewed
# manually instead of auto-disabled; everything else here is never used by
# Docker/Kubernetes networking or storage and is always safe to disable.
EXTRA_FS_MODULES_SAFE=(afs exfat ext fat fscache gfs2 smbfs_common)
EXTRA_FS_MODULES_STORAGE=(cifs fuse nfs_common nfsd ceph)
section_extra_fs_modules() {
  echo "== 1c. Additional unused filesystem kernel modules =="
  for m in "${EXTRA_FS_MODULES_SAFE[@]}"; do
    control "FSX.$m" "kernel module '$m' is disabled and blacklisted" \
      "check_module_disabled_$m" "fix_module_disabled_$m"
  done
  for m in "${EXTRA_FS_MODULES_STORAGE[@]}"; do
    if is_container_host; then
      control "FSX.$m" "kernel module '$m' disabled (skipped — Docker/Kubernetes detected; this filesystem may back a storage volume type, review manually)" \
        true_check_skip true_check_skip
    else
      control "FSX.$m" "kernel module '$m' is disabled and blacklisted" \
        "check_module_disabled_$m" "fix_module_disabled_$m"
    fi
  done
}
for _m in afs exfat ext fat fscache gfs2 smbfs_common cifs fuse nfs_common nfsd ceph; do
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
  # Iterate explicitly rather than handing grep an unexpanded glob (which, on
  # GNU grep, reports an open error — and a false "N/A" — when limits.d/
  # has no *.conf files yet).
  local f
  for f in /etc/security/limits.conf /etc/security/limits.d/*.conf; do
    [[ -f "$f" ]] || continue
    grep -Eq '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' "$f" && return 0
  done
  return 1
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
  local out
  out="$(aa-status 2>/dev/null)" || return 1
  # Requires ALL of: >0 profiles loaded, >0 in enforce mode, 0 unconfined
  # processes, 0 in complain mode, 0 in kill mode.
  local enforce_n loaded_n
  enforce_n="$(printf '%s\n' "$out" | grep -Eo '^[0-9]+ profiles are in enforce mode' | grep -Eo '^[0-9]+')"
  loaded_n="$(printf '%s\n' "$out" | grep -Eo '^[0-9]+ profiles are loaded' | grep -Eo '^[0-9]+')"
  [[ -n "$enforce_n" && "$enforce_n" -gt 0 ]] || return 1
  [[ -n "$loaded_n" && "$loaded_n" -gt 0 ]] || return 1
  printf '%s\n' "$out" | grep -Eq '^0[[:space:]]*processes[[:space:]]+are[[:space:]]+unconfined' || return 1
  printf '%s\n' "$out" | grep -Eq '^0[[:space:]]*profiles[[:space:]]+are[[:space:]]+in[[:space:]]+complain[[:space:]]+mode' || return 1
  printf '%s\n' "$out" | grep -Eq '^0[[:space:]]*profiles[[:space:]]+are[[:space:]]+in[[:space:]]+kill[[:space:]]+mode' || return 1
  return 0
}
fix_apparmor_enforcing() {
  systemctl enable --now apparmor.service
  aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
  log INFO "Ran aa-enforce on every profile under /etc/apparmor.d/. Any profile still in complain/kill mode without a file there (e.g. some snap or container-runtime-generated profiles), or any still-unconfined process, needs manual review: 'aa-enforce <profile-name>' or restart the affected service so it picks up its profile."
}
check_apparmor_bootloader() {
  # The CIS control specifically wants this declared on the kernel cmdline
  # in /etc/default/grub, not just "AppArmor happens to be active right
  # now" — Ubuntu's kernel enables it by default without this, but a
  # persistent boot-time declaration survives even if that default ever
  # changes. Skipped (not failed) on non-GRUB systems (e.g. systemd-boot
  # cloud images), where there's nothing to edit.
  [[ -f "$GRUB_DEFAULT_FILE" ]] || return 2
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
# service-unit:package-name pairs — the package name sometimes differs from
# the systemd unit (e.g. the nfs-server.service unit ships in the
# nfs-kernel-server package). CIS's own remediation for this section is to
# remove the package outright, not just disable the unit, so that's what
# the fix does — none of these are needed by Docker/Kubernetes.
SVC_PACKAGE_MAP=(
  "avahi-daemon:avahi-daemon"
  "cups:cups"
  "isc-dhcp-server:isc-dhcp-server"
  "bind9:bind9"
  "vsftpd:vsftpd"
  "slapd:slapd"
  "dovecot:dovecot-core"
  "smbd:samba"
  "nfs-server:nfs-kernel-server"
  "ypserv:nis"
  "rpcbind:rpcbind"
  "rsync:rsync"
  "snmpd:snmpd"
  "tftpd-hpa:tftpd-hpa"
  "squid:squid"
  "nginx:nginx"
  "apache2:apache2"
  "xinetd:xinetd"
)
section_services() {
  echo "== 6. Unnecessary services =="
  for pair in "${SVC_PACKAGE_MAP[@]}"; do
    local svc="${pair%%:*}" pkg="${pair#*:}"
    control "SVC.$svc" "service '$svc' disabled and its package ('$pkg') removed, if not needed" \
      "check_service_and_pkg_absent $svc $pkg" "fix_service_and_pkg_absent $svc $pkg"
  done

  control "SVC.telnet_client" "telnet client not installed (telnet or inetutils-telnet)" \
    check_no_telnet_client fix_no_telnet_client
  control "SVC.ftp_client" "ftp client not installed (ftp or tnftp)" \
    check_no_ftp_client fix_no_ftp_client
  control "SVC.xserver" "X window server packages not installed (servers should be headless)" \
    check_no_xserver fix_no_xserver
}
check_service_and_pkg_absent() {
  local svc="$1.service" pkg="$2"
  pkg_installed "$pkg" && return 1
  svc_exists "$svc" && svc_enabled "$svc" && return 1
  return 0
}
fix_service_and_pkg_absent() {
  local svc="$1.service" pkg="$2"
  systemctl disable --now "$svc" 2>/dev/null || true
  apt-get purge -y -qq "$pkg" 2>/dev/null || true
}
check_no_telnet_client() { ! pkg_installed telnet && ! pkg_installed inetutils-telnet; }
fix_no_telnet_client() { apt-get purge -y -qq telnet inetutils-telnet 2>/dev/null || true; }
check_no_ftp_client() { ! pkg_installed ftp && ! pkg_installed tnftp; }
fix_no_ftp_client() { apt-get purge -y -qq ftp tnftp 2>/dev/null || true; }
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
  # CIS treats systemd-timesyncd and chrony as alternative implementations
  # (2.3.2.x vs 2.3.3.x), each with its own specific sub-checks — running
  # both, or picking whichever happens to already be active, leaves the
  # other implementation's checks permanently failing. Standardize on
  # chrony specifically (Ubuntu Server's traditional choice, and the one
  # this script's own PAM/etc controls already assume).
  pkg_installed chrony || return 1
  { svc_active chronyd.service || svc_active chrony.service; } || return 1
  { svc_enabled chronyd.service || svc_enabled chrony.service; } || return 1
  return 0
}
fix_time_sync() {
  apt-get update -qq && apt-get install -y -qq chrony
  systemctl enable --now chronyd.service 2>/dev/null || systemctl enable --now chrony.service
  # Commit fully to chrony so systemd-timesyncd's own checks pass via their
  # "timesyncd not in use" escape clause instead of conflicting with it.
  systemctl stop systemd-timesyncd.service 2>/dev/null || true
  systemctl disable systemd-timesyncd.service 2>/dev/null || true
  systemctl mask systemd-timesyncd.service 2>/dev/null || true
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
  control "CRON.allow" "/etc/cron.allow exists, root:root, mode 0600 (only root may use cron)" \
    check_cron_allow fix_cron_allow
  control "AT.allow" "'at' package installed and /etc/at.allow exists, root:root, mode 0600" \
    check_at_allow fix_at_allow
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
check_cron_allow() {
  [[ -f /etc/cron.allow ]] || return 1
  [[ "$(stat -c '%U:%G' /etc/cron.allow)" == "root:root" ]] || return 1
  [[ "$(stat -c '%a' /etc/cron.allow)" -le 600 ]] || return 1
  return 0
}
fix_cron_allow() {
  touch /etc/cron.allow
  chown root:root /etc/cron.allow
  chmod 600 /etc/cron.allow
}
check_at_allow() {
  pkg_installed at || return 1
  [[ -f /etc/at.allow ]] || return 1
  local owner; owner="$(stat -c '%U:%G' /etc/at.allow)"
  [[ "$owner" == "root:root" || "$owner" == "root:daemon" ]] || return 1
  [[ "$(stat -c '%a' /etc/at.allow)" -le 600 ]] || return 1
  return 0
}
fix_at_allow() {
  pkg_installed at || { apt-get update -qq && apt-get install -y -qq at; }
  touch /etc/at.allow
  chown root:root /etc/at.allow
  chmod 600 /etc/at.allow
}

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
  # AllowUsers/DenyUsers/AllowGroups/DenyGroups restrict who may SSH in at
  # all — inherently specific to your user population. Auto-picking e.g.
  # "AllowGroups sudo" could silently lock out legitimate non-admin SSH
  # users, so this is deliberately left as a manual decision.
  say_skip "SSH.access_control" "sshd access restricted via AllowUsers/DenyUsers/AllowGroups/DenyGroups (not automated — add the directive matching who should actually have SSH access, e.g. 'AllowGroups sudo' in $SSHD_CONFIG)"
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
# set_sshd_kv <key> <value> — set a directive in the main sshd_config, and
# strip any conflicting occurrence from /etc/ssh/sshd_config.d/*.conf
# drop-ins first. Ubuntu's stock sshd_config does
# 'Include /etc/ssh/sshd_config.d/*.conf' near the TOP of the file — sshd
# uses the first occurrence of a directive it encounters, so a value in a
# drop-in silently wins over anything we append to the bottom of the main
# file unless we clear it out of the drop-in too.
set_sshd_kv() {
  local key="$1" value="$2"
  local f
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [[ -f "$f" ]] || continue
    grep -Eiq "^[[:space:]]*${key}[[:space:]]" "$f" 2>/dev/null || continue
    backup_file "$f"
    sed -i -E "/^[[:space:]]*${key}[[:space:]]/Id" "$f"
  done
  set_kv_space "$SSHD_CONFIG" "$key" "$value"
}
fix_sshd_kv() { set_sshd_kv "$1" "$2"; systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true; }
check_ssh_maxauthtries() {
  local v; v="$(sshd_effective | awk '$1=="maxauthtries"{print $2}')"
  [[ -n "$v" && "$v" -le 4 ]]
}
fix_ssh_maxauthtries() { set_sshd_kv MaxAuthTries 4; }
check_ssh_clientalive() {
  local i c
  i="$(sshd_effective | awk '$1=="clientaliveinterval"{print $2}')"
  c="$(sshd_effective | awk '$1=="clientalivecountmax"{print $2}')"
  [[ -n "$i" && "$i" -gt 0 && "$i" -le 300 && -n "$c" && "$c" -le 3 ]]
}
fix_ssh_clientalive() { set_sshd_kv ClientAliveInterval 300; set_sshd_kv ClientAliveCountMax 3; }
check_ssh_logingrace() {
  local v; v="$(sshd_effective | awk '$1=="logingracetime"{print $2}')"
  [[ -n "$v" && "$v" -le 60 && "$v" != 0 ]]
}
fix_ssh_logingrace() { set_sshd_kv LoginGraceTime 60; }
check_ssh_maxsessions() {
  local v; v="$(sshd_effective | awk '$1=="maxsessions"{print $2}')"
  [[ -n "$v" && "$v" -le 10 ]]
}
fix_ssh_maxsessions() { set_sshd_kv MaxSessions 10; }
check_ssh_maxstartups() {
  local v; v="$(sshd_effective | awk '$1=="maxstartups"{print $2}')"
  [[ -n "$v" ]] || return 1
  # All three colon-separated fields matter (start:rate:full) — checking
  # only the first meant an unconfigured directive (OpenSSH's own compiled
  # default is 10:30:100) looked compliant, since 10<=10 alone passes while
  # the real requirement (full<=60) doesn't.
  local start="${v%%:*}" rest="${v#*:}"
  local rate="${rest%%:*}" full="${rest#*:}"
  [[ "$start" =~ ^[0-9]+$ && "$start" -ge 1 && "$start" -le 10 ]] || return 1
  [[ "$rate" =~ ^[0-9]+$ && "$rate" -ge 1 && "$rate" -le 30 ]] || return 1
  [[ "$full" =~ ^[0-9]+$ && "$full" -ge 1 && "$full" -le 60 ]] || return 1
  return 0
}
fix_ssh_maxstartups() { set_sshd_kv MaxStartups "10:30:60"; }
check_ssh_algos() {
  grep -Eq '^[[:space:]]*Ciphers[[:space:]]' "$SSHD_CONFIG" || return 1
  grep -Eq '^[[:space:]]*MACs[[:space:]]' "$SSHD_CONFIG" || return 1
  grep -Eq '^[[:space:]]*KexAlgorithms[[:space:]]' "$SSHD_CONFIG" || return 1
  # CIS explicitly excludes these from the MACs line, even though some
  # (umac-128-etm) aren't otherwise considered weak — matches the scanner's
  # own check exactly rather than just "a MACs line exists".
  ! grep -Eq '^[[:space:]]*MACs[[:space:]].*(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)' "$SSHD_CONFIG"
}
fix_ssh_algos() {
  set_sshd_kv Ciphers "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  set_sshd_kv MACs "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
  set_sshd_kv KexAlgorithms "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 10. PAM — password quality, lockout, history
# ---------------------------------------------------------------------------
section_pam() {
  echo "== 10. PAM: password quality / lockout / history =="
  control "PAM.pwquality_pkg" "libpam-pwquality installed" check_pwquality_pkg fix_pwquality_pkg
  control "PAM.minlen" "pwquality minlen >= 14" check_pwquality_minlen fix_pwquality_minlen
  control "PAM.difok" "pwquality difok >= 2 (changed characters from old password)" check_pwquality_difok fix_pwquality_difok
  control "PAM.complexity" "pwquality minclass >= 4 (require all 4 character classes)" check_pwquality_complexity fix_pwquality_complexity
  control "PAM.maxrepeat" "pwquality maxrepeat <= 3 (no long runs of the same character)" check_pwquality_maxrepeat fix_pwquality_maxrepeat
  control "PAM.maxsequence" "pwquality maxsequence <= 3 (no long runs like 'abcd'/'1234')" check_pwquality_maxsequence fix_pwquality_maxsequence
  control "PAM.faillock" "faillock configured: deny<=5, unlock_time=900" check_faillock fix_faillock
  control "PAM.faillock_root" "faillock also locks out the root account" check_faillock_root fix_faillock_root
  control "PAM.remember" "password reuse remembered (remember=24)" check_pwhistory fix_pwhistory
  control "PAM.remember_root" "password history enforced for root too" check_pwhistory_root fix_pwhistory_root
  control "PAM.pwhistory_use_authtok" "pam_pwhistory uses use_authtok" check_pwhistory_use_authtok fix_pwhistory_use_authtok
  control "PAM.unix_nullok" "pam_unix does not permit empty passwords (no nullok)" check_pam_unix_nullok fix_pam_unix_nullok
  control "PAM.unix_use_authtok" "pam_unix uses use_authtok" check_pam_unix_use_authtok fix_pam_unix_use_authtok
  # pam_unix/pam_faillock "module enabled" wiring (CIS 5.3.2.1/5.3.2.2) means
  # very specific control-syntax brackets across FOUR files (common-account,
  # common-auth, common-password, common-session). That's normally already
  # correct on a stock Ubuntu install via pam-auth-update's default
  # profile — but rewriting it with sed if it's ever NOT exactly right is a
  # real risk of misconfiguring the whole authentication stack (a wrong
  # edit here can lock out every account, not just break a password
  # change). Verified, not auto-rewritten.
  if check_pam_unix_wiring; then
    say_pass "PAM.unix_wiring" "pam_unix wired into common-account/-auth/-password/-session with the standard control syntax"
  else
    say_skip "PAM.unix_wiring" "pam_unix wiring looks non-standard in one of common-account/-auth/-password/-session (not auto-rewritten — risk of locking out every account, not just breaking a password change); compare against a fresh 'pam-auth-update' baseline"
  fi
  if check_pam_faillock_wiring; then
    say_pass "PAM.faillock_wiring" "pam_faillock wired into common-account/-auth with the standard control syntax"
  else
    say_skip "PAM.faillock_wiring" "pam_faillock wiring looks non-standard in common-account/common-auth (not auto-rewritten — same lockout risk); verify via 'pam-auth-update'"
  fi
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
# set_pwquality_min <option> <min_value> — passes if the configured value is
# >= min_value; fixes by setting it to exactly min_value.
_pwq_get() {
  grep -E "^\s*${1}\s*=" "$PWQ_CONF" 2>/dev/null | tail -1 | grep -Eo '[0-9]+'
}
_pwq_set() {
  local opt="$1" val="$2"
  backup_file "$PWQ_CONF"; touch "$PWQ_CONF"
  if grep -Eq "^\s*${opt}\s*=" "$PWQ_CONF"; then
    sed -i -E "s/^\s*${opt}\s*=.*/${opt} = ${val}/" "$PWQ_CONF"
  else
    echo "${opt} = ${val}" >> "$PWQ_CONF"
  fi
}
check_pwquality_difok() { local v; v="$(_pwq_get difok)"; [[ -n "$v" && "$v" -ge 2 ]]; }
fix_pwquality_difok() { _pwq_set difok 2; }
check_pwquality_complexity() { local v; v="$(_pwq_get minclass)"; [[ -n "$v" && "$v" -ge 4 ]]; }
fix_pwquality_complexity() { _pwq_set minclass 4; }
check_pwquality_maxrepeat() { local v; v="$(_pwq_get maxrepeat)"; [[ -n "$v" && "$v" -ge 1 && "$v" -le 3 ]]; }
fix_pwquality_maxrepeat() { _pwq_set maxrepeat 3; }
check_pwquality_maxsequence() { local v; v="$(_pwq_get maxsequence)"; [[ -n "$v" && "$v" -ge 1 && "$v" -le 3 ]]; }
fix_pwquality_maxsequence() { _pwq_set maxsequence 3; }
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
PWHISTORY_CONF_FILE="/etc/pam.d/common-password"
# ensure_pwhistory_line — insert a pam_pwhistory.so password line if the
# stack doesn't have one at all. Stock Debian/Ubuntu don't ship a
# pam-auth-update "pwhistory" profile, so there's no safer/declarative way
# to enable this — CIS's own remediation for this control is to edit
# common-password directly, which is what this does. Placed immediately
# before the pam_unix.so password line (order matters: pwhistory must run
# before pam_unix.so so pam_unix.so can reuse the already-typed password
# via use_authtok). Safe to call repeatedly — a no-op once the line exists.
ensure_pwhistory_line() {
  local f="$PWHISTORY_CONF_FILE"
  [[ -f "$f" ]] || return 1
  grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f" && return 0
  backup_file "$f"
  if grep -Eq '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$f"; then
    sed -i -E '0,/^([[:space:]]*password[[:space:]]+.*pam_unix\.so.*)$/s//password requisite pam_pwhistory.so remember=24 use_authtok enforce_for_root\n\1/' "$f"
  else
    echo 'password requisite pam_pwhistory.so remember=24 use_authtok enforce_for_root' >> "$f"
  fi
  log INFO "Inserted pam_pwhistory.so into $f. If you later run 'pam-auth-update' for an unrelated PAM profile change, verify this line survived it."
}
check_pwhistory() {
  local v
  v="$(grep -Eo '^\s*password\s+.*pam_pwhistory\.so.*remember=[0-9]+' /etc/pam.d/common-password 2>/dev/null | grep -Eo 'remember=[0-9]+' | tail -1 | cut -d= -f2)"
  [[ -n "$v" && "$v" -ge 24 ]]
}
fix_pwhistory() {
  local f="/etc/pam.d/common-password"
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f" 2>/dev/null; then
    backup_file "$f"
    sed -i -E 's/^(\s*password\s+.*pam_pwhistory\.so.*)remember=[0-9]+/\1remember=24/' "$f"
  else
    ensure_pwhistory_line
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
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f" 2>/dev/null; then
    backup_file "$f"
    grep -Eq '^\s*password\s+.*pam_pwhistory\.so.*enforce_for_root' "$f" || \
      sed -i -E 's|^(\s*password\s+.*pam_pwhistory\.so.*)$|\1 enforce_for_root|' "$f"
  else
    ensure_pwhistory_line
  fi
}
check_pwhistory_use_authtok() {
  grep -Erq '^\s*password\s+.*pam_pwhistory\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null
}
fix_pwhistory_use_authtok() {
  local f="/etc/pam.d/common-password"
  if grep -Eq '^\s*password\s+.*pam_pwhistory\.so' "$f" 2>/dev/null; then
    backup_file "$f"
    grep -Eq '^\s*password\s+.*pam_pwhistory\.so.*use_authtok' "$f" || \
      sed -i -E 's|^(\s*password\s+.*pam_pwhistory\.so.*)$|\1 use_authtok|' "$f"
  else
    ensure_pwhistory_line
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
check_pam_unix_wiring() {
  grep -Eq '^account[[:space:]]+\[success=1[^]]*\][[:space:]]+pam_unix\.so' /etc/pam.d/common-account 2>/dev/null || return 1
  grep -Eq '^auth[[:space:]]+\[success=[23][^]]*default=ignore[^]]*\][[:space:]]+pam_unix\.so' /etc/pam.d/common-auth 2>/dev/null || return 1
  grep -Eq '^password[[:space:]]+\[success=[12][^]]*default=ignore[^]]*\][[:space:]]+pam_unix\.so' /etc/pam.d/common-password 2>/dev/null || return 1
  grep -Eq '^session[[:space:]]+required[[:space:]]+pam_unix\.so' /etc/pam.d/common-session 2>/dev/null || return 1
  return 0
}
check_pam_faillock_wiring() {
  grep -Eq '^account[[:space:]]+required[[:space:]]+pam_faillock\.so' /etc/pam.d/common-account 2>/dev/null || return 1
  grep -Eq '^auth.*\[default=die\].*pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null || return 1
  grep -Eq '^auth[[:space:]]+requisite[[:space:]]+pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null || return 1
  return 0
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
  control "ACC.root_umask" "root's shell umask is 027 or 077 (~/.bashrc, ~/.bash_profile)" \
    check_root_umask fix_root_umask
  control "ACC.inactive" "INACTIVE lock <= 30 days for new accounts (useradd defaults)" check_inactive fix_inactive
  control "ACC.tmout" "default interactive shell idle timeout (TMOUT) configured, <= 900s" \
    check_tmout fix_tmout
  control "ACC.existing_users_aging" "existing human accounts (UID 1000-65533 with a real password) also have password-aging limits applied — login.defs only affects newly-created accounts" \
    check_existing_users_aging fix_existing_users_aging
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
check_root_umask() {
  # Both files are required (Ubuntu doesn't ship /root/.bash_profile by
  # default — bash reads it for login shells, .bashrc for interactive
  # non-login shells; root can hit either depending on how it's invoked).
  # Check existence explicitly first: grep exits 2 (not 1) on a missing
  # file, which control() reads as "N/A" rather than "needs fixing" — and
  # .bash_profile not existing is the common case here, so that silently
  # skipped this control instead of creating the file.
  local f
  for f in /root/.bash_profile /root/.bashrc; do
    [[ -f "$f" ]] || return 1
    grep -Eq 'umask.*(0027|0077)' "$f" || return 1
  done
  return 0
}
fix_root_umask() {
  for f in /root/.bash_profile /root/.bashrc; do
    [[ -e "$f" ]] || touch "$f"
    backup_file "$f"
    if grep -Eq '^\s*umask\s+' "$f"; then
      sed -i -E 's/^\s*umask\s+.*/umask 0027/' "$f"
    else
      printf '\numask 0027\n' >> "$f"
    fi
  done
}
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
# _each_human_user <callback> — invoke callback with each real human
# account's username: UID 1000-65533 (excludes system accounts and the
# 65534 'nobody' sentinel) with an actual settable password (skips locked
# '!'-prefixed, '*', and empty-password/system entries).
_each_human_user() {
  local callback="$1" user uid pass
  while IFS=: read -r user _ uid _ _ _ _; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    pass="$(getent shadow "$user" 2>/dev/null | cut -d: -f2)"
    case "$pass" in
      ''|'!'*|'*') continue ;;
    esac
    "$callback" "$user"
  done < /etc/passwd
}
check_existing_users_aging() {
  local rc=0
  _check_one_user_aging() {
    local user="$1" line max min inact
    line="$(getent shadow "$user" 2>/dev/null)"
    max="$(echo "$line" | cut -d: -f5)"
    min="$(echo "$line" | cut -d: -f4)"
    inact="$(echo "$line" | cut -d: -f7)"
    [[ -n "$max" && "$max" -le 365 ]] || rc=1
    [[ -n "$min" && "$min" -ge 1 ]] || rc=1
    [[ -n "$inact" && "$inact" -le 30 ]] || rc=1
  }
  _each_human_user _check_one_user_aging
  return "$rc"
}
fix_existing_users_aging() {
  _fix_one_user_aging() { chage --maxdays 365 --mindays 1 --inactive 30 "$1" 2>/dev/null || true; }
  _each_human_user _fix_one_user_aging
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
  # opasswd.old (the previous-rotation backup pam_pwhistory keeps) doesn't
  # exist until a password has actually been changed once — pre-create it
  # with the right permissions so the check doesn't just wait around for
  # that to happen naturally.
  control "PERM.opasswd_old" "/etc/security/opasswd.old mode 0600 (or stricter), owned root:root" \
    check_opasswd_old fix_opasswd_old
}
check_opasswd_old() {
  [[ -e /etc/security/opasswd.old ]] || return 1   # missing -> needs creating, not N/A
  check_perm_max /etc/security/opasswd.old 600 root root
}
fix_opasswd_old() {
  [[ -e /etc/security/opasswd.old ]] || touch /etc/security/opasswd.old
  fix_perm /etc/security/opasswd.old 600 root root
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
# Require the exact unquoted form so a stale quoted value from an older
# version of this script (Defaults logfile="/var/log/sudo.log") gets
# normalized instead of being accepted as-is forever.
check_sudo_logfile() { grep -REq '^\s*Defaults\s+logfile=/var/log/sudo\.log\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; }
fix_sudo_logfile() {
  # Remove any existing logfile= directive first (main file and any
  # drop-in) so we don't end up with two conflicting Defaults lines.
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    grep -Eq '^\s*Defaults\s+logfile=' "$f" 2>/dev/null || continue
    backup_file "$f"
    sed -i -E '/^\s*Defaults\s+logfile=/d' "$f"
    if [[ "$f" == "/etc/sudoers" ]]; then
      visudo -cf /etc/sudoers >/dev/null || log INFO "Warning: /etc/sudoers failed visudo -cf after removing a stale logfile= line — check it manually."
    fi
  done
  backup_file "$SUDOERS_DROPIN"
  echo 'Defaults logfile=/var/log/sudo.log' >> "$SUDOERS_DROPIN"
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
    # Most clusters are IPv4-only, in which case IPv6 forwarding staying off
    # is correct and harmless. A dual-stack/IPv6 pod network needs it on —
    # since we can't tell which this is, leave it alone rather than guess
    # either way (unlike ip_forward, where "off" is unambiguously wrong).
    say_skip "SYSCTL.net.ipv6.conf.all.forwarding" "net.ipv6.conf.all.forwarding (left as-is — Docker/Kubernetes detected; only needed for dual-stack/IPv6 pod networking)"
  else
    control "SYSCTL.net.ipv4.ip_forward" "net.ipv4.ip_forward = 0" \
      "check_sysctl_eq net.ipv4.ip_forward 0" "fix_sysctl net.ipv4.ip_forward 0"
    control "SYSCTL.net.ipv6.conf.all.forwarding" "net.ipv6.conf.all.forwarding = 0" \
      "check_sysctl_eq net.ipv6.conf.all.forwarding 0" "fix_sysctl net.ipv6.conf.all.forwarding 0"
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
  control "AUDIT.disk_error" "auditd disk_error_action = syslog" \
    check_audit_disk_error fix_audit_disk_error
  # disk_full_action only accepts halt|single at Level 1 (no lighter option
  # like 'syslog' satisfies this specific control) — both are disruptive:
  # 'single' drops to single-user mode (kills networking too — on a remote
  # box without console access, that's an effective lockout until someone
  # reaches the physical/virtual console), 'halt' stops the machine outright.
  # This is a real, CIS-documented tradeoff (fail closed on audit-log
  # exhaustion), not a script bug — review before relying on this in
  # --apply on a host you can't reach a console for.
  control "AUDIT.disk_full" "auditd disk_full_action = single (system stops accepting logins when the audit partition fills — see comment above)" \
    check_audit_disk_full fix_audit_disk_full
  control "AUDIT.space_left" "auditd space_left_action = email (warn while space remains, before it's actually low)" \
    check_audit_space_left fix_audit_space_left
  control "AUDIT.admin_space_left" "auditd admin_space_left_action = single (once space is critically low)" \
    check_audit_admin_space_left fix_audit_admin_space_left
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
_auditd_conf_set() {
  local key="$1" val="$2"
  backup_file "$AUDITD_CONF"; touch "$AUDITD_CONF"
  if grep -Eq "^${key}\s*=" "$AUDITD_CONF"; then
    sed -i -E "s|^${key}\s*=.*|${key} = ${val}|" "$AUDITD_CONF"
  else
    echo "${key} = ${val}" >> "$AUDITD_CONF"
  fi
}
check_audit_disk_error() { [[ -f "$AUDITD_CONF" ]] && grep -Eq '^disk_error_action\s*=\s*(syslog|single|halt)' "$AUDITD_CONF"; }
fix_audit_disk_error() { _auditd_conf_set disk_error_action syslog; }
check_audit_disk_full() { [[ -f "$AUDITD_CONF" ]] && grep -Eq '^disk_full_action\s*=\s*(halt|single)' "$AUDITD_CONF"; }
fix_audit_disk_full() { _auditd_conf_set disk_full_action single; }
check_audit_space_left() { [[ -f "$AUDITD_CONF" ]] && grep -Eq '^space_left_action\s*=\s*(email|exec|single|halt)' "$AUDITD_CONF"; }
fix_audit_space_left() { _auditd_conf_set space_left_action email; }
check_audit_admin_space_left() { [[ -f "$AUDITD_CONF" ]] && grep -Eq '^admin_space_left_action\s*=\s*(single|halt)' "$AUDITD_CONF"; }
fix_audit_admin_space_left() { _auditd_conf_set admin_space_left_action single; }

# ---------------------------------------------------------------------------
# 16b. Audit rules (auditctl / /etc/audit/rules.d) — CIS 6.2.3.x
# ---------------------------------------------------------------------------
# These are purely observational (what gets logged) — unlike the firewall or
# ip_forward sections, there's no operational-safety reason to special-case
# a Docker/Kubernetes host here, so this applies uniformly.
#
# WARNING: the last rule below is "-e 2", which makes the running audit
# configuration IMMUTABLE until the next reboot — no further audit rule
# changes (from this script or anything else, including auditctl itself)
# can be applied without rebooting first. That's intentional (CIS 6.2.3.20:
# tamper-resistance), but it means if you need to adjust audit rules again
# on the same boot, you'll have to reboot first.
AUDIT_RULES_FILE="/etc/audit/rules.d/60-cis-hardening.rules"
AUDIT_IMMUTABLE_FILE="/etc/audit/rules.d/zz-cis-immutable.rules"

section_audit_rules() {
  echo "== 16b. Audit rules =="
  if ! pkg_installed auditd; then
    say_skip "AUDIT_RULES.*" "auditd not installed — run the 'auditd' section (with --apply) first, then re-run this one"
    return
  fi

  control "AUDIT_RULES.scope" "changes to sudoers scope are collected (-w /etc/sudoers, /etc/sudoers.d)" \
    "check_audit_key scope" fix_audit_rules_write_all
  control "AUDIT_RULES.user_emulation" "actions as another user (setuid execve) are logged" \
    "check_audit_key user_emulation" fix_audit_rules_write_all
  control "AUDIT_RULES.sudo_log_file" "changes to the sudo log file are collected" \
    "check_audit_key sudo_log_file" fix_audit_rules_write_all
  control "AUDIT_RULES.time-change" "changes to date/time are collected" \
    "check_audit_key time-change" fix_audit_rules_write_all
  control "AUDIT_RULES.system-locale" "changes to the network environment are collected" \
    "check_audit_key system-locale" fix_audit_rules_write_all
  control "AUDIT_RULES.access" "unsuccessful file access attempts are collected" \
    "check_audit_key access" fix_audit_rules_write_all
  control "AUDIT_RULES.identity" "changes to user/group identity files are collected" \
    "check_audit_key identity" fix_audit_rules_write_all
  control "AUDIT_RULES.perm_mod" "discretionary access control (permission) changes are collected" \
    "check_audit_key perm_mod" fix_audit_rules_write_all
  control "AUDIT_RULES.mounts" "successful filesystem mounts are collected" \
    "check_audit_key mounts" fix_audit_rules_write_all
  control "AUDIT_RULES.session" "session initiation (utmp/wtmp/btmp) is collected" \
    "check_audit_key session" fix_audit_rules_write_all
  control "AUDIT_RULES.logins" "login/logout events are collected" \
    "check_audit_key logins" fix_audit_rules_write_all
  control "AUDIT_RULES.delete" "file deletion events by users are collected" \
    "check_audit_key delete" fix_audit_rules_write_all
  control "AUDIT_RULES.MAC-policy" "changes to AppArmor (MAC) policy are collected" \
    "check_audit_key MAC-policy" fix_audit_rules_write_all
  control "AUDIT_RULES.perm_chng" "use of chcon/setfacl/chacl is collected" \
    "check_audit_key perm_chng" fix_audit_rules_write_all
  control "AUDIT_RULES.usermod" "use of usermod is collected" \
    "check_audit_key usermod" fix_audit_rules_write_all
  control "AUDIT_RULES.kernel_modules" "kernel module load/unload is collected" \
    "check_audit_key kernel_modules" fix_audit_rules_write_all
  control "AUDIT_RULES.immutable" "audit configuration is immutable (-e 2 — see warning above; needs a reboot to take effect after being written)" \
    check_audit_immutable fix_audit_immutable
}

check_audit_key() {
  local key="$1"
  auditctl -l 2>/dev/null | grep -Eq -- "-k ${key}\$|-k ${key}[[:space:]]|-F key=${key}\$|-F key=${key}[[:space:]]"
}

fix_audit_rules_write_all() {
  backup_file "$AUDIT_RULES_FILE"
  cat > "$AUDIT_RULES_FILE" <<'EOF'
## This file is managed by harden_ubuntu24_cis_l1.sh (CIS 6.2.3.x). Manual
## edits will be overwritten the next time the script's audit_rules
## section is applied.

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid!=unset -S execve -k user_emulation

-w /var/log/sudo.log -p wa -k sudo_log_file

-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale

-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
EOF
  chmod 640 "$AUDIT_RULES_FILE"
  augenrules --load >/dev/null 2>&1 || {
    # Loading fails outright if the running config is already immutable
    # (-e 2) from an earlier boot — that's expected, not an error: the file
    # content above will still take effect on the next reboot.
    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
      log INFO "Audit config is already immutable (enabled 2) for this boot — $AUDIT_RULES_FILE was updated and will take effect after the next reboot."
    else
      return 1
    fi
  }
}

check_audit_immutable() {
  [[ -d /etc/audit/rules.d ]] || return 1
  grep -Rq '^-e[[:space:]]*2[[:space:]]*$' /etc/audit/rules.d/*.rules 2>/dev/null
}
fix_audit_immutable() {
  backup_file "$AUDIT_IMMUTABLE_FILE"
  echo '-e 2' > "$AUDIT_IMMUTABLE_FILE"
  chmod 640 "$AUDIT_IMMUTABLE_FILE"
  augenrules --load >/dev/null 2>&1 || true
  log INFO "-e 2 (immutable audit config) written to $AUDIT_IMMUTABLE_FILE. Effective now if this is the first audit-rule load this boot, otherwise after the next reboot. Once active, audit rules cannot be changed again (by this script or anything else) until the system is rebooted."
}

# ---------------------------------------------------------------------------
# 17. System logging
# ---------------------------------------------------------------------------
section_logging() {
  echo "== 17. rsyslog / journald =="
  control "LOG.rsyslog" "rsyslog installed and enabled" check_rsyslog fix_rsyslog
  control "LOG.journald_persist" "systemd-journald configured for persistent storage" check_journald_persist fix_journald_persist
  control "LOG.journald_rotate" "systemd-journald rotation fully configured (SystemMaxUse/SystemKeepFree/RuntimeMaxUse/RuntimeKeepFree/MaxFileSec)" \
    check_journald_rotate fix_journald_rotate
  if pkg_installed rsyslog; then
    control "LOG.rsyslog_filemode" "rsyslog log file creation mode 0640 or stricter" \
      check_rsyslog_filemode fix_rsyslog_filemode
  fi
  control "LOG.varlog_perms" "no files under /var/log are group-writable or world-readable/writable/executable" \
    check_varlog_perms fix_varlog_perms
}
check_varlog_perms() {
  [[ -d /var/log ]] || return 2
  # perm bits: group-write (020) or any "other" bit (007)
  ! find /var/log -type f -perm /027 2>/dev/null | grep -q .
}
fix_varlog_perms() {
  # Conservative: only strip group-write and all "other" bits. Leaves
  # owner permissions (and any group-read auditd/rsyslog/etc. rely on to
  # actually write these files) untouched.
  find /var/log -type f -exec chmod g-w,o-rwx {} \; 2>/dev/null || true
}
check_rsyslog() { pkg_installed rsyslog && svc_active rsyslog.service; }
fix_rsyslog() { apt-get update -qq && apt-get install -y -qq rsyslog; systemctl enable --now rsyslog.service; }
check_journald_rotate() {
  local f=/etc/systemd/journald.conf
  local key
  for key in SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec; do
    grep -Eq "^\s*${key}\s*=\s*\S+" "$f" 2>/dev/null || return 1
  done
  return 0
}
fix_journald_rotate() {
  local f=/etc/systemd/journald.conf
  backup_file "$f"
  declare -A vals=(
    [SystemMaxUse]=500M
    [SystemKeepFree]=1G
    [RuntimeMaxUse]=100M
    [RuntimeKeepFree]=200M
    [MaxFileSec]=1month
  )
  local key
  for key in "${!vals[@]}"; do
    if grep -Eq "^\s*#?\s*${key}\s*=" "$f"; then
      sed -i -E "s/^\s*#?\s*${key}\s*=.*/${key}=${vals[$key]}/" "$f"
    else
      echo "${key}=${vals[$key]}" >> "$f"
    fi
  done
  # Also drop a conf.d file with the same settings — the SCA policy checks
  # for either, and this survives journald.conf itself being reset.
  mkdir -p /etc/systemd/journald.conf.d
  local dropin=/etc/systemd/journald.conf.d/60-cis-hardening.conf
  backup_file "$dropin"
  {
    echo '[Journal]'
    for key in "${!vals[@]}"; do echo "${key}=${vals[$key]}"; done
  } > "$dropin"
  systemctl restart systemd-journald
}
RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_DROPIN="/etc/rsyslog.d/60-cis-hardening.conf"
check_rsyslog_filemode() {
  [[ -f "$RSYSLOG_CONF" ]] || return 1
  local v; v="$(grep -Eo '\$FileCreateMode\s+[0-7]{3,4}' "$RSYSLOG_CONF" | tail -1 | awk '{print $2}')"
  [[ -n "$v" && "$v" -le 640 ]] || return 1
  # The scanner requires BOTH rsyslog.conf itself AND at least one file
  # under rsyslog.d/ to declare this — matching that exactly rather than
  # just the main file (same shape as the journald.conf.d requirement).
  grep -Erlq '^\$FileCreateMode\s+(0640|0600|0400)' /etc/rsyslog.d/*.conf 2>/dev/null
}
fix_rsyslog_filemode() {
  backup_file "$RSYSLOG_CONF"
  if grep -Eq '^\s*\$FileCreateMode' "$RSYSLOG_CONF"; then
    sed -i -E 's/^\s*\$FileCreateMode\s+[0-7]{3,4}/\$FileCreateMode 0640/' "$RSYSLOG_CONF"
  else
    echo '$FileCreateMode 0640' >> "$RSYSLOG_CONF"
  fi
  backup_file "$RSYSLOG_DROPIN"
  echo '$FileCreateMode 0640' > "$RSYSLOG_DROPIN"
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
  control "AIDE.audit_tools" "AIDE monitors the audit tool binaries for tampering" \
    check_aide_audit_tools fix_aide_audit_tools
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
AIDE_CONF="/etc/aide/aide.conf"
check_aide_audit_tools() {
  [[ -f "$AIDE_CONF" ]] || return 1
  local t
  for t in auditctl auditd ausearch aureport autrace augenrules; do
    grep -Eq "(^/sbin|/usr/sbin)/${t}[[:space:]]+.*p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512" "$AIDE_CONF" || return 1
  done
  return 0
}
fix_aide_audit_tools() {
  [[ -f "$AIDE_CONF" ]] || return 1
  backup_file "$AIDE_CONF"
  {
    echo ""
    echo "# CIS 6.3.3 -- integrity monitoring for the audit tool binaries themselves"
    for t in auditctl auditd ausearch aureport autrace augenrules; do
      grep -Eq "(^/sbin|/usr/sbin)/${t}[[:space:]]+.*p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512" "$AIDE_CONF" || \
        echo "/sbin/${t} p+i+n+u+g+s+b+acl+xattrs+sha512"
    done
  } >> "$AIDE_CONF"
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
