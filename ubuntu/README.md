# Ubuntu 24.04 LTS — CIS Level 1 checklist

Run `harden_ubuntu24_cis_l1.sh` (see repo root README for usage). Each row
below is one control implemented by the script; `--list` prints the section
keys, `--only` runs a subset. This is a plain-language mapping, not the CIS
benchmark text itself — check the official CIS Ubuntu Linux 24.04 LTS
Benchmark if you need exact wording/rationale for an audit.

## Docker / Kubernetes hosts

The script detects Docker/Kubernetes (`docker.service`, `containerd.service`,
`kubelet.service`, `crio.service`, or a `docker`/`kubectl` binary on `PATH`)
and changes behavior on two fronts that would otherwise break a running
cluster:

- **`net.ipv4.ip_forward`** — kept at **1** instead of being forced to `0`.
  Container/pod networking does not work without it.
- **Host firewall section is skipped entirely** — kube-proxy and your CNI
  plugin (Calico/Flannel/Cilium/etc.) manage `iptables`/`nftables` rules
  directly. Enabling `ufw`, forcing a default-deny policy, or flushing
  `iptables` rules to `nftables` can break pod networking, Services, and
  NetworkPolicies. Firewall these hosts at the cloud security-group /
  perimeter layer, or with Kubernetes NetworkPolicies, instead.

Everything else in this script (SSH, PAM, auditd, AppArmor, file
permissions, etc.) is safe to run on a Docker/Kubernetes node as usual. One
thing worth a manual look: `net.ipv4.conf.*.rp_filter=1` (strict
reverse-path filtering, still applied) can drop traffic under some
CNI/LoadBalancer configurations that preserve source IPs (e.g.
`externalTrafficPolicy: Local`) — the script logs a reminder when it detects
a container platform.

This repo does not (yet) include the separate **CIS Docker Benchmark** or
**CIS Kubernetes Benchmark** controls (daemon config, image/registry policy,
pod security admission, etc.) — only host-OS Level 1 hardening that's safe
to run alongside those workloads.

| Section | Control ID | What it checks |
|---|---|---|
| Filesystem modules | `FS.*` | `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf` kernel modules blacklisted and unloaded |
| Network protocol modules | `NETMOD.*` | `dccp`, `tipc`, `rds`, `sctp` kernel modules blacklisted and unloaded |
| Software updates | `UPD.unattended` | `unattended-upgrades` installed and enabled |
| | `UPD.gpgcheck` | APT never configured to allow unauthenticated/insecure repos |
| Process hardening | `PROC.aslr` | `kernel.randomize_va_space = 2` |
| | `PROC.coredump_suid` | `fs.suid_dumpable = 0` |
| | `PROC.coredump_limit` | Core dumps disabled via `limits.conf` |
| | `PROC.coredump_systemd` | `systemd-coredump` storage disabled (`Storage=none`) |
| | `PROC.prelink` | `prelink` package absent |
| | `PROC.apport` | Automatic Error Reporting (`apport`) disabled |
| AppArmor | `MAC.installed` | `apparmor` + `apparmor-utils` installed |
| | `MAC.bootloader` | AppArmor enabled (kernel default, or `apparmor=1 security=apparmor` on the GRUB cmdline) |
| | `MAC.enabled` | AppArmor active with profiles in enforce mode |
| Banners | `BANNER.issue` / `.issue.net` / `.motd` | Authorized-use warning banner present |
| | `BANNER.perms` | `/etc/issue*` owned root:root, mode 0644 |
| Unnecessary services | `SVC.*` | Common unneeded network services (avahi, cups, dhcp/dns/ftp/ldap/mail/nfs/nis/print/rsync/snmp/tftp/proxy/web servers, xinetd) disabled if present |
| | `SVC.telnet_client` / `.ftp_client` | `telnet`/`ftp` client packages removed |
| | `SVC.xserver` | X window server packages removed (servers should be headless) |
| Time sync | `TIME.installed` | `chrony` or `systemd-timesyncd` installed and active |
| | `TIME.timeserver` | chrony has at least one `server`/`pool` configured |
| | `TIME.chronyuser` | `chronyd` runs as the unprivileged `_chrony` user |
| cron/at | `CRON.svc` | `cron.service` enabled |
| | `CRON.perms` | cron config paths owned root, not group/world-writable |
| | `CRON.deny` | `cron.deny`/`at.deny` removed (allow-list model) |
| SSH | `SSH.perms` | `sshd_config` root:root, mode 0600 |
| | `SSH.protocol` | No legacy `Protocol 1` directive |
| | `SSH.rootlogin` | `PermitRootLogin no` |
| | `SSH.emptypass` | `PermitEmptyPasswords no` |
| | `SSH.x11` | `X11Forwarding no` |
| | `SSH.disableforwarding` | `DisableForwarding yes` |
| | `SSH.maxauth` | `MaxAuthTries` ≤ 4 |
| | `SSH.maxstartups` | `MaxStartups 10:30:60` |
| | `SSH.ignorerhosts` | `IgnoreRhosts yes` |
| | `SSH.hostbased` | `HostbasedAuthentication no` |
| | `SSH.userenv` | `PermitUserEnvironment no` |
| | `SSH.clientalive` | `ClientAliveInterval 300`, `ClientAliveCountMax 3` |
| | `SSH.logingrace` | `LoginGraceTime` ≤ 60 |
| | `SSH.maxsessions` | `MaxSessions` ≤ 10 |
| | `SSH.loglevel` | `LogLevel VERBOSE` |
| | `SSH.banner` | `Banner /etc/issue.net` |
| | `SSH.ciphers` | Explicit strong `Ciphers`/`MACs`/`KexAlgorithms` |
| PAM | `PAM.pwquality_pkg` | `libpam-pwquality` installed |
| | `PAM.minlen` | `minlen >= 14` |
| | `PAM.complexity` | Character-class requirements enforced |
| | `PAM.faillock` | `faillock.conf`: `deny<=5`, `unlock_time>=900` |
| | `PAM.faillock_root` | faillock also covers the root account (`even_deny_root`, `root_unlock_time`) |
| | `PAM.remember` | `pam_pwhistory` `remember=5` |
| | `PAM.remember_root` | Password history enforced for root too (`enforce_for_root`) |
| | `PAM.pwhistory_use_authtok` | `pam_pwhistory` uses `use_authtok` |
| | `PAM.unix_nullok` | `pam_unix` does not permit empty passwords (no `nullok`) |
| | `PAM.unix_use_authtok` | `pam_unix` uses `use_authtok` |
| `su` restriction | `ACL.su_restricted` | `su` restricted to members of the `sudo` group via `pam_wheel` |
| Accounts | `ACC.maxdays` / `.mindays` / `.warnage` | `PASS_MAX_DAYS<=365`, `PASS_MIN_DAYS>=1`, `PASS_WARN_AGE>=7` |
| | `ACC.umask` | Default `UMASK 027` (also covers root, since it's PAM/login.defs-wide) |
| | `ACC.inactive` | New accounts locked ≤30 days after password expiry |
| | `ACC.tmout` | Idle interactive shells auto-logout (`TMOUT<=900`) |
| File permissions | `PERM.passwd` / `.shadow` / `.group` / `.gshadow` / `.opasswd` | Ownership and mode on the core account databases |
| sudo | `SUDO.logfile` | `Defaults logfile=` configured |
| | `SUDO.use_pty` | `Defaults use_pty` |
| Kernel network params | `SYSCTL.*` | IP forwarding (see Docker/K8s note above), source routing, ICMP redirects, martian logging, broadcast ICMP, bogus ICMP responses, reverse-path filtering, SYN cookies, IPv6 router advertisements |
| Firewall | `FW.installed` / `.enabled` / `.default_deny` | `ufw` installed, active, default-deny incoming — **skipped on Docker/Kubernetes hosts**, see above |
| Auditd | `AUDIT.installed` | `auditd` installed and running |
| | `AUDIT.maxlogfile` / `.keep_logs` | Log rotation size and retention |
| | `AUDIT.backlog` | `audit_backlog_limit>=8192` on the kernel cmdline (GRUB; needs reboot) |
| | `AUDIT.early` | `audit=1` on the kernel cmdline, so auditing covers early boot (GRUB; needs reboot) |
| | `AUDIT.tool_owner` | Audit tool binaries owned root:root, mode ≤0755 |
| Logging | `LOG.rsyslog` | `rsyslog` installed and running |
| | `LOG.journald_persist` | `journald` persists logs to disk |
| | `LOG.journald_rotate` | `journald` rotation configured (`SystemMaxUse`) |
| | `LOG.rsyslog_filemode` | rsyslog-created log files mode ≤0640 |
| AIDE | `AIDE.installed` | AIDE installed, database initialized |
| | `AIDE.cron` | Scheduled integrity check |

## Notes / manual follow-ups

- `usb-storage` module disabling is intentionally **skipped by default** —
  disabling it can break USB installers/keyboards on physical hardware.
  Review `section_filesystem_modules` in the script if you want it enforced.
- `AUDIT.backlog` / `AUDIT.early` / `MAC.bootloader` edit
  `/etc/default/grub` and run `update-grub`, but **do not reboot** — the
  kernel cmdline change only takes effect after a reboot you schedule
  yourself. Skipped (not failed) on systems that don't use GRUB (e.g.
  systemd-boot cloud images).
- `ACL.su_restricted` (restricting `su` via `pam_wheel`) only applies if the
  user running `sudo ./harden...sh` is already a member of the `sudo`
  group — otherwise it's skipped with a log message, so you can't
  accidentally lock yourself out of `su`.
- `PAM.faillock`/`PAM.remember*` only edit the relevant `.conf` files; wiring
  `pam_faillock`/`pam_pwhistory` into `/etc/pam.d/common-auth` if they aren't
  already there is left as a manual step via `pam-auth-update`, so the
  script doesn't silently rewrite your PAM stack structure.
- Separate partitions/mount options (`/tmp`, `/var`, `/home` with
  `nodev,nosuid,noexec`) and a GRUB bootloader password are **not**
  automated here — both require install-time/physical-console changes and
  are too easy to get destructively wrong from a script.
- GDM/desktop-specific controls are out of scope (script targets servers);
  add a `desktop` section if you're hardening workstations with a GUI.
- A remote syslog destination (`rsyslog` "send logs to a remote log host")
  is inherently org-specific — not automated; point `rsyslog.conf` at your
  log collector manually.
