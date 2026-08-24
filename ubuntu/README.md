# Ubuntu 24.04 LTS — CIS Level 1 checklist

Run `harden_ubuntu24_cis_l1.sh` (see repo root README for usage). Each row
below is one control implemented by the script; `--list` prints the section
keys, `--only` runs a subset. This is a plain-language mapping, not the CIS
benchmark text itself — check the official CIS Ubuntu Linux 24.04 LTS
Benchmark if you need exact wording/rationale for an audit.

## Docker / Kubernetes hosts

The script detects Docker/Kubernetes (`docker.service`, `containerd.service`,
`kubelet.service`, `crio.service`, or a `docker`/`kubectl` binary on `PATH`)
and changes behavior on three fronts that would otherwise break a running
cluster:

- **`net.ipv4.ip_forward`** — kept at **1** instead of being forced to `0`.
  Container/pod networking does not work without it. `net.ipv6.conf.all.forwarding`
  is left alone either way (only relevant for dual-stack/IPv6 pod networking).
- **Host firewall section is skipped entirely** — kube-proxy and your CNI
  plugin (Calico/Flannel/Cilium/etc.) manage `iptables`/`nftables` rules
  directly. Enabling `ufw`, forcing a default-deny policy, or flushing
  `iptables` rules to `nftables` can break pod networking, Services, and
  NetworkPolicies. Firewall these hosts at the cloud security-group /
  perimeter layer, or with Kubernetes NetworkPolicies, instead. **This means
  an automated CIS/SCA scan will always show the 4.x firewall controls as
  failed on a container host** — that's an intentional, documented tradeoff,
  not a gap to chase.
- **`cifs`/`fuse`/`nfs_common`/`nfsd`/`ceph` kernel modules are left alone**
  (reviewed manually instead of auto-blacklisted) — these back SMB/NFS/CephFS
  PersistentVolumes and FUSE-based CSI drivers or rootless containers.
  Blacklisting one your cluster actually uses doesn't fail loudly; it just
  makes that filesystem permanently unmountable.

Everything else in this script (SSH, PAM, auditd, AppArmor, file
permissions, audit rules, etc.) is safe to run on a Docker/Kubernetes node
as usual. One thing worth a manual look: `net.ipv4.conf.*.rp_filter=1`
(strict reverse-path filtering, still applied) can drop traffic under some
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
| Additional filesystem modules | `FSX.afs`/`.exfat`/`.ext`/`.fat`/`.fscache`/`.gfs2`/`.smbfs_common` | Always blacklisted — never used by Docker/Kubernetes |
| | `FSX.cifs`/`.fuse`/`.nfs_common`/`.nfsd`/`.ceph` | Blacklisted on non-container hosts; **reviewed manually on Docker/Kubernetes hosts** (see above) |
| Software updates | `UPD.unattended` | `unattended-upgrades` installed and enabled |
| | `UPD.gpgcheck` | APT never configured to allow unauthenticated/insecure repos |
| Process hardening | `PROC.aslr` | `kernel.randomize_va_space = 2` |
| | `PROC.coredump_suid` | `fs.suid_dumpable = 0` |
| | `PROC.coredump_limit` | Core dumps disabled via `limits.conf` |
| | `PROC.coredump_systemd` | `systemd-coredump` storage disabled (`Storage=none`) |
| | `PROC.prelink` | `prelink` package absent |
| | `PROC.apport` | Automatic Error Reporting (`apport`) disabled |
| AppArmor | `MAC.installed` | `apparmor` + `apparmor-utils` installed |
| | `MAC.bootloader` | `apparmor=1 security=apparmor` present on the GRUB cmdline (checked literally, per CIS — not just "AppArmor happens to be active") |
| | `MAC.enabled` | `aa-status`: profiles loaded > 0, in enforce mode > 0, 0 unconfined processes, 0 in complain mode, 0 in kill mode |
| Banners | `BANNER.issue` / `.issue.net` / `.motd` | Authorized-use warning banner present |
| | `BANNER.perms` | `/etc/issue*` owned root:root, mode 0644 |
| Unnecessary services | `SVC.*` | Common unneeded network service **packages purged** (avahi, cups, dhcp/dns/ftp/ldap/mail/nfs/nis/print/rsync/snmp/tftp/proxy/web servers, xinetd) — not just the service disabled, matching CIS's own remediation |
| | `SVC.telnet_client` | `telnet` **and** `inetutils-telnet` removed |
| | `SVC.ftp_client` | `ftp` **and** `tnftp` removed |
| | `SVC.xserver` | X window server packages removed (servers should be headless) |
| Time sync | `TIME.installed` | `chrony` specifically installed, active, and enabled (see note below) |
| | `TIME.timeserver` | chrony has at least one `server`/`pool` configured |
| | `TIME.chronyuser` | `chronyd` runs as the unprivileged `_chrony` user |
| cron/at | `CRON.svc` | `cron.service` enabled |
| | `CRON.perms` | cron config paths owned root, not group/world-writable |
| | `CRON.deny` | `cron.deny`/`at.deny` removed (allow-list model) |
| | `CRON.allow` | `/etc/cron.allow` exists, root:root, mode 0600 |
| | `AT.allow` | `at` package installed, `/etc/at.allow` exists, root:root, mode 0600 |
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
| | `SSH.ciphers` | Explicit strong `Ciphers`/`MACs`/`KexAlgorithms` (no weak MACs like `hmac-md5*`/`hmac-sha1-96`/`umac-64*`) |
| | `SSH.access_control` | **Not automated** — informational only, see notes below |
| PAM | `PAM.pwquality_pkg` | `libpam-pwquality` installed |
| | `PAM.minlen` | `minlen >= 14` |
| | `PAM.difok` | `difok >= 2` (characters that must differ from the old password) |
| | `PAM.complexity` | `minclass >= 4` (all 4 character classes required) |
| | `PAM.maxrepeat` | `maxrepeat` between 1 and 3 (no long runs of one character) |
| | `PAM.maxsequence` | `maxsequence` between 1 and 3 (no long runs like `abcd`/`1234`) |
| | `PAM.faillock` | `faillock.conf`: `deny<=5`, `unlock_time>=900` |
| | `PAM.faillock_root` | faillock also covers the root account (`even_deny_root`, `root_unlock_time`) |
| | `PAM.remember` | `pam_pwhistory` `remember=24` |
| | `PAM.remember_root` | Password history enforced for root too (`enforce_for_root`) |
| | `PAM.pwhistory_use_authtok` | `pam_pwhistory` uses `use_authtok` |
| | `PAM.unix_nullok` | `pam_unix` does not permit empty passwords (no `nullok`) |
| | `PAM.unix_use_authtok` | `pam_unix` uses `use_authtok` |
| `su` restriction | `ACL.su_restricted` | `su` restricted to members of the `sudo` group via `pam_wheel` |
| Accounts | `ACC.maxdays` / `.mindays` / `.warnage` | `PASS_MAX_DAYS<=365`, `PASS_MIN_DAYS>=1`, `PASS_WARN_AGE>=7` in `/etc/login.defs` (new accounts only) |
| | `ACC.existing_users_aging` | The same limits (`chage --maxdays 365 --mindays 1 --inactive 30`) retroactively applied to existing human accounts (UID 1000–65533 with a real password) — `login.defs` alone only affects accounts created *after* the change |
| | `ACC.umask` | Default `UMASK 027` in `/etc/login.defs` |
| | `ACC.root_umask` | `umask 0027`/`0077` in **both** `/root/.bash_profile` and `/root/.bashrc` |
| | `ACC.inactive` | New accounts locked ≤30 days after password expiry |
| | `ACC.tmout` | Idle interactive shells auto-logout (`TMOUT<=900`) |
| File permissions | `PERM.passwd` / `.shadow` / `.group` / `.gshadow` / `.opasswd` | Ownership and mode on the core account databases |
| sudo | `SUDO.logfile` | `Defaults logfile=/var/log/sudo.log` configured |
| | `SUDO.use_pty` | `Defaults use_pty` |
| Kernel network params | `SYSCTL.*` | IP forwarding (see Docker/K8s note above), IPv6 forwarding, source routing, ICMP redirects, martian logging, broadcast ICMP, bogus ICMP responses, reverse-path filtering, SYN cookies, IPv6 router advertisements |
| Firewall | `FW.installed` / `.enabled` / `.default_deny` | `ufw` installed, active, default-deny incoming — **skipped on Docker/Kubernetes hosts**, see above |
| Auditd | `AUDIT.installed` | `auditd` installed and running |
| | `AUDIT.maxlogfile` / `.keep_logs` | Log rotation size and retention |
| | `AUDIT.backlog` | `audit_backlog_limit>=8192` on the kernel cmdline (GRUB; needs reboot) |
| | `AUDIT.early` | `audit=1` on the kernel cmdline, so auditing covers early boot (GRUB; needs reboot) |
| | `AUDIT.tool_owner` | Audit tool binaries owned root:root, mode ≤0755 |
| | `AUDIT.disk_error` | `disk_error_action = syslog` |
| | `AUDIT.disk_full` | `disk_full_action = single` — **disruptive by design**, see notes below |
| | `AUDIT.space_left` | `space_left_action = email` (early warning) |
| | `AUDIT.admin_space_left` | `admin_space_left_action = single` — **disruptive by design**, see notes below |
| Audit rules | `AUDIT_RULES.scope` | Changes to `/etc/sudoers`, `/etc/sudoers.d` collected |
| | `AUDIT_RULES.user_emulation` | Privileged `execve` (acting as another user) collected |
| | `AUDIT_RULES.sudo_log_file` | Changes to `/var/log/sudo.log` collected |
| | `AUDIT_RULES.time-change` | `adjtimex`/`settimeofday`/`clock_settime`/`/etc/localtime` changes collected |
| | `AUDIT_RULES.system-locale` | `sethostname`/`setdomainname` and network config file changes collected |
| | `AUDIT_RULES.access` | Unsuccessful file access (`EACCES`/`EPERM`) collected |
| | `AUDIT_RULES.identity` | Changes to `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd`, `/etc/nsswitch.conf`, `/etc/pam.conf`, `/etc/pam.d` collected |
| | `AUDIT_RULES.perm_mod` | `chmod`/`chown`/`setxattr`-family syscalls collected |
| | `AUDIT_RULES.mounts` | Successful `mount` calls collected |
| | `AUDIT_RULES.session` | `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp` changes collected |
| | `AUDIT_RULES.logins` | `/var/log/lastlog`, `/var/run/faillock` changes collected |
| | `AUDIT_RULES.delete` | `unlink`/`unlinkat`/`rename`/`renameat` collected |
| | `AUDIT_RULES.MAC-policy` | Changes to `/etc/apparmor`, `/etc/apparmor.d` collected |
| | `AUDIT_RULES.perm_chng` | Use of `chcon`/`setfacl`/`chacl` collected |
| | `AUDIT_RULES.usermod` | Use of `usermod` collected |
| | `AUDIT_RULES.kernel_modules` | Kernel module load/unload/`kmod` collected |
| | `AUDIT_RULES.immutable` | `-e 2` set (audit config immutable until reboot) — **applied last**, see notes below |
| Logging | `LOG.rsyslog` | `rsyslog` installed and running |
| | `LOG.journald_persist` | `journald` persists logs to disk |
| | `LOG.journald_rotate` | `journald` rotation fully configured (`SystemMaxUse`, `SystemKeepFree`, `RuntimeMaxUse`, `RuntimeKeepFree`, `MaxFileSec`) |
| | `LOG.rsyslog_filemode` | rsyslog-created log files mode ≤0640 |
| | `LOG.varlog_perms` | No file under `/var/log` is group-writable or world-readable/writable/executable |
| AIDE | `AIDE.installed` | AIDE installed, database initialized |
| | `AIDE.cron` | Scheduled integrity check |
| | `AIDE.audit_tools` | AIDE also monitors the audit tool binaries themselves for tampering |

## Notes / manual follow-ups

- `usb-storage` module disabling is intentionally **skipped by default** —
  disabling it can break USB installers/keyboards on physical hardware.
  Review `section_filesystem_modules` in the script if you want it enforced.
- `AUDIT.backlog` / `AUDIT.early` / `MAC.bootloader` edit
  `/etc/default/grub` and run `update-grub`, but **do not reboot** — the
  kernel cmdline change only takes effect after a reboot you schedule
  yourself. Skipped (not failed) on systems that don't use GRUB (e.g.
  systemd-boot cloud images).
- **`AUDIT_RULES.immutable` (`-e 2`) makes the running audit configuration
  immutable until the next reboot** — no further audit rule changes (from
  this script or `auditctl` directly) can be applied without rebooting
  first. It's applied last, after every other `AUDIT_RULES.*` control, for
  exactly this reason. If you need to tweak audit rules again later in the
  same boot, you'll have to reboot before they'll take.
- **`AUDIT.disk_full` (`disk_full_action = single`) and
  `AUDIT.admin_space_left` (`admin_space_left_action = single`) are
  deliberately disruptive** — this specific CIS control only accepts
  `single` or `halt` (no lighter option), and `single` drops the system to
  single-user mode, which typically kills networking too. On a remote box
  without out-of-band console access, that's an effective lockout until
  someone can reach the console. This is a real, CIS-documented "fail
  closed on audit-log exhaustion" tradeoff, not a script bug — review
  before including these two in `--apply` on hosts you can't console into.
- `AUDIT.tool_owner`'s CIS SCA equivalent (6.2.4.8) has an oddly-worded
  "excluded modes" list that appears to flag even `0750`/`0755` (the
  standard, CIS-recommended mode) as non-compliant. That looks like a
  content bug in that specific scanner rule, not a real requirement — this
  script keeps the standard `root:root 0755` and doesn't chase it.
- `ACL.su_restricted` (restricting `su` via `pam_wheel`) only applies if the
  user running `sudo ./harden...sh` is already a member of the `sudo`
  group — otherwise it's skipped with a log message, so you can't
  accidentally lock yourself out of `su`.
- `SSH.access_control` (`AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`)
  is inherently specific to your user population — auto-picking e.g.
  `AllowGroups sudo` could silently lock out legitimate non-admin SSH
  users, so it's left as a manual decision (the control is reported
  informationally, not silently dropped).
- `PAM.faillock`/`PAM.faillock_root` only edit `faillock.conf`; wiring
  `pam_faillock` into `/etc/pam.d/common-auth` if it isn't already there is
  left as a manual step via `pam-auth-update`.
- `PAM.remember`/`PAM.remember_root`/`PAM.pwhistory_use_authtok`, by
  contrast, **do** insert a `pam_pwhistory.so` line into
  `/etc/pam.d/common-password` if one isn't already present (immediately
  before the `pam_unix.so` line, matching CIS's own remediation) — stock
  Debian/Ubuntu don't ship a `pam-auth-update` profile for it, so there's
  no more declarative way to enable it. If you later run `pam-auth-update`
  for an unrelated PAM profile change, double-check this line survived it.
- **Time sync commits fully to `chrony`**, masking `systemd-timesyncd` —
  CIS scores these as two separate, mutually-exclusive implementations
  (2.3.2.x timesyncd vs 2.3.3.x chrony); running whichever happened to
  already be active by default leaves the other implementation's checks
  permanently failing.
- Separate partitions/mount options (`/tmp`, `/var`, `/home` with
  `nodev,nosuid,noexec`) and a GRUB bootloader password are **not**
  automated here — both require install-time/physical-console changes and
  are too easy to get destructively wrong from a script.
- GDM/desktop-specific controls are out of scope (script targets servers);
  add a `desktop` section if you're hardening workstations with a GUI.
- A remote syslog destination (`rsyslog` "send logs to a remote log host")
  and `systemd-journal-upload` TLS certs are inherently org/infra-specific
  (need a real remote collector and real certificates) — not automated.
