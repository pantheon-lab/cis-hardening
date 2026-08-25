# Changelog

## Unreleased

- Initial repo: Ubuntu 24.04 LTS CIS Level 1 hardening script + checklist.
- Initial repo: Windows 11 / Server 2022 CIS Level 1 hardening script + checklist.
- Fix: `control()` in the Ubuntu script invoked `check_fn`/`fix_fn` quoted
  (`"$check_fn"`), which tried to run multi-word strings like
  `"check_sysctl_eq kernel.randomize_va_space 2"` as one literal command
  name instead of `check_sysctl_eq` with two arguments — surfaced as
  `command not found` on every control passing arguments this way (SSH,
  PAM-adjacent, sysctl, file-permission, and service checks in particular).
  Confirmed on a real Ubuntu 24.04 run and fixed by leaving them unquoted
  so bash word-splits them as intended.
- Fix: `check_coredump_limits` passed an unexpanded `limits.d/*.conf` glob
  straight to `grep`, which reports an open error (and a false "N/A"/SKIP)
  when no such files exist yet; now iterates existing files explicitly.
- Fix: `PAM.remember`/`PAM.remember_root`/`PAM.pwhistory_use_authtok` gave up
  with an unhelpful empty "fix failed" whenever `pam_pwhistory.so` wasn't
  already present in `/etc/pam.d/common-password` — which is the case on
  essentially every stock Ubuntu 24.04 install, since Debian/Ubuntu don't
  ship a `pam-auth-update` profile for it. All three now share
  `ensure_pwhistory_line`, which inserts the standard
  `password requisite pam_pwhistory.so remember=5 use_authtok
  enforce_for_root` line immediately before the `pam_unix.so` password
  line (order matters: pwhistory must run first) — the same remediation
  CIS itself documents for this control. Verified against a real
  Ubuntu-style `common-password` with GNU sed.
- Fix (Windows): `Section-AccountPolicy`/`Section-LockoutPolicy` call
  `Get-SeceditSettings` before their first `Invoke-Control`, outside any
  try/catch. With `$ErrorActionPreference = 'Stop'`, a missing/blocked
  `secedit` (or `auditpol`, etc. in other sections) would abort the entire
  script instead of just that section. The main section-dispatch loop now
  wraps each `Section-*` call in try/catch, so one section's setup failure
  reports as an error and the rest of the run still completes. Also
  removed an unused padded placeholder in the `Say-*` output helpers that
  was producing extra whitespace in the console output.
- Major Ubuntu script expansion, driven by a real Wazuh SCA scan
  (`cis_ubuntu24-04` policy) run against a live host, covering ~99
  additional failing controls:
  - `FSX.*`: 12 more CIS 1.1.1.10 filesystem modules blacklisted, with
    `cifs`/`fuse`/`nfs_common`/`nfsd`/`ceph` reviewed manually (not
    auto-disabled) on Docker/Kubernetes hosts, since those back
    SMB/NFS/CephFS PVs and FUSE-based CSI drivers/rootless containers.
  - `MAC.bootloader` now checks the GRUB cmdline literally instead of
    accepting a currently-active `aa-status` as a shortcut; `MAC.enabled`
    now verifies all 5 CIS sub-conditions (loaded/enforce counts,
    unconfined/complain/kill-mode counts), not just "some profiles enforce".
  - `SYSCTL.net.ipv6.conf.all.forwarding` added (container-aware: left
    alone, not forced either way, on Docker/Kubernetes hosts).
  - `SVC.*` now purges the underlying package (not just disables the
    service), matching CIS's own remediation; added `inetutils-telnet`/
    `tnftp` as alternate telnet/ftp client packages.
  - Time sync now commits fully to `chrony` (masks `systemd-timesyncd`) —
    CIS scores these as mutually-exclusive alternatives, and running
    whichever was already active left the other's checks failing forever.
  - `CRON.allow`/`AT.allow` added — an allow-list, which is the actual
    control, not just removing `cron.deny`/`at.deny`.
  - Fixed `PAM.remember` to require `remember>=24` (the real CIS Ubuntu
    24.04 L1 value) — it was previously set/checked against `>=5`.
  - `PAM.difok`/`PAM.maxrepeat`/`PAM.maxsequence` added; `PAM.complexity`
    switched from the dcredit/ucredit/lcredit/ocredit approach to
    `minclass=4`, which is what CIS's automated check actually inspects.
  - `ACC.existing_users_aging` added — `login.defs` only affects
    newly-created accounts; existing human accounts (UID 1000-65533 with a
    real password) now get the same limits applied via `chage`.
  - `ACC.root_umask` added (`/root/.bash_profile` + `/root/.bashrc`,
    distinct from the login.defs-wide `ACC.umask`).
  - `SSH.access_control` added as an explicit informational/manual note
    (was previously just absent from the script).
  - New `audit_rules` section: the full standard CIS 6.2.3.1-6.2.3.20 audit
    rule set (sudoers scope, user emulation, time/locale changes, file
    access, identity files, permission changes, mounts, sessions, logins,
    deletions, MAC policy, chcon/setfacl/chacl/usermod, kernel modules,
    and finally `-e 2` immutability, applied last since it locks out
    further audit rule changes until reboot).
  - `AUDIT.disk_error`/`.disk_full`/`.space_left`/`.admin_space_left`
    added, with the `disk_full`/`admin_space_left` options' operational
    risk (they only accept `single`/`halt`, both disruptive) called out
    explicitly rather than silently applied.
  - `AIDE.audit_tools` added — AIDE now also monitors the audit tool
    binaries for tampering (CIS 6.3.3).
  - `LOG.journald_rotate` expanded to all 5 required settings (was just
    `SystemMaxUse`); `LOG.varlog_perms` added (strips group-write/any
    "other" bits from files under `/var/log`).
  - `SUDO.logfile`'s path is now unquoted in sudoers, avoiding any
    ambiguity with the scanner's literal-path regex.
- Follow-up round, driven by a re-scan showing the remaining 56 failures
  (down from 99 — everything else was already the documented tradeoffs:
  partitions, bootloader password, firewall-on-Kubernetes, `1.1.1.10`'s
  five storage-backing modules, and `2.3.2.2` vs the chrony/timesyncd
  choice, both now called out explicitly in the README):
  - Fixed a real bug: `SSH.ciphers` configured `umac-128-etm@openssh.com`
    as a "strong" MAC, but CIS's own excluded-MACs list flags it as weak.
    Removed it; only the `hmac-sha2-*-etm` MACs remain.
  - Hardened all SSH directive fixes (`set_sshd_kv`) to also strip
    conflicting occurrences from `/etc/ssh/sshd_config.d/*.conf` first —
    Ubuntu's stock `sshd_config` includes that directory near the top of
    the file, so a drop-in's value otherwise silently wins over anything
    appended to the bottom of the main file (sshd uses the first
    occurrence it encounters). Verified against a simulated
    cloud-init-style drop-in conflict.
  - `PAM.unix_wiring`/`PAM.faillock_wiring` added as verify-only checks
    (CIS 5.3.2.1/5.3.2.2) — surfaced now instead of being silently
    untracked, but still not auto-rewritten given the lockout risk.
  - `PERM.opasswd_old` added — CIS also checks `/etc/security/opasswd.old`,
    which doesn't exist until the first password change; pre-created with
    the right permissions instead of waiting on that to happen naturally.
- Two more real bugs found from a follow-up scan + the user checking the
  actual files by hand:
  - `SUDO.logfile` only checked that *some* `Defaults logfile=` directive
    existed, so a stale quoted value from before the "remove quotes" fix
    (`Defaults logfile="/var/log/sudo.log"`) was accepted forever and never
    got normalized. Tightened to require the exact unquoted form, and
    `fix_sudo_logfile` now removes any existing `logfile=` line (main
    `/etc/sudoers` too, validated with `visudo -cf` after) before writing
    the correct one, instead of just appending and hoping.
  - `LOG.rsyslog_filemode` (CIS 6.1.3.4) only ever wrote `$FileCreateMode`
    to `/etc/rsyslog.conf`, but the scanner's `condition: all` requires
    *both* that AND a matching file under `/etc/rsyslog.d/*.conf` — same
    shape as the journald.conf.d requirement already handled. Now also
    drops `/etc/rsyslog.d/60-cis-hardening.conf`.
- Two more real bugs, root-caused from the user pasting actual file
  contents rather than more scan output — both were bugs in the *check*
  functions, which is why the corresponding fix never ran even after
  several `--apply` passes:
  - `check_ssh_maxstartups` only validated the first number of the
    `start:rate:full` triple. OpenSSH's own compiled-in default
    (`10:30:100`, matching Ubuntu's commented-out example line) has
    `start=10`, which alone satisfies `<=10` — so an entirely
    unconfigured `MaxStartups` looked compliant, while the real
    requirement (`full<=60`) didn't hold. Now validates all three fields.
  - `check_root_umask` ran `grep` directly against `/root/.bash_profile`
    without checking it exists first. GNU grep exits `2` (not `1`) when
    the target file is missing, and `control()` treats exit `2` as
    "not applicable" rather than "needs fixing" — so on a stock Ubuntu
    box (which doesn't ship `.bash_profile` by default), this control
    silently skipped itself instead of creating the file. Same class of
    bug already fixed twice elsewhere in this script, missed here.
