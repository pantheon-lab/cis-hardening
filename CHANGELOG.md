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
