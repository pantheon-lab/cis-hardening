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
