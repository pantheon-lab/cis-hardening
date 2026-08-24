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
