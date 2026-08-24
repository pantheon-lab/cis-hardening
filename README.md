# CIS Level 1 Hardening — Ubuntu & Windows

Scripts to audit and apply **CIS Benchmark Level 1** hardening controls to:

- **Ubuntu 24.04 LTS** — `ubuntu/harden_ubuntu24_cis_l1.sh`
- **Windows 11 / Windows Server 2022** — `windows/Harden-Windows-CIS-L1.ps1`

Level 1 controls are aimed at reducing attack surface while keeping systems
usable, with minimal risk of breaking normal workloads. These scripts do not
reproduce the CIS Benchmark documents themselves (which are copyrighted) —
they implement the underlying technical controls in the maintainers' own
words, with a plain-language checklist per OS for traceability.

## ⚠️ Before you run anything

- **Read the script.** Hardening changes SSH, firewall, auditd, account
  lockout, and password policy — misconfiguration can lock you out of a box.
- **Snapshot / take a backup** of the machine (or a VM snapshot) first.
- **Run in audit mode first.** Both scripts default to **audit-only**
  (report what would change) and require an explicit flag to apply changes.
- **Test on a non-production system** before rolling out broadly.
- Designed for a single host at a time. For fleets, wrap these in your
  existing config management (Ansible/Puppet/etc.) rather than running ad hoc.
- **Running Docker or Kubernetes on this host?** The Ubuntu script
  auto-detects that and skips/adjusts the two controls that would otherwise
  break container networking (`ip_forward`, the host firewall section) —
  see [`ubuntu/README.md`](ubuntu/README.md#docker--kubernetes-hosts) for
  what's still worth reviewing by hand.

## Layout

```
cis-hardening/
├── README.md                  # this file
├── CHANGELOG.md
├── ubuntu/
│   ├── harden_ubuntu24_cis_l1.sh
│   └── README.md              # control-by-control checklist
└── windows/
    ├── Harden-Windows-CIS-L1.ps1
    └── README.md              # control-by-control checklist
```

## Quick start

### Ubuntu 24.04

```bash
cd ubuntu
sudo ./harden_ubuntu24_cis_l1.sh                 # audit only (default), no changes made
sudo ./harden_ubuntu24_cis_l1.sh --apply          # apply fixes
sudo ./harden_ubuntu24_cis_l1.sh --apply --only ssh,firewall   # apply a subset
```

Logs go to `/var/log/cis-hardening/`, and every file the script edits is
backed up to `/var/backups/cis-hardening/<timestamp>/` before modification.

### Windows 11 / Server 2022

Run PowerShell **as Administrator**:

```powershell
cd windows
.\Harden-Windows-CIS-L1.ps1                       # audit only (default), no changes made
.\Harden-Windows-CIS-L1.ps1 -Apply                # apply fixes
.\Harden-Windows-CIS-L1.ps1 -Apply -Only Firewall,AuditPolicy
```

If script execution is blocked, run once from an elevated prompt:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Transcript/log goes to `%ProgramData%\cis-hardening\`, and any registry keys
or policy exports touched are backed up to the same folder before changes.

## Status legend used in script output

| Status  | Meaning                                              |
|---------|-------------------------------------------------------|
| PASS    | Already compliant, no change needed                   |
| WOULD FIX | Non-compliant; would be changed in `--apply`/`-Apply` mode |
| FIXED   | Non-compliant; change was applied                      |
| SKIP    | Control not applicable to this system (e.g. service absent) |
| ERROR   | Control could not be evaluated/applied — check the log |

## Scope / disclaimer

- Targets **CIS Level 1 (Server/Workstation, as applicable)** controls for
  Ubuntu 24.04 LTS and Windows 11 / Server 2022, current as of 2026-08.
- This is not an official CIS product and is not affiliated with the Center
  for Internet Security. For a formal compliance attestation, use CIS-CAT Pro
  or an equivalent scanner against the official benchmark PDF.
- Provided as-is, no warranty. Review and test before production use.
