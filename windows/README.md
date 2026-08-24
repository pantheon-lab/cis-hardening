# Windows 11 / Server 2022 — CIS Level 1 checklist

Run `Harden-Windows-CIS-L1.ps1` as Administrator (see repo root README for
usage). Each row below is one control implemented by the script;
`-ListSections` prints the section names, `-Only` runs a subset. This is a
plain-language mapping, not the CIS benchmark text itself — check the
official CIS Microsoft Windows 11 / Windows Server 2022 Benchmark if you
need exact wording/rationale for an audit.

| Section | Control ID | What it checks |
|---|---|---|
| Account policy | `ACC.minlen` | Minimum password length ≥ 14 |
| | `ACC.history` | Password history ≥ 24 remembered |
| | `ACC.maxage` | Maximum password age 1–365 days |
| | `ACC.minage` | Minimum password age ≥ 1 day |
| | `ACC.complexity` | Password complexity required |
| | `ACC.reversible` | Reversible encryption disabled |
| Lockout policy | `LOCK.threshold` | Lockout after 1–5 bad attempts |
| | `LOCK.duration` | Lockout duration ≥ 15 minutes |
| | `LOCK.reset` | Bad-attempt counter reset ≥ 15 minutes |
| Security options | `SEC.guest` | Guest account disabled |
| | `SEC.anon_sam` / `.anon_sam_shares` | Anonymous SAM/share enumeration restricted |
| | `SEC.nolmhash` | LM hash storage disabled |
| | `SEC.ntlmv2` | NTLMv2-only auth (`LmCompatibilityLevel = 5`) |
| | `SEC.uac` / `.uac_consent` | UAC admin approval mode + secure-desktop consent prompt |
| | `SEC.smb1` | SMBv1 disabled |
| | `SEC.smb_signing` | SMB server signing required |
| | `SEC.autorun` | Autorun/Autoplay disabled |
| | `SEC.ctrlaltdel` | Ctrl+Alt+Del required before logon |
| | `SEC.lastuser` | Last logged-on username hidden |
| Audit policy | `AUD.*` | Advanced audit subcategories: Logon, Logoff, Account Lockout, Special Logon, User/Security-Group Account Management, Audit Policy Change, Authentication Policy Change, Sensitive Privilege Use, Process Creation, Removable Storage |
| Firewall | `FW.<profile>.enabled` / `.blockin` / `.logging` | Domain/Public/Private profiles enabled, default-deny inbound, dropped-packet logging |
| Defender | `DEF.realtime` | Real-time protection enabled |
| | `DEF.cloud` | Cloud-delivered (MAPS) protection enabled |
| | `DEF.pua` | Potentially Unwanted Application blocking enabled |
| | `DEF.samplesubmit` | Automatic sample submission enabled |
| | `DEF.tamperprotect` | Tamper Protection status (audit-only — cannot be set from a local script) |
| Network protocols | `NET.llmnr` | LLMNR disabled |
| | `NET.wdigest` | WDigest plaintext credential caching disabled |
| | `NET.ldap_signing` | LDAP client signing required |
| Remote Desktop | `RDP.nla` | Network Level Authentication required (only checked if RDP is enabled) |
| | `RDP.encryption` | RDP encryption level = High |
| PowerShell logging | `PS.scriptblock` | Script Block Logging enabled |
| | `PS.transcription` | Transcription enabled, output directory set |
| | `PS.v2disabled` | PowerShell v2 engine feature removed |
| Event log size | `LOG.Application/System.size` | ≥ 32 MB max size |
| | `LOG.Security.size` | ≥ 192 MB max size |
| Windows Update | `WU.autoupdate` | Automatic Updates not disabled by policy |
| | `WU.service` | `wuauserv` not set to Disabled |
| Services | `SVC.*` | Telnet Server, Remote Registry, Simple TCP/IP Services, SNMP, IIS (W3SVC), FTP, Computer Browser, Fax disabled **if present** |

## Notes / manual follow-ups

- **Tamper Protection** cannot be toggled from a local script by design —
  manage it via the Windows Security app or Intune/MDM/Group Policy.
- The `Services` section is intentionally conservative — it only disables
  services that are rarely needed and commonly flagged (Telnet, Remote
  Registry, SNMP, legacy IIS/FTP, Computer Browser, Fax). Review before
  running `-Apply` on a box that actually needs one of these.
- Account/lockout policy is applied via `secedit` export → edit → import.
  On a **domain-joined** machine these settings are normally enforced by
  Group Policy and will be overwritten on the next `gpupdate` — apply the
  equivalent GPO instead of relying on this script for domain members.
- RDP controls (`RDP.*`) are skipped (not failed) when RDP itself is
  disabled — the script won't turn RDP on for you.
- BitLocker, Credential Guard, Exploit Protection/ASR rules, and Secure Boot
  are not covered here — they usually need hardware/firmware checks and are
  better managed via Intune/MDM baselines than a standalone script.
