#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 1 style hardening for Windows 11 / Windows Server 2022.

.DESCRIPTION
    Defaults to AUDIT ONLY (reports what would change, makes no changes).
    Pass -Apply to actually apply fixes. See README.md in this folder for the
    control-by-control checklist.

.PARAMETER Apply
    Apply fixes for anything found non-compliant. Without this switch the
    script only reports status.

.PARAMETER Only
    Comma-separated list of section names to run. Use -ListSections to see
    the available names.

.PARAMETER ListSections
    List available section names and exit.

.EXAMPLE
    .\Harden-Windows-CIS-L1.ps1
    Audit only, no changes.

.EXAMPLE
    .\Harden-Windows-CIS-L1.ps1 -Apply

.EXAMPLE
    .\Harden-Windows-CIS-L1.ps1 -Apply -Only Firewall,AuditPolicy
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string[]]$Only,
    [switch]$ListSections
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
$Script:Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$Script:BaseDir     = Join-Path $env:ProgramData 'cis-hardening'
$Script:LogFile     = Join-Path $Script:BaseDir "windows-cis-l1-$($Script:Timestamp).log"
$Script:BackupDir   = Join-Path $Script:BaseDir "backup-$($Script:Timestamp)"

$Script:PassCount      = 0
$Script:FixCount       = 0
$Script:WouldFixCount  = 0
$Script:SkipCount      = 0
$Script:ErrorCount     = 0

$Script:AllSections = @(
    'AccountPolicy',
    'LockoutPolicy',
    'SecurityOptions',
    'AuditPolicy',
    'Firewall',
    'Defender',
    'NetworkProtocols',
    'RemoteDesktop',
    'PowerShellLogging',
    'EventLogSize',
    'WindowsUpdate',
    'Services'
)

New-Item -ItemType Directory -Force -Path $Script:BaseDir | Out-Null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-CisLog {
    param([string]$Level, [string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $Script:LogFile -Value $line
}

function Say-Pass      { param($Id,$Desc) $Script:PassCount++;     Write-Host ("  {0,-10} {1,-20} {2}" -f 'PASS','',"$Id  $Desc") -ForegroundColor Green;  Write-CisLog 'PASS' "$Id`: $Desc" }
function Say-Fixed     { param($Id,$Desc) $Script:FixCount++;      Write-Host ("  {0,-10} {1,-20} {2}" -f 'FIXED','',"$Id  $Desc") -ForegroundColor Cyan;  Write-CisLog 'FIXED' "$Id`: $Desc" }
function Say-WouldFix  { param($Id,$Desc) $Script:WouldFixCount++; Write-Host ("  {0,-10} {1,-20} {2}" -f 'WOULD FIX','',"$Id  $Desc") -ForegroundColor Yellow; Write-CisLog 'WOULD_FIX' "$Id`: $Desc" }
function Say-Skip      { param($Id,$Desc) $Script:SkipCount++;     Write-Host ("  {0,-10} {1,-20} {2}" -f 'SKIP','',"$Id  $Desc") -ForegroundColor DarkGray; Write-CisLog 'SKIP' "$Id`: $Desc" }
function Say-Error     { param($Id,$Desc) $Script:ErrorCount++;    Write-Host ("  {0,-10} {1,-20} {2}" -f 'ERROR','',"$Id  $Desc") -ForegroundColor Red;   Write-CisLog 'ERROR' "$Id`: $Desc" }

# Invoke-Control -Id <id> -Description <desc> -Check {..} -Fix {..}
# Check scriptblock returns one of: 'Pass', 'Fail', 'Skip'
function Invoke-Control {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Check,
        [Parameter(Mandatory)][scriptblock]$Fix
    )
    try {
        $result = & $Check
    } catch {
        Say-Error $Id "$Description — check failed: $($_.Exception.Message)"
        return
    }

    switch ($result) {
        'Pass' { Say-Pass $Id $Description }
        'Skip' { Say-Skip $Id $Description }
        'Fail' {
            if ($Script:Apply) {
                try {
                    & $Fix | Out-Null
                    Say-Fixed $Id $Description
                } catch {
                    Say-Error $Id "$Description — fix failed: $($_.Exception.Message)"
                }
            } else {
                Say-WouldFix $Id $Description
            }
        }
        default { Say-Error $Id "$Description — check returned unexpected value '$result'" }
    }
}

function Backup-RegistryKey {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    $safe = ($Path -replace '[:\\]', '_')
    $dest = Join-Path $Script:BackupDir "$safe.reg"
    New-Item -ItemType Directory -Force -Path $Script:BackupDir | Out-Null
    $regPath = $Path -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
    try { reg export $regPath $dest /y > $null 2>&1 } catch { }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Type = 'DWord'
    )
    Backup-RegistryKey -Path $Path
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name, $Default = $null)
    if (-not (Test-Path $Path)) { return $Default }
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $Default }
    return $item.$Name
}

function Test-ServiceExists { param([string]$Name) [bool](Get-Service -Name $Name -ErrorAction SilentlyContinue) }

# ---------------------------------------------------------------------------
# 1. Account policy (password policy) — via secedit export/modify/import
# ---------------------------------------------------------------------------
function Get-SeceditSettings {
    $cfgPath = Join-Path $env:TEMP "cis-secedit-$($Script:Timestamp).cfg"
    secedit /export /cfg $cfgPath /quiet | Out-Null
    $content = Get-Content $cfgPath
    Remove-Item $cfgPath -ErrorAction SilentlyContinue
    $settings = @{}
    foreach ($line in $content) {
        if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.+?)\s*$') {
            $settings[$Matches[1]] = $Matches[2]
        }
    }
    return $settings
}

function Set-SeceditValue {
    param([hashtable]$Values)
    $cfgPath = Join-Path $env:TEMP "cis-secedit-apply-$($Script:Timestamp).cfg"
    $dbPath  = Join-Path $env:TEMP "cis-secedit-apply-$($Script:Timestamp).sdb"
    secedit /export /cfg $cfgPath /quiet | Out-Null
    Backup-RegistryKey -Path 'HKLM:\SECURITY\Policy'  # best-effort; secedit itself is the real backup below
    Copy-Item $cfgPath (Join-Path $Script:BackupDir "secedit-before-$($Script:Timestamp).cfg") -Force -ErrorAction SilentlyContinue
    $content = Get-Content $cfgPath
    $newContent = foreach ($line in $content) {
        $matched = $false
        foreach ($key in $Values.Keys) {
            if ($line -match "^\s*$key\s*=") {
                "$key = $($Values[$key])"
                $matched = $true
                break
            }
        }
        if (-not $matched) { $line }
    }
    Set-Content -Path $cfgPath -Value $newContent
    secedit /configure /db $dbPath /cfg $cfgPath /quiet | Out-Null
    Remove-Item $cfgPath, $dbPath -ErrorAction SilentlyContinue
}

function Section-AccountPolicy {
    Write-Host "== 1. Account / password policy =="
    $settings = Get-SeceditSettings

    Invoke-Control -Id 'ACC.minlen' -Description 'Minimum password length >= 14' `
        -Check { if ([int]($settings['MinimumPasswordLength']) -ge 14) { 'Pass' } else { 'Fail' } } `
        -Fix { Set-SeceditValue @{ MinimumPasswordLength = 14 } }

    Invoke-Control -Id 'ACC.history' -Description 'Password history remembered >= 24' `
        -Check { if ([int]($settings['PasswordHistorySize']) -ge 24) { 'Pass' } else { 'Fail' } } `
        -Fix { Set-SeceditValue @{ PasswordHistorySize = 24 } }

    Invoke-Control -Id 'ACC.maxage' -Description 'Maximum password age between 1 and 365 days' `
        -Check {
            $v = [int]($settings['MaximumPasswordAge'])
            if ($v -ge 1 -and $v -le 365) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-SeceditValue @{ MaximumPasswordAge = 365 } }

    Invoke-Control -Id 'ACC.minage' -Description 'Minimum password age >= 1 day' `
        -Check { if ([int]($settings['MinimumPasswordAge']) -ge 1) { 'Pass' } else { 'Fail' } } `
        -Fix { Set-SeceditValue @{ MinimumPasswordAge = 1 } }

    Invoke-Control -Id 'ACC.complexity' -Description 'Password complexity requirements enabled' `
        -Check { if ($settings['PasswordComplexity'] -eq '1') { 'Pass' } else { 'Fail' } } `
        -Fix { Set-SeceditValue @{ PasswordComplexity = 1 } }

    Invoke-Control -Id 'ACC.reversible' -Description 'Reversible password encryption disabled' `
        -Check { if ($settings['ClearTextPassword'] -eq '0') { 'Pass' } else { 'Fail' } } `
        -Fix { Set-SeceditValue @{ ClearTextPassword = 0 } }
}

# ---------------------------------------------------------------------------
# 2. Account lockout policy
# ---------------------------------------------------------------------------
function Section-LockoutPolicy {
    Write-Host "== 2. Account lockout policy =="
    $settings = Get-SeceditSettings

    Invoke-Control -Id 'LOCK.threshold' -Description 'Lockout threshold between 1 and 5 attempts' `
        -Check {
            $v = [int]($settings['LockoutBadCount'])
            if ($v -ge 1 -and $v -le 5) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-SeceditValue @{ LockoutBadCount = 5 } }

    Invoke-Control -Id 'LOCK.duration' -Description 'Lockout duration >= 15 minutes' `
        -Check {
            $v = [int]($settings['LockoutDuration'])
            if ($v -ge 15) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-SeceditValue @{ LockoutDuration = 15 } }

    Invoke-Control -Id 'LOCK.reset' -Description 'Lockout counter reset window >= 15 minutes' `
        -Check {
            $v = [int]($settings['ResetLockoutCount'])
            if ($v -ge 15) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-SeceditValue @{ ResetLockoutCount = 15 } }
}

# ---------------------------------------------------------------------------
# 3. Security options (registry-backed local policies)
# ---------------------------------------------------------------------------
function Section-SecurityOptions {
    Write-Host "== 3. Security options =="

    Invoke-Control -Id 'SEC.guest' -Description 'Guest account disabled' `
        -Check {
            $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            if ($null -eq $guest -or -not $guest.Enabled) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue }

    Invoke-Control -Id 'SEC.anon_sam' -Description 'Anonymous enumeration of SAM accounts disabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Default 0
            if ($v -ge 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 }

    Invoke-Control -Id 'SEC.anon_sam_shares' -Description 'Anonymous enumeration of SAM accounts and shares disabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 }

    Invoke-Control -Id 'SEC.nolmhash' -Description 'Storage of LAN Manager password hashes disabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 }

    Invoke-Control -Id 'SEC.ntlmv2' -Description 'LAN Manager auth level restricted to NTLMv2 only (level 5)' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Default 0
            if ($v -ge 5) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 }

    Invoke-Control -Id 'SEC.uac' -Description 'UAC: admin approval mode enabled for built-in Administrator' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 }

    Invoke-Control -Id 'SEC.uac_consent' -Description 'UAC: prompt for consent on the secure desktop for standard elevation' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Default -1
            if ($v -eq 2) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 }

    Invoke-Control -Id 'SEC.smb1' -Description 'SMBv1 client/server disabled' `
        -Check {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($null -eq $feature -or $feature.State -eq 'Disabled') { 'Pass' } else { 'Fail' }
        } `
        -Fix { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null }

    Invoke-Control -Id 'SEC.smb_signing' -Description 'SMB server digital signing (always) enabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 }

    Invoke-Control -Id 'SEC.autorun' -Description 'Autoplay/Autorun disabled for all drives' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Default 0
            if ($v -eq 255) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 }

    Invoke-Control -Id 'SEC.ctrlaltdel' -Description 'CTRL+ALT+DEL required before logon (DisableCAD = 0)' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Default 0
            if ($v -eq 0) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Value 0 }

    Invoke-Control -Id 'SEC.lastuser' -Description 'Last signed-in user name not displayed on logon screen' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 }
}

# ---------------------------------------------------------------------------
# 4. Audit policy (advanced auditpol subcategories)
# ---------------------------------------------------------------------------
function Get-AuditSubcategoryState {
    param([string]$Subcategory)
    $raw = auditpol /get /subcategory:"$Subcategory" /r 2>$null
    if (-not $raw) { return $null }
    $csv = $raw | ConvertFrom-Csv
    if (-not $csv) { return $null }
    return $csv[0].'Inclusion Setting'
}

function Set-AuditSubcategory {
    param([string]$Subcategory, [string]$Setting)  # Setting: "Success and Failure" | "Success" | "Failure"
    switch ($Setting) {
        'Success and Failure' { auditpol /set /subcategory:"$Subcategory" /success:enable /failure:enable | Out-Null }
        'Success'              { auditpol /set /subcategory:"$Subcategory" /success:enable /failure:disable | Out-Null }
        'Failure'               { auditpol /set /subcategory:"$Subcategory" /success:disable /failure:enable | Out-Null }
    }
}

function Section-AuditPolicy {
    Write-Host "== 4. Advanced audit policy =="
    # Save current audit policy once, for reference/rollback.
    $backupCsv = Join-Path $Script:BackupDir "auditpol-before-$($Script:Timestamp).csv"
    New-Item -ItemType Directory -Force -Path $Script:BackupDir | Out-Null
    auditpol /backup /file:$backupCsv 2>$null | Out-Null

    $subcats = @(
        @{ Id='AUD.logon';          Name='Logon';                             Want='Success and Failure' }
        @{ Id='AUD.logoff';         Name='Logoff';                            Want='Success' }
        @{ Id='AUD.acct_lockout';   Name='Account Lockout';                   Want='Success and Failure' }
        @{ Id='AUD.special_logon';  Name='Special Logon';                     Want='Success' }
        @{ Id='AUD.user_acct_mgmt'; Name='User Account Management';           Want='Success and Failure' }
        @{ Id='AUD.security_group'; Name='Security Group Management';         Want='Success' }
        @{ Id='AUD.audit_policy';   Name='Audit Policy Change';               Want='Success and Failure' }
        @{ Id='AUD.auth_policy';    Name='Authentication Policy Change';      Want='Success' }
        @{ Id='AUD.sensitive_use';  Name='Sensitive Privilege Use';           Want='Success and Failure' }
        @{ Id='AUD.process_creation';Name='Process Creation';                 Want='Success' }
        @{ Id='AUD.removable';      Name='Removable Storage';                 Want='Success and Failure' }
    )

    foreach ($s in $subcats) {
        Invoke-Control -Id $s.Id -Description "Audit subcategory '$($s.Name)' = $($s.Want)" `
            -Check {
                $cur = Get-AuditSubcategoryState -Subcategory $s.Name
                if ($null -eq $cur) { 'Skip' } elseif ($cur -eq $s.Want -or ($s.Want -ne 'Success and Failure' -and $cur -match $s.Want)) { 'Pass' } else { 'Fail' }
            } `
            -Fix { Set-AuditSubcategory -Subcategory $s.Name -Setting $s.Want }
    }
}

# ---------------------------------------------------------------------------
# 5. Windows Firewall
# ---------------------------------------------------------------------------
function Section-Firewall {
    Write-Host "== 5. Windows Firewall =="
    foreach ($profile in @('Domain','Public','Private')) {
        Invoke-Control -Id "FW.$profile.enabled" -Description "$profile firewall profile enabled" `
            -Check {
                $p = Get-NetFirewallProfile -Profile $profile
                if ($p.Enabled) { 'Pass' } else { 'Fail' }
            } `
            -Fix { Set-NetFirewallProfile -Profile $profile -Enabled True }

        Invoke-Control -Id "FW.$profile.blockin" -Description "$profile firewall default inbound action is Block" `
            -Check {
                $p = Get-NetFirewallProfile -Profile $profile
                if ($p.DefaultInboundAction -eq 'Block') { 'Pass' } else { 'Fail' }
            } `
            -Fix { Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block }

        Invoke-Control -Id "FW.$profile.logging" -Description "$profile firewall logs dropped packets" `
            -Check {
                $p = Get-NetFirewallProfile -Profile $profile
                if ($p.LogBlocked -eq 'True') { 'Pass' } else { 'Fail' }
            } `
            -Fix { Set-NetFirewallProfile -Profile $profile -LogBlocked True }
    }
}

# ---------------------------------------------------------------------------
# 6. Windows Defender
# ---------------------------------------------------------------------------
function Section-Defender {
    Write-Host "== 6. Windows Defender =="
    Invoke-Control -Id 'DEF.realtime' -Description 'Real-time protection enabled' `
        -Check {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            if ($null -eq $mp) { 'Skip' } elseif (-not $mp.DisableRealtimeMonitoring) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-MpPreference -DisableRealtimeMonitoring $false }

    Invoke-Control -Id 'DEF.cloud' -Description 'Cloud-delivered (MAPS) protection enabled' `
        -Check {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            if ($null -eq $mp) { 'Skip' } elseif ($mp.MAPSReporting -ne 0) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-MpPreference -MAPSReporting 2 }

    Invoke-Control -Id 'DEF.pua' -Description 'Potentially Unwanted Application (PUA) protection enabled' `
        -Check {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            if ($null -eq $mp) { 'Skip' } elseif ($mp.PUAProtection -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-MpPreference -PUAProtection 1 }

    Invoke-Control -Id 'DEF.samplesubmit' -Description 'Automatic sample submission enabled' `
        -Check {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            if ($null -eq $mp) { 'Skip' } elseif ($mp.SubmitSamplesConsent -ne 2) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-MpPreference -SubmitSamplesConsent 1 }

    Invoke-Control -Id 'DEF.tamperprotect' -Description 'Tamper protection enabled' `
        -Check {
            $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($null -eq $status) { 'Skip' } elseif ($status.IsTamperProtected) { 'Pass' } else { 'Fail' }
        } `
        -Fix {
            # Tamper Protection cannot be reliably toggled via PowerShell/registry by design.
            Write-CisLog 'INFO' 'Tamper Protection must be enabled via Windows Security app or Intune/MDM policy — not settable from a local script.'
        }
}

# ---------------------------------------------------------------------------
# 7. Network protocol hardening (LLMNR, NetBIOS, WDigest)
# ---------------------------------------------------------------------------
function Section-NetworkProtocols {
    Write-Host "== 7. Network protocol hardening =="

    Invoke-Control -Id 'NET.llmnr' -Description 'LLMNR (link-local multicast name resolution) disabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default 1
            if ($v -eq 0) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 }

    Invoke-Control -Id 'NET.wdigest' -Description 'WDigest credential caching disabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default 1
            if ($v -eq 0) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 }

    Invoke-Control -Id 'NET.ldap_signing' -Description 'LDAP client signing required' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Default 0
            if ($v -ge 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Value 1 }
}

# ---------------------------------------------------------------------------
# 8. Remote Desktop
# ---------------------------------------------------------------------------
function Section-RemoteDesktop {
    Write-Host "== 8. Remote Desktop =="

    Invoke-Control -Id 'RDP.nla' -Description 'RDP requires Network Level Authentication (if RDP is enabled)' `
        -Check {
            $rdpEnabled = (Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1) -eq 0
            if (-not $rdpEnabled) { return 'Skip' }
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 }

    Invoke-Control -Id 'RDP.encryption' -Description 'RDP encryption level set to High (if RDP is enabled)' `
        -Check {
            $rdpEnabled = (Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1) -eq 0
            if (-not $rdpEnabled) { return 'Skip' }
            $v = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Default 0
            if ($v -ge 3) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3 }
}

# ---------------------------------------------------------------------------
# 9. PowerShell logging
# ---------------------------------------------------------------------------
function Section-PowerShellLogging {
    Write-Host "== 9. PowerShell logging =="

    Invoke-Control -Id 'PS.scriptblock' -Description 'PowerShell Script Block Logging enabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 }

    Invoke-Control -Id 'PS.transcription' -Description 'PowerShell Transcription enabled' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Default 0
            if ($v -eq 1) { 'Pass' } else { 'Fail' }
        } `
        -Fix {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            Set-RegistryValue -Path $path -Name 'EnableTranscripting' -Value 1
            Set-RegistryValue -Path $path -Name 'OutputDirectory' -Value (Join-Path $Script:BaseDir 'ps-transcripts') -Type String
        }

    Invoke-Control -Id 'PS.v2disabled' -Description 'Windows PowerShell 2.0 engine feature disabled' `
        -Check {
            $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
            if ($null -eq $f -or $f.State -eq 'Disabled') { 'Pass' } else { 'Fail' }
        } `
        -Fix { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null }
}

# ---------------------------------------------------------------------------
# 10. Event log sizes
# ---------------------------------------------------------------------------
function Section-EventLogSize {
    Write-Host "== 10. Event log retention =="
    $logs = @(
        @{ Name='Application'; MinKB = 32768 }
        @{ Name='Security';    MinKB = 196608 }
        @{ Name='System';      MinKB = 32768 }
    )
    foreach ($l in $logs) {
        Invoke-Control -Id "LOG.$($l.Name).size" -Description "$($l.Name) event log max size >= $($l.MinKB / 1024) MB" `
            -Check {
                $cfg = Get-WinEvent -ListLog $l.Name -ErrorAction SilentlyContinue
                if ($null -eq $cfg) { return 'Skip' }
                if (($cfg.MaximumSizeInBytes / 1KB) -ge $l.MinKB) { 'Pass' } else { 'Fail' }
            } `
            -Fix {
                $cfg = Get-WinEvent -ListLog $l.Name
                $cfg.MaximumSizeInBytes = $l.MinKB * 1KB
                $cfg.SaveChanges()
            }
    }
}

# ---------------------------------------------------------------------------
# 11. Windows Update
# ---------------------------------------------------------------------------
function Section-WindowsUpdate {
    Write-Host "== 11. Windows Update =="

    Invoke-Control -Id 'WU.autoupdate' -Description 'Automatic Updates configured to download and notify/install' `
        -Check {
            $v = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Default 0
            if ($v -eq 0) { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0 }

    Invoke-Control -Id 'WU.service' -Description 'Windows Update service (wuauserv) not disabled' `
        -Check {
            $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
            if ($null -eq $svc) { return 'Skip' }
            if ($svc.StartType -ne 'Disabled') { 'Pass' } else { 'Fail' }
        } `
        -Fix { Set-Service -Name wuauserv -StartupType Manual }
}

# ---------------------------------------------------------------------------
# 12. Unnecessary services
# ---------------------------------------------------------------------------
function Section-Services {
    Write-Host "== 12. Unnecessary services =="
    # Conservative list: legacy/high-risk services rarely needed on a hardened
    # endpoint or server. Review before applying on systems that need any of
    # these (e.g. print servers, Telnet gateways).
    $svcs = @(
        @{ Name='TlntSvr';   Desc='Telnet Server' }
        @{ Name='RemoteRegistry'; Desc='Remote Registry' }
        @{ Name='simptcp';   Desc='Simple TCP/IP Services' }
        @{ Name='SNMP';      Desc='SNMP Service' }
        @{ Name='W3SVC';     Desc='IIS World Wide Web Publishing Service' }
        @{ Name='FTPSVC';    Desc='FTP Server' }
        @{ Name='Browser';   Desc='Computer Browser' }
        @{ Name='Fax';       Desc='Fax Service' }
    )
    foreach ($s in $svcs) {
        Invoke-Control -Id "SVC.$($s.Name)" -Description "$($s.Desc) ($($s.Name)) disabled if present" `
            -Check {
                if (-not (Test-ServiceExists $s.Name)) { return 'Skip' }
                $svc = Get-Service -Name $s.Name
                if ($svc.StartType -eq 'Disabled') { 'Pass' } else { 'Fail' }
            } `
            -Fix {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s.Name -StartupType Disabled
            }
    }
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
function Show-Usage {
    @"
Usage: .\Harden-Windows-CIS-L1.ps1 [-Apply] [-Only Section1,Section2,...] [-ListSections]

  (no flags)      Audit only - report PASS/WOULD FIX/SKIP, no changes made.
  -Apply          Apply fixes for anything not already compliant.
  -Only LIST      Subset of sections to run (comma-separated). See -ListSections.
  -ListSections   List available section names and exit.
"@ | Write-Host
}

if ($ListSections) {
    $Script:AllSections | ForEach-Object { Write-Host $_ }
    return
}

Write-Host "CIS Level 1 hardening - Windows 11 / Server 2022"
if ($Apply) {
    Write-Host "Mode: APPLY (changes will be made). Backups: $Script:BackupDir"
} else {
    Write-Host "Mode: AUDIT ONLY (no changes will be made). Pass -Apply to fix."
}
Write-Host "Log: $Script:LogFile"
Write-Host ""

$sectionsToRun = if ($Only) { $Only } else { $Script:AllSections }

foreach ($sec in $sectionsToRun) {
    $fnName = "Section-$sec"
    if (Get-Command $fnName -ErrorAction SilentlyContinue) {
        & $fnName
        Write-Host ""
    } else {
        Write-Warning "Unknown section: $sec (see -ListSections)"
    }
}

Write-Host "-------------------------------------------------------------"
Write-Host "PASS: $Script:PassCount   FIXED: $Script:FixCount   WOULD FIX: $Script:WouldFixCount   SKIP: $Script:SkipCount   ERROR: $Script:ErrorCount"
Write-Host "Full log: $Script:LogFile"
if ($Apply) { Write-Host "Backups: $Script:BackupDir" }

if ($Script:ErrorCount -gt 0) {
    exit 2
} elseif (-not $Apply -and $Script:WouldFixCount -gt 0) {
    exit 1
}
exit 0
