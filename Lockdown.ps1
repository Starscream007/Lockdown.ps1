# ============================================================
#   Lockdown.ps1
#   Author  : Starscream
#   Purpose : Detection of directories with Write+Execute ACL
#             accessible to low-priv users (AppLocker bypass)
#             + LOLBAS check + AppLocker cache
#             + PowerShell Language Mode detection (CLM/bypass implications)
#             + PS v2 availability check
#             + user context simulation (domain or local)
#
#   Usage   :
#     ./Lockdown.ps1
#     ./Lockdown.ps1 -AllTargets
#     ./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"
#     ./Lockdown.ps1 -AllTargets -Output C:\results.txt
#     ./Lockdown.ps1 -AsUser "DOMAIN\john"
#     ./Lockdown.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"
#     ./Lockdown.ps1 -AsUser "localjohn"
#     ./Lockdown.ps1 -AsUser "MACHINE\localjohn"
# ============================================================

[CmdletBinding()]
param(
    [string[]]$Target,
    [string]$Output,
    [switch]$AllTargets,
    [string]$AsUser,
    [string[]]$Groups
)

# Targets
$defaultTargets = @(
    $env:windir,
    $env:ProgramData,
    "$env:SystemDrive\Program Files",
    "$env:SystemDrive\Program Files (x86)",
    "$env:SystemDrive\inetpub"
) | Where-Object { Test-Path $_ }

if ($AllTargets)  { $scanPaths = $defaultTargets }
elseif ($Target)  { $scanPaths = $Target }
else              { $scanPaths = @($env:windir) }

$count = 0

# Banner
Write-Host ""
Write-Host "  ====================================================" -ForegroundColor DarkCyan
Write-Host "   _     ___   ____ _  ______   _____         ___   _ " -ForegroundColor Cyan
Write-Host "  | |   / _ \ / ___| |/ /  _ \ / _  \ \      / / \ | |" -ForegroundColor Cyan
Write-Host "  | |  | | | | |   | ' /| | | | | | |\ \ /\ / /|  \| |" -ForegroundColor Cyan
Write-Host "  | |__| |_| | |___| . \| |_| | |_| | \ V  V / | |\  |" -ForegroundColor Cyan
Write-Host "  |_____\___/ \____|_|\_\____/ \___/   \_/\_/  |_| \_|" -ForegroundColor Cyan
Write-Host ""
Write-Host "          by Starscream  |  Decepticons Suite"          -ForegroundColor Magenta
Write-Host "               Peace through tyranny."                  -ForegroundColor Magenta
Write-Host "  ====================================================" -ForegroundColor DarkCyan
Write-Host ""

# User and group resolution
function Get-LdapGroups {
    param([string]$username)

    # Domain attempt
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctx      = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $userPrin = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $username)
        if ($userPrin) {
            $domain = $userPrin.Context.Name
            return $userPrin.GetAuthorizationGroups() |
                   ForEach-Object { "$domain\$($_.SamAccountName)" } |
                   Where-Object { $_ }
        }
    } catch { }

    # Fallback local account via WinNT
    try {
        $localUser = $username -replace '.*\\', ''
        $computer  = $env:COMPUTERNAME
        $user      = [ADSI]"WinNT://$computer/$localUser,user"
        $groups    = @()
        $user.Groups() | ForEach-Object {
            $grp  = [ADSI]$_.GetType().InvokeMember("AdsPath", 'GetProperty', $null, $_, $null)
            $groups += "BUILTIN\$($grp.Name[0])"
        }
        if ($groups.Count -gt 0) { return $groups }
    } catch { }

    return $null
}

$simulationMode = $false
$ldapResolved   = $false

if ($AsUser) {
    $simulationMode = $true
    $currentUser    = $AsUser

    if ($Groups) {
        $currentGroups = $Groups
        Write-Host "   [*] Simulation mode : $AsUser (manual groups)" -ForegroundColor Yellow
    } else {
        Write-Host "   [*] Attempting LDAP resolution for $AsUser ..." -ForegroundColor Cyan
        $ldapGroups = Get-LdapGroups -username $AsUser
        if ($ldapGroups) {
            $currentGroups = $ldapGroups
            $ldapResolved  = $true
            Write-Host "   [+] LDAP OK : $($currentGroups.Count) groups resolved" -ForegroundColor Green
        } else {
            $currentGroups = @("NT AUTHORITY\Authenticated Users", "BUILTIN\Users")
            Write-Host "   [!] LDAP failed : fallback to Authenticated Users + Users" -ForegroundColor Yellow
            Write-Host "       Use -Groups to pass groups manually"                   -ForegroundColor DarkGray
        }
    }
} else {
    $currentUser   = whoami
    $currentGroups = whoami /groups /fo csv 2>$null |
                     ConvertFrom-Csv |
                     Select-Object -ExpandProperty "Group Name"
}

# AppLocker policy (best-effort)
$appLockerAllowPaths = @()
$hasAppLocker        = $false
$appLockerPolicy     = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

try {
    $xml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    $xml.AppLockerPolicy.RuleCollection | ForEach-Object {
        $_.FilePathRule | Where-Object { $_.Action -eq "Allow" } | ForEach-Object {
            $p = $_.Conditions.FilePathCondition.Path `
                -replace '%WINDIR%',   $env:windir `
                -replace '%SYSTEM32%', "$env:windir\System32" `
                -replace '%OSDRIVE%',  $env:SystemDrive `
                -replace '\\\*$',      '' `
                -replace '\*$',        ''
            if ($p) { $appLockerAllowPaths += $p.TrimEnd('\') }
        }
    }
    $hasAppLocker = $true
} catch { }

# AppLocker dir helper
function Get-AppLockerMatch {
    param([string]$dirPath)
    if (-not $hasAppLocker) { return $null }
    foreach ($p in $appLockerAllowPaths) {
        if ($dirPath -like "$p*" -or $dirPath -eq $p) { return $p }
    }
    return $false
}

# AppLocker binary helper
function Get-AppLockerBinaryStatus {
    param([string]$binPath)
    if (-not $hasAppLocker) { return "unknown" }
    try {
        $result = Test-AppLockerPolicy -PolicyObject $appLockerPolicy -Path $binPath -ErrorAction Stop
        if ($result.PolicyDecision -eq "Allowed") { return "allowed" }
        else                                       { return "denied"  }
    } catch {
        foreach ($p in $appLockerAllowPaths) {
            if ($binPath -like "$p*") { return "allowed" }
        }
        return "unknown"
    }
}

# Header
$alInfo  = if ($hasAppLocker) { "AppLocker Policy Loaded ($($appLockerAllowPaths.Count) allow paths)" } else { "AppLocker Policy not accessible" }
$alColor = if ($hasAppLocker) { "Green" } else { "DarkGray" }

$userLabel   = if ($simulationMode) { "$currentUser [simulation]" } else { $currentUser }
$groupSource = if ($ldapResolved) { "[LDAP]" } elseif ($simulationMode -and $Groups) { "[manual]" } elseif ($simulationMode) { "[fallback]" } else { "[whoami]" }

Write-Host ""
Write-Host "   User       : $userLabel"   -ForegroundColor Cyan
Write-Host "   Groups     : $groupSource" -ForegroundColor Cyan
$currentGroups | ForEach-Object {
    Write-Host "               $_"         -ForegroundColor Yellow
}
Write-Host "   AppLocker  : $alInfo"      -ForegroundColor $alColor
Write-Host "  ============================================="        -ForegroundColor DarkCyan

if ($Output) {
    "Lockdown.ps1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" | Out-File $Output
    "User      : $userLabel"    | Add-Content $Output
    "Groups    : $groupSource"  | Add-Content $Output
    $currentGroups | ForEach-Object { "    $_" | Add-Content $Output }
    "AppLocker : $alInfo"       | Add-Content $Output
    ""                          | Add-Content $Output
}

# ACL Scan
foreach ($scanPath in $scanPaths) {
    Write-Host ""
    Write-Host "  [*] Analyzing $scanPath" -ForegroundColor Cyan
    Write-Host ""

    Get-ChildItem $scanPath -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $dir = $_
        try {
            (Get-Acl $dir.FullName).Access | ForEach-Object {
                if ($_.AccessControlType -eq "Allow") {
                    $id = $_.IdentityReference.Value
                    if ($currentGroups -contains $id -or
                        $id -eq "NT AUTHORITY\Authenticated Users" -or
                        $id -eq "BUILTIN\Users") {

                        $r          = $_.FileSystemRights.ToString()
                        $hasWrite   = $r -match "Write|Create|FullControl|Modify"
                        $hasExecute = $r -match "Execute|FullControl|Modify"

                        if ($hasWrite -and $hasExecute) {

                            $aclTag   = if ($_.IsInherited) { "[inherited]" } else { "[explicit]" }
                            $aclColor = if ($_.IsInherited) { "DarkGray" }    else { "Green" }

                            $alMatch    = Get-AppLockerMatch $dir.FullName
                            $alTag      = if ($null -ne $alMatch -and $alMatch -ne $false) { "[AL:Allow]" } `
                                          elseif ($alMatch -eq $false)                     { "[AL:not in allow]" } `
                                          else                                              { "" }
                            $alTagColor = if ($alMatch) { "Green" } else { "Red" }

                            $count++
                            $mainColor = if (-not $_.IsInherited) { "Green" } else { "Yellow" }

                            Write-Host "[+] $($dir.FullName)" -ForegroundColor $mainColor
                            Write-Host "    Identity : $id"   -ForegroundColor Cyan
                            Write-Host "    Rights   : $r"    -ForegroundColor Yellow
                            Write-Host "    ACL      : $aclTag" -ForegroundColor $aclColor
                            if ($alTag) {
                                Write-Host "    AppLocker: $alTag" -ForegroundColor $alTagColor
                            }
                            Write-Host ""

                            if ($Output) {
                                "[+] $($dir.FullName)"    | Add-Content $Output
                                "    Identity : $id"      | Add-Content $Output
                                "    Rights   : $r"       | Add-Content $Output
                                "    ACL      : $aclTag"  | Add-Content $Output
                                if ($alTag) { "    AppLocker: $alTag" | Add-Content $Output }
                                ""                        | Add-Content $Output
                            }
                        }
                    }
                }
            }
        } catch {
            # Access denied â€” silent
        }
    }
}

# LOLBAS Check
$lolbas = @(
    "installutil.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "msbuild.exe",
    "certutil.exe",
    "winget.exe"
)

Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   LOLBAS Checker"                              -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""             | Add-Content $Output
    "LOLBAS Check" | Add-Content $Output
    ""             | Add-Content $Output
}

foreach ($bin in $lolbas) {

    if ($bin -eq "installutil.exe") {
        $binPath = Get-ChildItem "$env:windir\Microsoft.NET\Framework64" -Recurse -Filter "installutil.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1 -ExpandProperty FullName
        if (-not $binPath) {
            $binPath = Get-ChildItem "$env:windir\Microsoft.NET\Framework" -Recurse -Filter "installutil.exe" -ErrorAction SilentlyContinue |
                       Select-Object -First 1 -ExpandProperty FullName
        }
    } elseif ($bin -eq "msbuild.exe") {
        $binPath = Get-ChildItem "$env:windir\Microsoft.NET\Framework*" -Recurse -Filter "msbuild.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1 -ExpandProperty FullName
    } elseif ($bin -eq "winget.exe") {
        $binPath = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Recurse -Filter "winget.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1 -ExpandProperty FullName
    } else {
        $binPath = "$env:windir\System32\$bin"
    }

    if (-not $binPath -or -not (Test-Path $binPath)) {
        Write-Host "    [-] $bin : not found"                  -ForegroundColor DarkGray
        if ($Output) { "    [-] $bin : not found" | Add-Content $Output }
        continue
    }

    $status = Get-AppLockerBinaryStatus $binPath

    switch ($status) {
        "allowed" {
            Write-Host "    [+] $bin : available [AL:Allow]" -ForegroundColor Green
            if ($Output) { "    [+] $bin : available [AL:Allow]" | Add-Content $Output }
        }
        "denied"  {
            Write-Host "    [-] $bin : blocked [AL:Deny]"    -ForegroundColor Red
            if ($Output) { "    [-] $bin : blocked [AL:Deny]" | Add-Content $Output }
        }
        default   {
            Write-Host "    [?] $bin : present [AL:unknown]" -ForegroundColor Yellow
            if ($Output) { "    [?] $bin : present [AL:unknown]" | Add-Content $Output }
        }
    }
}

# PowerShell Language Mode Check
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   PowerShell Language Mode"                    -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                             | Add-Content $Output
    "PowerShell Language Mode"     | Add-Content $Output
    ""                             | Add-Content $Output
}

$langMode = $ExecutionContext.SessionState.LanguageMode

switch ($langMode) {
    "FullLanguage" {
        Write-Host "    [+] $langMode : no restrictions" -ForegroundColor Green
        if ($Output) { "    [+] $langMode : no restrictions" | Add-Content $Output }
    }
    "ConstrainedLanguage" {
        Write-Host "    [!] $langMode : CLM active [AppLocker likely enforced]" -ForegroundColor Yellow
        Write-Host "        -> PS v2 bypass if available"                       -ForegroundColor DarkGray
        Write-Host "        -> LOLBAS execution may still work"                 -ForegroundColor DarkGray
        if ($Output) {
            "    [!] $langMode : CLM active [AppLocker likely enforced]" | Add-Content $Output
            "        -> PS v2 bypass if available"                       | Add-Content $Output
            "        -> LOLBAS execution may still work"                 | Add-Content $Output
        }
    }
    "RestrictedLanguage" {
        Write-Host "    [!] $langMode : severely restricted [no cmdlets, no variables]" -ForegroundColor Red
        if ($Output) { "    [!] $langMode : severely restricted [no cmdlets, no variables]" | Add-Content $Output }
    }
    "NoLanguage" {
        Write-Host "    [-] $langMode : script execution fully disabled" -ForegroundColor Red
        if ($Output) { "    [-] $langMode : script execution fully disabled" | Add-Content $Output }
    }
    default {
        Write-Host "    [?] $langMode : unknown mode" -ForegroundColor Yellow
        if ($Output) { "    [?] $langMode : unknown mode" | Add-Content $Output }
    }
}

# PowerShell v2 Check
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   PowerShell v2 Checker"                       -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                    | Add-Content $Output
    "PowerShell v2 Check" | Add-Content $Output
    ""                    | Add-Content $Output
}

$ps2reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" `
          -ErrorAction SilentlyContinue

if ($ps2reg -and $ps2reg.PowerShellVersion -eq "2.0") {
    if ($langMode -eq "ConstrainedLanguage") {
        Write-Host "    [+] PowerShell v2 : available [CLM + logging bypass â€” use it]" -ForegroundColor Green
        if ($Output) { "    [+] PowerShell v2 : available [CLM + logging bypass â€” use it]" | Add-Content $Output }
    } else {
        Write-Host "    [+] PowerShell v2 : available [CLM + logging bypass]" -ForegroundColor Green
        if ($Output) { "    [+] PowerShell v2 : available [CLM + logging bypass]" | Add-Content $Output }
    }
} else {
    Write-Host "    [-] PowerShell v2 : absent or disabled"               -ForegroundColor DarkGray
    if ($Output) { "    [-] PowerShell v2 : absent or disabled" | Add-Content $Output }
}

# AppLocker Cache Check
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   AppLocker Cache Checker"                     -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                      | Add-Content $Output
    "AppLocker Cache Check" | Add-Content $Output
    ""                      | Add-Content $Output
}

$cacheDir   = "$env:windir\System32\AppLocker"
$cacheFiles = @("AppCache.dat", "AppCache.dat.LOG1", "AppCache.dat.LOG2")

if (-not (Test-Path $cacheDir)) {
    Write-Host "    [-] $cacheDir : not found"              -ForegroundColor DarkGray
    if ($Output) { "    [-] $cacheDir : not found" | Add-Content $Output }
} else {
    foreach ($cf in $cacheFiles) {
        $cfPath = Join-Path $cacheDir $cf
        if (-not (Test-Path $cfPath)) {
            Write-Host "    [-] $cf : not found"            -ForegroundColor DarkGray
            if ($Output) { "    [-] $cf : not found" | Add-Content $Output }
            continue
        }
        try {
            $acl      = Get-Acl $cfPath
            $writable = $acl.Access | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                ($currentGroups -contains $_.IdentityReference.Value -or
                 $_.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -or
                 $_.IdentityReference.Value -eq "BUILTIN\Users") -and
                $_.FileSystemRights -match "Write|FullControl|Modify"
            }
            if ($writable) {
                Write-Host "    [+] $cf : writable [cache poisoning possible]" -ForegroundColor Green
                if ($Output) { "    [+] $cf : writable [cache poisoning possible]" | Add-Content $Output }
            } else {
                Write-Host "    [-] $cf : not writable"                        -ForegroundColor DarkGray
                if ($Output) { "    [-] $cf : not writable" | Add-Content $Output }
            }
        } catch {
            Write-Host "    [?] $cf : access denied"                           -ForegroundColor Yellow
            if ($Output) { "    [?] $cf : access denied" | Add-Content $Output }
        }
    }
}

# Footer
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   $count director(ies) found"                 -ForegroundColor Yellow
if ($Output) {
    Write-Host "   Results exported : $Output"             -ForegroundColor DarkGray
}
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Conquest is made of the ashes of one's enemies..." -ForegroundColor DarkCyan
Write-Host ""

