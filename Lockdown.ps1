# ============================================================
#   Lockdown.ps1
#   Author  : Starscream
#   Version : 2.0  (rewrite of the original Lockdown)
#   Purpose : Detection of directories with Write+Execute ACL
#             accessible to low-priv users (AppLocker bypass)
#             + LOLBAS check + AppLocker cache
#             + PowerShell Language Mode detection (CLM/bypass implications)
#             + PS v2 availability check
#             + user context simulation (domain or local)
#
#   v2 changes :
#     - Generic access rights (GenericAll/Write/Execute) resolved
#       -> fixes false negatives on ACE carrying generic masks
#     - Write/Execute detection via bitwise flags, not string match
#       -> WriteData (file drop) and ExecuteFile tested explicitly
#       -> CreateDirectories / Modify-without-execute not counted
#     - Effective access per right : canonical Windows evaluation order
#       (explicit Deny > explicit Allow > inherited Deny > inherited Allow)
#       -> explicit Allow correctly beats inherited Deny
#     - Group identities resolved via SID -> NTAccount (LDAP and local),
#       matching the NetBIOS form stored in ACEs
#     - AppLocker : %PROGRAMFILES% expanded (+x86), separator-boundary
#       path match, Allow AND Deny path rules parsed (Deny precedence)
#     - RuleCollection EnforcementMode report (Exe/Dll/Script/Msi/Appx)
#     - Bypass Candidates summary (Write+Execute under an Allow path)
#     - Perf : HashSet group lookup, GetAccessControl(), -Force
#
#   Usage :
#     ./Lockdown.ps1
#     ./Lockdown.ps1 -AllTargets
#     ./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"
#     ./Lockdown.ps1 -AllTargets -Output C:\results.txt
#     ./Lockdown.ps1 -AsUser "DOMAIN\john"
#     ./Lockdown.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"
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

# Collected bypass candidates (Write+Execute AND inside an AppLocker allow path)
$bypassCandidates = [System.Collections.Generic.List[string]]::new()

# ------------------------------------------------------------
#   Access-mask flags (NTFS FileSystemRights + generic bits)
# ------------------------------------------------------------
# Specific file rights
$FR_WriteData    = 0x00000002   # CreateFiles  -> drop a file (needed)
$FR_ExecuteFile  = 0x00000020   # Traverse/Execute
# AppendData (0x4 = CreateDirectories) intentionally NOT treated as write:
# it allows creating subdirs, not dropping a file.
# Generic access bits (never expanded by the .NET FileSystemRights enum)
$GEN_ALL         = 0x10000000
$GEN_EXECUTE     = 0x20000000
$GEN_WRITE       = 0x40000000

# Returns @{ Write = [bool]; Execute = [bool] } for a given FileSystemRights value.
# Resolves generic masks to the specific capabilities relevant here.
function Get-WXFlags {
    param($FileSystemRights)
    $r = [int]$FileSystemRights
    $w = ( ($r -band $FR_WriteData)   -ne 0 ) -or
         ( ($r -band $GEN_WRITE)      -ne 0 ) -or
         ( ($r -band $GEN_ALL)        -ne 0 )
    $e = ( ($r -band $FR_ExecuteFile) -ne 0 ) -or
         ( ($r -band $GEN_EXECUTE)    -ne 0 ) -or
         ( ($r -band $GEN_ALL)        -ne 0 )
    return @{ Write = $w; Execute = $e }
}

# Canonical Windows ACL evaluation for a single right.
# Order : explicit Deny > explicit Allow > inherited Deny > inherited Allow.
# -> explicit Allow correctly overrides an inherited Deny (false-negative fix).
function Resolve-EffectiveRight {
    param([bool]$ExAllow, [bool]$ExDeny, [bool]$InAllow, [bool]$InDeny)
    if ($ExDeny)  { return $false }
    if ($ExAllow) { return $true  }
    if ($InDeny)  { return $false }
    if ($InAllow) { return $true  }
    return $false
}

# Banner
Write-Host ""
Write-Host "  ====================================================" -ForegroundColor DarkCyan
Write-Host "   _     ___   ____ _  ______   _____         ___   _ " -ForegroundColor Cyan
Write-Host "  | |   / _ \ / ___| |/ /  _ \ / _  \ \      / / \ | |" -ForegroundColor Cyan
Write-Host "  | |  | | | | |   | ' /| | | | | | |\ \ /\ / /|  \| |" -ForegroundColor Cyan
Write-Host "  | |__| |_| | |___| . \| |_| | |_| | \ V  V / | |\  |" -ForegroundColor Cyan
Write-Host "  |_____\___/ \____|_|\_\____/ \___/   \_/\_/  |_| \_|" -ForegroundColor Cyan
Write-Host ""
Write-Host "        by Starscream  |  Decepticons Suite  [NG]"      -ForegroundColor Magenta
Write-Host "               Peace through tyranny."                  -ForegroundColor Magenta
Write-Host "  ====================================================" -ForegroundColor DarkCyan
Write-Host ""

# Resolve a security principal (group) to the NTAccount string that ACE
# IdentityReference.Value uses (NetBIOS form). Returns $null on failure.
function Resolve-SidToNTAccount {
    param($Sid)
    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate(
                [System.Security.Principal.NTAccount]).Value
    } catch { return $null }
}

# User and group resolution
function Get-LdapGroups {
    param([string]$username)

    # Domain attempt
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctx      = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $userPrin = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $username)
        if ($userPrin) {
            $resolved = @()
            foreach ($g in $userPrin.GetAuthorizationGroups()) {
                try {
                    # SID -> NTAccount gives the NetBIOS form stored in ACEs,
                    # unlike Context.Name which is often the FQDN.
                    $nt = Resolve-SidToNTAccount $g.Sid
                    if ($nt) { $resolved += $nt }
                    elseif ($g.SamAccountName) { $resolved += $g.SamAccountName }
                } catch { }
            }
            if ($resolved.Count -gt 0) { return $resolved }
        }
    } catch { }

    # Fallback local account via WinNT
    try {
        $localUser = $username -replace '.*\\', ''
        $computer  = $env:COMPUTERNAME
        $user      = [ADSI]"WinNT://$computer/$localUser,user"
        $groups    = @()
        $user.Groups() | ForEach-Object {
            $grp = [ADSI]$_.GetType().InvokeMember("AdsPath", 'GetProperty', $null, $_, $null)
            $nt  = $null
            try {
                # Resolve the group SID to its NTAccount form (correct authority
                # prefix: BUILTIN\, NT AUTHORITY\, or MACHINE\CustomGroup).
                $sidBytes = $grp.InvokeGet('objectSID')
                if ($sidBytes) {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                    $nt  = Resolve-SidToNTAccount $sid
                }
            } catch { }
            if ($nt) { $groups += $nt }
            elseif ($grp.Name[0]) { $groups += "$($grp.Name[0])" }  # bare name fallback
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

# Fast membership lookup (O(1) vs -contains O(n) per ACE)
$groupSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($g in $currentGroups) { if ($g) { [void]$groupSet.Add($g) } }
[void]$groupSet.Add("NT AUTHORITY\Authenticated Users")
[void]$groupSet.Add("BUILTIN\Users")

# ------------------------------------------------------------
#   AppLocker policy (best-effort)
# ------------------------------------------------------------
$appLockerAllowPaths = @()
$appLockerDenyPaths  = @()
$enforcementModes    = @{}   # collection type -> EnforcementMode
$hasAppLocker        = $false
$appLockerPolicy     = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

# Normalize an AppLocker FilePathCondition into concrete literal path prefixes.
# %PROGRAMFILES% yields two variants (native + x86); other vars expanded inline.
function Resolve-RulePaths {
    param([string]$raw)
    if (-not $raw) { return @() }
    $variants = @()
    if ($raw -match '%PROGRAMFILES%') {
        $pf   = $env:ProgramFiles
        $pf86 = ${env:ProgramFiles(x86)}
        if ($pf)   { $variants += ($raw -replace '%PROGRAMFILES%', $pf)   }
        if ($pf86) { $variants += ($raw -replace '%PROGRAMFILES%', $pf86) }
    } else {
        $variants += $raw
    }
    $out = @()
    foreach ($v in $variants) {
        $p = $v `
            -replace '%WINDIR%',   $env:windir `
            -replace '%SYSTEM32%', "$env:windir\System32" `
            -replace '%OSDRIVE%',  $env:SystemDrive `
            -replace '\\\*$',      '' `
            -replace '\*$',        ''
        if ($p) { $out += $p.TrimEnd('\') }
    }
    return $out
}

try {
    $xml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    $xml.AppLockerPolicy.RuleCollection | ForEach-Object {
        $collType = $_.Type
        $mode     = $_.EnforcementMode
        if (-not $mode) { $mode = "NotConfigured" }
        if ($collType) { $enforcementModes[$collType] = $mode }

        $_.FilePathRule | ForEach-Object {
            $paths = Resolve-RulePaths $_.Conditions.FilePathCondition.Path
            if     ($_.Action -eq "Allow") { $appLockerAllowPaths += $paths }
            elseif ($_.Action -eq "Deny")  { $appLockerDenyPaths  += $paths }
        }
    }
    $appLockerAllowPaths = $appLockerAllowPaths | Select-Object -Unique
    $appLockerDenyPaths  = $appLockerDenyPaths  | Select-Object -Unique
    $hasAppLocker = $true
} catch { }

# Separator-boundary test : is dirPath one of the prefixes, or strictly beneath
# one (prefix + '\') ? Avoids C:\Windows matching C:\WindowsApps, and avoids
# -like metacharacter issues.
function Test-PathUnderAny {
    param([string]$dirPath, $prefixes)
    foreach ($p in $prefixes) {
        if ($dirPath.Equals($p, [System.StringComparison]::OrdinalIgnoreCase) -or
            $dirPath.StartsWith($p + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

# AppLocker dir helper.
# Returns : $null  -> no policy
#           "deny" -> under a Deny path (Deny overrides Allow -> NOT a bypass)
#           $false -> not in any allow path
#           <path> -> matching allow path (and not denied)
function Get-AppLockerMatch {
    param([string]$dirPath)
    if (-not $hasAppLocker) { return $null }
    if (Test-PathUnderAny $dirPath $appLockerDenyPaths) { return "deny" }
    foreach ($p in $appLockerAllowPaths) {
        if ($dirPath.Equals($p, [System.StringComparison]::OrdinalIgnoreCase) -or
            $dirPath.StartsWith($p + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $p
        }
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
        if (Test-PathUnderAny $binPath $appLockerDenyPaths) { return "denied" }
        if (Test-PathUnderAny $binPath $appLockerAllowPaths) { return "allowed" }
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
Write-Host ""
Write-Host "   AppLocker  : $alInfo"      -ForegroundColor $alColor
Write-Host "  ============================================="        -ForegroundColor DarkCyan

if ($Output) {
    "Lockdown-NG.ps1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" | Out-File $Output
    "User      : $userLabel"    | Add-Content $Output
    "Groups    : $groupSource"  | Add-Content $Output
    $currentGroups | ForEach-Object { "    $_" | Add-Content $Output }
    "AppLocker : $alInfo"       | Add-Content $Output
    ""                          | Add-Content $Output
}

# ------------------------------------------------------------
#   AppLocker Enforcement Mode (per RuleCollection)
# ------------------------------------------------------------
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   AppLocker Enforcement Mode"                  -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                            | Add-Content $Output
    "AppLocker Enforcement Mode"  | Add-Content $Output
    ""                            | Add-Content $Output
}

if (-not $hasAppLocker) {
    Write-Host "    [?] policy not accessible - enforcement unknown" -ForegroundColor DarkGray
    if ($Output) { "    [?] policy not accessible - enforcement unknown" | Add-Content $Output }
} else {
    $collOrder = @("Exe", "Dll", "Script", "Msi", "Appx")
    foreach ($ct in $collOrder) {
        if (-not $enforcementModes.ContainsKey($ct)) {
            Write-Host "    [-] $ct : NotConfigured [not restricted]" -ForegroundColor DarkGray
            if ($Output) { "    [-] $ct : NotConfigured [not restricted]" | Add-Content $Output }
            continue
        }
        $m = $enforcementModes[$ct]
        switch ($m) {
            "Enabled" {
                Write-Host "    [!] $ct : Enabled [enforced]" -ForegroundColor Red
                if ($Output) { "    [!] $ct : Enabled [enforced]" | Add-Content $Output }
            }
            "AuditOnly" {
                Write-Host "    [+] $ct : AuditOnly [runs, logged only - no bypass needed]" -ForegroundColor Green
                if ($Output) { "    [+] $ct : AuditOnly [runs, logged only - no bypass needed]" | Add-Content $Output }
            }
            default {
                Write-Host "    [+] $ct : $m [not restricted]" -ForegroundColor Green
                if ($Output) { "    [+] $ct : $m [not restricted]" | Add-Content $Output }
            }
        }
    }
    # Any collection type present in the policy but outside the known list
    foreach ($ct in $enforcementModes.Keys) {
        if ($collOrder -notcontains $ct) {
            $m = $enforcementModes[$ct]
            Write-Host "    [?] $ct : $m" -ForegroundColor Yellow
            if ($Output) { "    [?] $ct : $m" | Add-Content $Output }
        }
    }
}

# ------------------------------------------------------------
#   ACL Scan (effective Write+Execute per directory)
# ------------------------------------------------------------
foreach ($scanPath in $scanPaths) {
    Write-Host ""
    Write-Host "  [*] Analyzing $scanPath" -ForegroundColor Cyan
    Write-Host ""

    $dirs = Get-ChildItem -LiteralPath $scanPath -Directory -Recurse -Force -ErrorAction SilentlyContinue

    foreach ($dir in $dirs) {
        try {
            # Faster than Get-Acl; fall back for PS7 where the method is gone
            $acl = try { $dir.GetAccessControl() } catch { Get-Acl -LiteralPath $dir.FullName }

            # Four buckets per right : explicit/inherited x Allow/Deny
            $exAllowW = $false; $exAllowE = $false
            $exDenyW  = $false; $exDenyE  = $false
            $inAllowW = $false; $inAllowE = $false
            $inDenyW  = $false; $inDenyE  = $false
            $anyExplicit  = $false
            $contributors = [System.Collections.Generic.List[string]]::new()

            foreach ($ace in $acl.Access) {
                $id = $ace.IdentityReference.Value
                if (-not $groupSet.Contains($id)) { continue }

                $wx        = Get-WXFlags $ace.FileSystemRights
                $inherited = $ace.IsInherited

                if ($ace.AccessControlType -eq 'Allow') {
                    if ($wx.Write)   { if ($inherited) { $inAllowW = $true } else { $exAllowW = $true } }
                    if ($wx.Execute) { if ($inherited) { $inAllowE = $true } else { $exAllowE = $true } }
                    if ($wx.Write -or $wx.Execute) {
                        $contributors.Add("$id ($($ace.FileSystemRights))")
                        if (-not $inherited) { $anyExplicit = $true }
                    }
                } else {   # Deny
                    if ($wx.Write)   { if ($inherited) { $inDenyW = $true } else { $exDenyW = $true } }
                    if ($wx.Execute) { if ($inherited) { $inDenyE = $true } else { $exDenyE = $true } }
                }
            }

            # Effective access : canonical evaluation order, per right
            $effW = Resolve-EffectiveRight $exAllowW $exDenyW $inAllowW $inDenyW
            $effE = Resolve-EffectiveRight $exAllowE $exDenyE $inAllowE $inDenyE

            if ($effW -and $effE) {

                $aclTag   = if ($anyExplicit) { "[explicit]" } else { "[inherited]" }
                $aclColor = if ($anyExplicit) { "Green" }      else { "DarkGray" }
                $mainColor= if ($anyExplicit) { "Green" }      else { "Yellow" }

                $alMatch     = Get-AppLockerMatch $dir.FullName
                $isAllowPath = ($null -ne $alMatch) -and ($alMatch -ne $false) -and ($alMatch -ne "deny")
                if     ($null -eq $alMatch)     { $alTag = "";                   $alTagColor = "DarkGray" }
                elseif ($alMatch -eq "deny")    { $alTag = "[AL:Deny-override]"; $alTagColor = "Red" }
                elseif ($alMatch -eq $false)    { $alTag = "[AL:not in allow]";  $alTagColor = "Red" }
                else                            { $alTag = "[AL:Allow]";         $alTagColor = "Green" }

                # Bypass candidate : writable+executable AND reachable under
                # an AppLocker allow path, Deny paths excluded (Deny overrides
                # Allow). AL policy unreadable -> flag all (status unconfirmed).
                if ($isAllowPath -or (-not $hasAppLocker)) {
                    [void]$bypassCandidates.Add($dir.FullName)
                }

                $count++

                Write-Host "[+] $($dir.FullName)" -ForegroundColor $mainColor
                $first = $true
                foreach ($c in $contributors) {
                    if ($first) { Write-Host "    Identity : $c" -ForegroundColor Cyan; $first = $false }
                    else        { Write-Host "               $c" -ForegroundColor Cyan }
                }
                Write-Host "    Access   : Write+Execute [effective]" -ForegroundColor Yellow
                Write-Host "    ACL      : $aclTag"                   -ForegroundColor $aclColor
                if ($alTag) {
                    Write-Host "    AppLocker: $alTag" -ForegroundColor $alTagColor
                }
                Write-Host ""

                if ($Output) {
                    "[+] $($dir.FullName)" | Add-Content $Output
                    $first = $true
                    foreach ($c in $contributors) {
                        if ($first) { "    Identity : $c" | Add-Content $Output; $first = $false }
                        else        { "               $c" | Add-Content $Output }
                    }
                    "    Access   : Write+Execute [effective]" | Add-Content $Output
                    "    ACL      : $aclTag"                   | Add-Content $Output
                    if ($alTag) { "    AppLocker: $alTag"      | Add-Content $Output }
                    ""                                         | Add-Content $Output
                }
            }
        } catch {
            # Access denied - silent
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

$ps2reg     = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" `
              -ErrorAction SilentlyContinue
$ps2regOk   = $ps2reg -and $ps2reg.PowerShellVersion -eq "2.0"

# Check Windows feature (requires elevation, best-effort)
$ps2feature = $null
$netFx3     = $null
try {
    $ps2feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction Stop
    $netFx3     = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction Stop
} catch { }

$ps2featureOk = $ps2feature -and $ps2feature.State -eq "Enabled"
$netFx3Ok     = $netFx3 -and $netFx3.State -eq "Enabled"

if ($ps2regOk -and $ps2featureOk -and $netFx3Ok) {
    # Registry + feature + .NET 3.5 all OK
    if ($langMode -eq "ConstrainedLanguage") {
        Write-Host "    [+] PowerShell v2 : available [CLM + logging bypass - use it]" -ForegroundColor Green
        if ($Output) { "    [+] PowerShell v2 : available [CLM + logging bypass - use it]" | Add-Content $Output }
    } else {
        Write-Host "    [+] PowerShell v2 : available [CLM + logging bypass]" -ForegroundColor Green
        if ($Output) { "    [+] PowerShell v2 : available [CLM + logging bypass]" | Add-Content $Output }
    }
} elseif ($ps2regOk -and $null -eq $ps2feature) {
    # Registry OK but feature check failed (no elevation) - inconclusive
    Write-Host "    [?] PowerShell v2 : registry present but runtime unverified [run as admin to confirm]" -ForegroundColor Yellow
    if ($Output) { "    [?] PowerShell v2 : registry present but runtime unverified [run as admin to confirm]" | Add-Content $Output }
} elseif ($ps2regOk -and (-not $ps2featureOk -or -not $netFx3Ok)) {
    # Registry OK but feature or .NET 3.5 disabled
    $reason = if (-not $netFx3Ok) { "NetFx3 disabled" } else { "PSv2 feature disabled" }
    Write-Host "    [-] PowerShell v2 : registry present but runtime unavailable [$reason]" -ForegroundColor Red
    if ($Output) { "    [-] PowerShell v2 : registry present but runtime unavailable [$reason]" | Add-Content $Output }
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
                $groupSet.Contains($_.IdentityReference.Value) -and
                (Get-WXFlags $_.FileSystemRights).Write
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

# ------------------------------------------------------------
#   Bypass Candidates (prioritized summary)
# ------------------------------------------------------------
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   Bypass Candidates"                           -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                   | Add-Content $Output
    "Bypass Candidates"  | Add-Content $Output
    ""                   | Add-Content $Output
}

$uniqueCandidates = $bypassCandidates | Select-Object -Unique

if ($uniqueCandidates.Count -eq 0) {
    Write-Host "    [-] none : no Write+Execute dir inside an allow path" -ForegroundColor DarkGray
    if ($Output) { "    [-] none : no Write+Execute dir inside an allow path" | Add-Content $Output }
} else {
    if (-not $hasAppLocker) {
        Write-Host "    [!] AppLocker policy unreadable - listing all W+X dirs (allow-path status unconfirmed)" -ForegroundColor Yellow
        if ($Output) { "    [!] AppLocker policy unreadable - listing all W+X dirs (allow-path status unconfirmed)" | Add-Content $Output }
        Write-Host ""
    }
    foreach ($c in $uniqueCandidates) {
        Write-Host "    [+] $c" -ForegroundColor Green
        if ($Output) { "    [+] $c" | Add-Content $Output }
    }

    # Cross-reference execution enforcement : if Exe/Script not enforced,
    # a write-exec location may not even require a bypass.
    if ($hasAppLocker) {
        $exeMode    = if ($enforcementModes.ContainsKey("Exe"))    { $enforcementModes["Exe"] }    else { "NotConfigured" }
        $scriptMode = if ($enforcementModes.ContainsKey("Script")) { $enforcementModes["Script"] } else { "NotConfigured" }
        $dllMode    = if ($enforcementModes.ContainsKey("Dll"))    { $enforcementModes["Dll"] }    else { "NotConfigured" }

        $notes = @()
        if ($exeMode -ne "Enabled" -or $scriptMode -ne "Enabled") {
            $notes += "    [i] Exe=$exeMode / Script=$scriptMode : non-enforced classes may run without a bypass"
        }
        if ($dllMode -ne "Enabled") {
            $notes += "    [i] Dll=$dllMode : a DLL dropped in these dirs loads via regsvr32/rundll32 without a bypass"
        }
        if ($notes.Count -gt 0) {
            Write-Host ""
            foreach ($n in $notes) {
                Write-Host $n -ForegroundColor DarkCyan
                if ($Output) { $n | Add-Content $Output }
            }
        }
    }
}

# Footer
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   $count director(ies) found | $($uniqueCandidates.Count) bypass candidate(s)" -ForegroundColor Yellow
if ($Output) {
    Write-Host "   Results exported : $Output"             -ForegroundColor DarkGray
}
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Conquest is made of the ashes of one's enemies..." -ForegroundColor DarkCyan
Write-Host ""
