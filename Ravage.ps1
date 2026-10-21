# ============================================================
#   Ravage.ps1
#   Author  : Starscream
#   Version : 2.0  (full rewrite)
#   Purpose : Detection of directories with Write+Execute ACL
#             accessible to low-priv users (AppLocker bypass)
#             + LOLBAS check + AppLocker cache
#             + PowerShell Language Mode detection (CLM/bypass implications)
#             + PS v2 availability check
#             + Windows Defender posture (mode, protections, ASR, exclusions)
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
#     - EnforcementMode-aware : when a collection is not Enabled, execution
#       is not actually gated -> LOLBAS and candidates reflect that instead
#       of reporting everything as blocked / not-in-allow
#     - RuleCollection EnforcementMode report (Exe/Dll/Script/Msi/Appx)
#     - Windows Defender posture + ASR rules + exclusions, cross-referenced
#       against bypass candidates (W+X dir under an exclusion = AV-blind)
#     - Privileged principals (Administrators/SYSTEM/operators) dropped from
#       the match set by default : an admin disables AppLocker, not evades it.
#       -IncludePrivileged keeps them (raw view).
#     - Bypass Candidates summary (Write+Execute, usable in context)
#     - Perf : HashSet group lookup, GetAccessControl(), -Force
#
#   Usage :
#     ./Ravage.ps1
#     ./Ravage.ps1 -AllTargets
#     ./Ravage.ps1 -Target "C:\Windows","C:\ProgramData"
#     ./Ravage.ps1 -AllTargets -Output C:\results.txt
#     ./Ravage.ps1 -AsUser "DOMAIN\john"
#     ./Ravage.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"
#     ./Ravage.ps1 -AsUser "MACHINE\localjohn"
#     ./Ravage.ps1 -IncludePrivileged
#     ./Ravage.ps1 -AmsiProbe          # active AMSI check (generates a detection event)
# ============================================================

[CmdletBinding()]
param(
    [string[]]$Target,
    [string]$Output,
    [switch]$AllTargets,
    [string]$AsUser,
    [string[]]$Groups,
    [switch]$IncludePrivileged,
    [switch]$AmsiProbe
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

# Collected bypass candidates (Write+Execute dirs usable for execution in context)
$bypassCandidates = [System.Collections.Generic.List[string]]::new()

# Defender exclusion paths, surfaced for cross-ref in Bypass Candidates
$defenderExclusionPaths = @()

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
Write-Host "           ____      ___     ___    ____ _____ " -ForegroundColor Cyan
Write-Host "          |  _ \    / \ \   / / \  / ___| ____|" -ForegroundColor Cyan
Write-Host "          | |_) |  / _ \ \ / / _ \| |  _|  _|  " -ForegroundColor Cyan
Write-Host "          |  _ <  / ___ \ V / ___ \ |_| | |___ " -ForegroundColor Cyan
Write-Host "          |_| \_\/_/   \_\_/_/   \_\____|_____|" -ForegroundColor Cyan
Write-Host ""
Write-Host "        by Starscream  |  Decepticons Suite"            -ForegroundColor Magenta
Write-Host ""
Write-Host "        Ravage eject Operation: infiltration.."       -ForegroundColor Magenta
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

# ------------------------------------------------------------
#   Privileged-principal filter
# ------------------------------------------------------------
# A W+X dir writable by Administrators/SYSTEM/operators is not a bypass : an
# admin disables AppLocker, it doesn't evade it. These principals are dropped
# from the match set by default. -IncludePrivileged keeps them (raw view).
# SID-based -> survives OS localization.
$privilegedSids = @(
    'S-1-5-32-544',  # Administrators
    'S-1-5-18',      # Local System
    'S-1-5-32-551',  # Backup Operators
    'S-1-5-32-549',  # Server Operators
    'S-1-5-32-550',  # Print Operators
    'S-1-5-32-548',  # Account Operators
    'S-1-5-32-552'   # Replicator
)
$privilegedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (-not $IncludePrivileged) {
    foreach ($sid in $privilegedSids) {
        $nt = Resolve-SidToNTAccount $sid
        if ($nt) { [void]$privilegedNames.Add($nt) }
    }
}

# Real token elevated ? (only meaningful when not simulating)
$isElevated = $false
try {
    $isElevated = ([System.Security.Principal.WindowsPrincipal] `
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# Fast membership lookup (O(1) vs -contains O(n) per ACE)
$groupSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$droppedPriv = 0
foreach ($g in $currentGroups) {
    if (-not $g) { continue }
    if ($privilegedNames.Contains($g)) { $droppedPriv++; continue }
    [void]$groupSet.Add($g)
}
[void]$groupSet.Add("NT AUTHORITY\Authenticated Users")
[void]$groupSet.Add("BUILTIN\Users")

if ($droppedPriv -gt 0) {
    Write-Host ""
    Write-Host "   [!] $droppedPriv privileged principal(s) dropped from match set [-IncludePrivileged to keep]" -ForegroundColor Yellow
    if ($Output) { "   [!] $droppedPriv privileged principal(s) dropped from match set [-IncludePrivileged to keep]" | Add-Content $Output }
}
if ($isElevated -and -not $simulationMode) {
    Write-Host "   [i] Elevated token, no -AsUser : showing generic low-priv surface (Users + Authenticated Users)" -ForegroundColor DarkGray
    Write-Host "       Pass -AsUser DOMAIN\user to scope to a real target's groups"                               -ForegroundColor DarkGray
    if ($Output) {
        "   [i] Elevated token, no -AsUser : showing generic low-priv surface (Users + Authenticated Users)" | Add-Content $Output
        "       Pass -AsUser DOMAIN\user to scope to a real target's groups"                                  | Add-Content $Output
    }
}

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
    # A LOLBAS is an .exe -> governed by the Exe collection. If Exe is not
    # Enabled (NotConfigured / AuditOnly), execution is not blocked, whatever
    # the rules say. Reporting it as denied would be a false negative.
    if (-not ($enforcementModes.ContainsKey("Exe") -and $enforcementModes["Exe"] -eq "Enabled")) {
        return "notenforced"
    }
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
    "Ravage.ps1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" | Out-File $Output
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

# Is EXE execution actually gated ? Only when the Exe collection is Enabled.
# No policy, or Exe NotConfigured/AuditOnly -> execution runs anywhere, so
# allow-path membership is irrelevant for candidate selection and tagging.
$exeEnforced = $hasAppLocker -and
               $enforcementModes.ContainsKey("Exe") -and
               ($enforcementModes["Exe"] -eq "Enabled")

# ------------------------------------------------------------
#   ACL Scan (effective Write+Execute per directory)
# ------------------------------------------------------------
# Collect-then-render : the scan loop no longer prints. Each W+X directory is
# pushed as a finding object; after the loop a collapse pass folds inherited
# descendants under their nearest explicit (or inherited-root) ancestor so the
# console shows anchors + counts instead of thousands of inherited leaves. The
# -Output file still gets the full, un-collapsed listing (recon exhaustiveness).
$findings = [System.Collections.Generic.List[object]]::new()

foreach ($scanPath in $scanPaths) {
    Write-Host ""
    Write-Host "  [*] Analyzing $scanPath" -ForegroundColor Cyan

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
            $identities   = [System.Collections.Generic.List[string]]::new()  # distinct contributing principals (for collapse subset test)

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
                        if (-not $identities.Contains($id)) { $identities.Add($id) }
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

                $alMatch     = Get-AppLockerMatch $dir.FullName
                $isAllowPath = ($null -ne $alMatch) -and ($alMatch -ne $false) -and ($alMatch -ne "deny")

                if (-not $exeEnforced) {
                    # Execution not gated -> any W+X dir is a usable drop-and-run spot,
                    # allow-path membership is moot.
                    $alTag = "[AL:not enforced]"; $alTagColor = "Green"
                }
                elseif ($null -eq $alMatch)  { $alTag = "";                   $alTagColor = "DarkGray" }
                elseif ($alMatch -eq "deny") { $alTag = "[AL:Deny-override]"; $alTagColor = "Red" }
                elseif ($alMatch -eq $false) { $alTag = "[AL:not in allow]";  $alTagColor = "Red" }
                else                         { $alTag = "[AL:Allow]";         $alTagColor = "Green" }

                # Bypass candidate = usable execution location :
                #   - execution not enforced -> any W+X dir works
                #   - enforced -> only under an Allow path, Deny excluded
                $isCandidate = ((-not $exeEnforced) -or $isAllowPath)

                $findings.Add([PSCustomObject]@{
                    FullName     = $dir.FullName
                    Contributors = $contributors
                    Identities   = $identities
                    IsExplicit   = $anyExplicit
                    AlTag        = $alTag
                    AlTagColor   = $alTagColor
                    IsCandidate  = $isCandidate
                    AnchorPath   = $null        # filled by collapse pass
                })
            }
        } catch {
            # Access denied - silent
        }
    }
}

$count = $findings.Count

# ------------------------------------------------------------
#   Collapse pass : assign each finding an anchor
# ------------------------------------------------------------
# Anchor = a finding that is shown on its own line. A finding is an anchor if it
# carries an explicit ACE, OR it is inherited but has no qualifying ancestor
# anchor (an "inherited root" : its writable parent wasn't itself a candidate).
# An inherited finding folds under its nearest ancestor anchor ONLY when its
# contributing principals are a subset of that anchor's -> a deeper dir that
# exposes a NEW principal is never hidden, it becomes its own anchor.
$anchorIdSets = @{}   # anchorPath -> HashSet[string] of its identities

foreach ($f in ($findings | Sort-Object FullName)) {
    if ($f.IsExplicit) {
        $f.AnchorPath = $f.FullName
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($i in $f.Identities) { [void]$set.Add($i) }
        $anchorIdSets[$f.FullName] = $set
        continue
    }
    # inherited : walk up to nearest ancestor anchor
    $p      = Split-Path $f.FullName -Parent
    $anchor = $null
    while ($p) {
        if ($anchorIdSets.ContainsKey($p)) { $anchor = $p; break }
        $pp = Split-Path $p -Parent
        if ($pp -eq $p) { break }
        $p = $pp
    }
    $foldable = $false
    if ($anchor) {
        $aset = $anchorIdSets[$anchor]
        $foldable = $true
        foreach ($i in $f.Identities) { if (-not $aset.Contains($i)) { $foldable = $false; break } }
    }
    if ($foldable) {
        $f.AnchorPath = $anchor
    } else {
        # becomes its own anchor (inherited root, or new-principal surface)
        $f.AnchorPath = $f.FullName
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($i in $f.Identities) { [void]$set.Add($i) }
        $anchorIdSets[$f.FullName] = $set
    }
}

# Count collapsed descendants per anchor (display-only)
$descCount = @{}
foreach ($f in $findings) {
    if ($f.AnchorPath -ne $f.FullName) {
        if (-not $descCount.ContainsKey($f.AnchorPath)) { $descCount[$f.AnchorPath] = 0 }
        $descCount[$f.AnchorPath]++
    }
}

# Helper : given a subset of findings, return the rows to show (anchors in the
# subset + any orphans whose anchor is not in the subset), each with a count of
# how many subset members fold under it. Used for the candidate and exclusion
# summaries so they condense the same way the main listing does.
function Get-CondensedRows {
    param([object[]]$Items)
    $inSet = @{}
    foreach ($i in $Items) { $inSet[$i.FullName] = $true }
    $cnt  = @{}
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($i in ($Items | Sort-Object FullName)) {
        if (($i.AnchorPath -eq $i.FullName) -or (-not $inSet.ContainsKey($i.AnchorPath))) {
            if (-not $cnt.ContainsKey($i.FullName)) { $cnt[$i.FullName] = 0; [void]$rows.Add($i.FullName) }
        } else {
            if (-not $cnt.ContainsKey($i.AnchorPath)) { $cnt[$i.AnchorPath] = 0 }
            $cnt[$i.AnchorPath]++
        }
    }
    return ,($rows | ForEach-Object { [PSCustomObject]@{ Path = $_; Count = $cnt[$_] } })
}

# ------------------------------------------------------------
#   Render : console condensed (anchors), -Output exhaustive (all)
# ------------------------------------------------------------
Write-Host ""
if ($findings.Count -eq 0) {
    Write-Host "  [-] no Write+Execute directory found in context" -ForegroundColor DarkGray
} else {
    foreach ($f in ($findings | Where-Object { $_.AnchorPath -eq $_.FullName } | Sort-Object FullName)) {
        $mainColor = if ($f.IsExplicit) { "Green" } else { "Yellow" }
        $aclColor  = if ($f.IsExplicit) { "Green" } else { "DarkGray" }
        $aclTag    = if ($f.IsExplicit) { "[explicit]" } else { "[inherited]" }
        $n         = if ($descCount.ContainsKey($f.FullName)) { $descCount[$f.FullName] } else { 0 }
        $suffix    = if ($n -gt 0) { "  (+$n inherited)" } else { "" }

        Write-Host "[+] $($f.FullName)$suffix" -ForegroundColor $mainColor
        $first = $true
        foreach ($c in $f.Contributors) {
            if ($first) { Write-Host "    Identity : $c" -ForegroundColor Cyan; $first = $false }
            else        { Write-Host "               $c" -ForegroundColor Cyan }
        }
        Write-Host "    Access   : Write+Execute [effective]" -ForegroundColor Yellow
        Write-Host "    ACL      : $aclTag"                   -ForegroundColor $aclColor
        if ($f.AlTag) { Write-Host "    AppLocker: $($f.AlTag)" -ForegroundColor $f.AlTagColor }
        Write-Host ""
    }
}

# File : full un-collapsed listing
if ($Output) {
    foreach ($f in ($findings | Sort-Object FullName)) {
        $aclTag = if ($f.IsExplicit) { "[explicit]" } else { "[inherited]" }
        "[+] $($f.FullName)" | Add-Content $Output
        $first = $true
        foreach ($c in $f.Contributors) {
            if ($first) { "    Identity : $c" | Add-Content $Output; $first = $false }
            else        { "               $c" | Add-Content $Output }
        }
        "    Access   : Write+Execute [effective]" | Add-Content $Output
        "    ACL      : $aclTag"                   | Add-Content $Output
        if ($f.AlTag) { "    AppLocker: $($f.AlTag)" | Add-Content $Output }
        ""                                         | Add-Content $Output
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
    "winget.exe",
    "regasm.exe"
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
    } elseif ($bin -eq "regasm.exe") {
        $binPath = Get-ChildItem "$env:windir\Microsoft.NET\Framework*" -Recurse -Filter "regasm.exe" -ErrorAction SilentlyContinue |
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
        "notenforced" {
            Write-Host "    [+] $bin : available [AL:not enforced]" -ForegroundColor Green
            if ($Output) { "    [+] $bin : available [AL:not enforced]" | Add-Content $Output }
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
#   Windows Defender posture
# ------------------------------------------------------------
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   Windows Defender"                            -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""

if ($Output) {
    ""                 | Add-Content $Output
    "Windows Defender" | Add-Content $Output
    ""                 | Add-Content $Output
}

# Get-MpComputerStatus : readable by standard users on a default config.
# Failure = Defender module absent, replaced by 3rd-party AV, or access denied.
$defStatus = $null
try { $defStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }

$defPref = $null
try { $defPref = Get-MpPreference -ErrorAction Stop } catch { }

if (-not $defStatus) {
    Write-Host "    [?] Get-MpComputerStatus failed - module absent / 3rd-party AV / access denied" -ForegroundColor Yellow
    if ($Output) { "    [?] Get-MpComputerStatus failed - module absent / 3rd-party AV / access denied" | Add-Content $Output }
} else {

    # Running mode : Normal = actively blocking ; Passive/SxS Passive = another AV
    # is primary, Defender not blocking ; EDR Block = MDE block mode.
    $mode = $defStatus.AMRunningMode
    if ($mode -eq "Normal") {
        Write-Host "    [!] Running mode       : $mode [actively blocking]" -ForegroundColor Red
        if ($Output) { "    [!] Running mode       : $mode [actively blocking]" | Add-Content $Output }
    } else {
        Write-Host "    [+] Running mode       : $mode [not primary - reduced blocking]" -ForegroundColor Green
        if ($Output) { "    [+] Running mode       : $mode [not primary - reduced blocking]" | Add-Content $Output }
    }

    # Per-protection. Convention : ON = Red (obstacle), OFF = Green (window).
    $checks = @(
        @{ Label = "Real-time protection"; Val = $defStatus.RealTimeProtectionEnabled },
        @{ Label = "Behavior monitor";     Val = $defStatus.BehaviorMonitorEnabled   },
        @{ Label = "On-access protection"; Val = $defStatus.OnAccessProtectionEnabled },
        @{ Label = "NIS (network)";        Val = $defStatus.NISEnabled               },
        @{ Label = "Tamper protection";    Val = $defStatus.IsTamperProtected        }
    )
    foreach ($c in $checks) {
        if ($c.Val) {
            $line = "    [!] {0,-20} : ON" -f $c.Label
            Write-Host $line -ForegroundColor Red
            if ($Output) { $line | Add-Content $Output }
        } else {
            $extra = if ($c.Label -eq "Tamper protection") { " [Defender can be disabled]" } else { "" }
            $line  = "    [+] {0,-20} : OFF$extra" -f $c.Label
            Write-Host $line -ForegroundColor Green
            if ($Output) { $line | Add-Content $Output }
        }
    }

    # Cloud / sample submission (higher = more telemetry to MS cloud)
    if ($defPref) {
        $maps   = switch ([int]$defPref.MAPSReporting)        { 0 {"Disabled"} 1 {"Basic"} 2 {"Advanced"} default {"$($defPref.MAPSReporting)"} }
        $sample = switch ([int]$defPref.SubmitSamplesConsent) { 0 {"NeverSend"} 1 {"SendSafe"} 2 {"NeverSend(prompt)"} 3 {"SendAll"} default {"$($defPref.SubmitSamplesConsent)"} }
        Write-Host "    [i] MAPS cloud         : $maps"   -ForegroundColor DarkCyan
        Write-Host "    [i] Sample submission  : $sample" -ForegroundColor DarkCyan
        if ($Output) {
            "    [i] MAPS cloud         : $maps"   | Add-Content $Output
            "    [i] Sample submission  : $sample" | Add-Content $Output
        }
    }

    # Signature staleness (stale defs = weaker detection)
    $sigDate = $defStatus.AntivirusSignatureLastUpdated
    if ($sigDate) {
        $ageDays = [math]::Round(((Get-Date) - $sigDate).TotalDays, 1)
        $sigCol  = if ($ageDays -gt 7) { "Green" } else { "DarkGray" }
        $sigTag  = if ($ageDays -gt 7) { "[stale]" } else { "" }
        Write-Host "    [i] Signatures age     : $ageDays day(s) $sigTag" -ForegroundColor $sigCol
        if ($Output) { "    [i] Signatures age     : $ageDays day(s) $sigTag" | Add-Content $Output }
    }
}

# -- ASR rules (pragmatic : action only, no GUID->name table) --
# Action codes : 0 Disabled | 1 Block | 2 Audit | 5 NotConfigured | 6 Warn
# attacker-POV : Block = obstacle (Red) ; Audit/Disabled/Warn = window.
Write-Host ""
Write-Host "   -- ASR rules --" -ForegroundColor Cyan
if ($Output) { "   -- ASR rules --" | Add-Content $Output }

if (-not $defPref) {
    Write-Host "    [?] Get-MpPreference failed - ASR unreadable" -ForegroundColor Yellow
    if ($Output) { "    [?] Get-MpPreference failed - ASR unreadable" | Add-Content $Output }
} else {
    $asrIds  = @($defPref.AttackSurfaceReductionRules_Ids)     | Where-Object { $_ }
    $asrAct  = @($defPref.AttackSurfaceReductionRules_Actions)

    if ($asrIds.Count -eq 0) {
        Write-Host "    [+] none configured [no ASR coverage]" -ForegroundColor Green
        if ($Output) { "    [+] none configured [no ASR coverage]" | Add-Content $Output }
    } else {
        for ($i = 0; $i -lt $asrIds.Count; $i++) {
            $id  = $asrIds[$i]
            $act = if ($i -lt $asrAct.Count) { [int]$asrAct[$i] } else { -1 }
            switch ($act) {
                1 {
                    Write-Host "    [!] $id : Block [enforced]" -ForegroundColor Red
                    if ($Output) { "    [!] $id : Block [enforced]" | Add-Content $Output }
                }
                2 {
                    Write-Host "    [+] $id : Audit [logged, not blocked]" -ForegroundColor Green
                    if ($Output) { "    [+] $id : Audit [logged, not blocked]" | Add-Content $Output }
                }
                6 {
                    Write-Host "    [~] $id : Warn [user-bypassable]" -ForegroundColor Yellow
                    if ($Output) { "    [~] $id : Warn [user-bypassable]" | Add-Content $Output }
                }
                0 {
                    Write-Host "    [+] $id : Disabled" -ForegroundColor Green
                    if ($Output) { "    [+] $id : Disabled" | Add-Content $Output }
                }
                5 {
                    Write-Host "    [+] $id : NotConfigured [not restricted]" -ForegroundColor Green
                    if ($Output) { "    [+] $id : NotConfigured [not restricted]" | Add-Content $Output }
                }
                default {
                    Write-Host "    [?] $id : action=$act [unknown]" -ForegroundColor DarkGray
                    if ($Output) { "    [?] $id : action=$act [unknown]" | Add-Content $Output }
                }
            }
        }
    }
}

# -- Exclusions (highest-value) --
# CAVEAT : since Defender ~2021 exclusions are hidden from standard users.
# Empty under non-admin = "unreadable", NOT "none".
Write-Host ""
Write-Host "   -- Exclusions --" -ForegroundColor Cyan
if ($Output) { "   -- Exclusions --" | Add-Content $Output }

if (-not $defPref) {
    Write-Host "    [?] Get-MpPreference failed - exclusions unreadable" -ForegroundColor Yellow
    if ($Output) { "    [?] Get-MpPreference failed - exclusions unreadable" | Add-Content $Output }
} else {
    $exPath = @($defPref.ExclusionPath)      | Where-Object { $_ }
    $exExt  = @($defPref.ExclusionExtension) | Where-Object { $_ }
    $exProc = @($defPref.ExclusionProcess)   | Where-Object { $_ }
    $total  = $exPath.Count + $exExt.Count + $exProc.Count

    # surface path exclusions for Bypass Candidates cross-ref
    $defenderExclusionPaths = @($exPath | ForEach-Object { $_.TrimEnd('\') })

    if ($total -eq 0) {
        Write-Host "    [?] none returned - either no exclusions, or hidden from non-admin" -ForegroundColor Yellow
        if ($Output) { "    [?] none returned - either no exclusions, or hidden from non-admin" | Add-Content $Output }
    } else {
        foreach ($p in $exPath) {
            Write-Host "    [+] path : $p" -ForegroundColor Green
            if ($Output) { "    [+] path : $p" | Add-Content $Output }
        }
        foreach ($e in $exExt) {
            Write-Host "    [+] ext  : $e" -ForegroundColor Green
            if ($Output) { "    [+] ext  : $e" | Add-Content $Output }
        }
        foreach ($pr in $exProc) {
            Write-Host "    [+] proc : $pr" -ForegroundColor Green
            if ($Output) { "    [+] proc : $pr" | Add-Content $Output }
        }
    }
}

# -- AMSI --
# Two layers, answering "is AMSI in place, and whose" :
#   (1) registration (default) : read HKLM\SOFTWARE\Microsoft\AMSI\Providers, resolve each
#       CLSID's InprocServer32 DLL, classify Defender vs third-party. Verdict = is a working
#       provider registered, and is it Defender or another. Read-only : never triggers a
#       control, never breaks. Blind spot : an EDR that hooks AMSI in userland WITHOUT a
#       registered provider is invisible here -> a clean verdict is NOT an AMSI all-clear.
#   (2) active probe (-AmsiProbe) : feed the benign AMSI test sentinel to AMSI in THIS shell.
#       Blocked -> AMSI is armed here ; not blocked -> not armed. This is the only way to
#       catch userland hooking, but it GENERATES an AMSI detection event (the engagement's
#       EDR may alert or auto-isolate the host) -> opt-in, never default.
Write-Host ""
Write-Host "   -- AMSI --" -ForegroundColor Cyan
if ($Output) { "   -- AMSI --" | Add-Content $Output }

$amsiDefenderClsid = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'   # Defender (MpOav)
$amsiProviderKey   = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
$amsiProviders     = $null
try {
    $amsiProviders = @(Get-ChildItem $amsiProviderKey -ErrorAction Stop | ForEach-Object { $_.PSChildName })
} catch { $amsiProviders = $null }

# Resolve a provider CLSID to its InprocServer32 DLL path (native + WOW64), expanded.
function Resolve-AmsiProviderDll {
    param([string]$clsid)
    foreach ($base in @('HKLM:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID')) {
        try {
            $raw = (Get-ItemProperty "$base\$clsid\InprocServer32" -ErrorAction Stop).'(default)'
            if ($raw) {
                $raw = ($raw -replace '^"|"$', '')
                return [System.Environment]::ExpandEnvironmentVariables($raw)
            }
        } catch { }
    }
    return $null
}

# (1) Registration verdict
if ($null -eq $amsiProviders) {
    Write-Host "    [?] AMSI\Providers key absent or unreadable" -ForegroundColor Yellow
    if ($Output) { "    [?] AMSI\Providers key absent or unreadable" | Add-Content $Output }
} else {
    $defenderOk   = $false      # Defender provider registered AND its DLL resolves
    $thirdPartyOk = @()         # non-Defender providers whose DLL resolves
    $degraded     = @()         # providers registered but DLL does not resolve
    foreach ($clsid in $amsiProviders) {
        $dll   = Resolve-AmsiProviderDll $clsid
        $dllOk = $dll -and (Test-Path $dll -ErrorAction SilentlyContinue)
        if ($clsid -eq $amsiDefenderClsid) {
            if ($dllOk) { $defenderOk = $true }
        } elseif ($dllOk) {
            $thirdPartyOk += [PSCustomObject]@{ Clsid = $clsid; Dll = $dll }
        }
        if (-not $dllOk) { $degraded += [PSCustomObject]@{ Clsid = $clsid; Dll = $dll } }
    }

    # Verdict line : in place or not, and whose
    if ($defenderOk -and $thirdPartyOk.Count -gt 0) {
        Write-Host "    [!] AMSI active : Defender + third-party [registration]" -ForegroundColor Red
        if ($Output) { "    [!] AMSI active : Defender + third-party [registration]" | Add-Content $Output }
    } elseif ($defenderOk) {
        Write-Host "    [!] AMSI active : Defender [registration]" -ForegroundColor Red
        if ($Output) { "    [!] AMSI active : Defender [registration]" | Add-Content $Output }
    } elseif ($thirdPartyOk.Count -gt 0) {
        Write-Host "    [!] AMSI active : third-party only, Defender absent [registration]" -ForegroundColor Red
        if ($Output) { "    [!] AMSI active : third-party only, Defender absent [registration]" | Add-Content $Output }
    } else {
        Write-Host "    [+] AMSI : no working provider registered [effectively unarmed]" -ForegroundColor Green
        if ($Output) { "    [+] AMSI : no working provider registered [effectively unarmed]" | Add-Content $Output }
    }

    # Detail : which third-party, and any degraded (registered-but-DLL-broken) provider
    foreach ($tp in $thirdPartyOk) {
        Write-Host "        third-party provider $($tp.Clsid) -> $($tp.Dll)" -ForegroundColor Red
        if ($Output) { "        third-party provider $($tp.Clsid) -> $($tp.Dll)" | Add-Content $Output }
    }
    foreach ($dg in $degraded) {
        $d = if ($dg.Dll) { $dg.Dll } else { "<no InprocServer32>" }
        Write-Host "        [+] provider DLL unresolved $($dg.Clsid) -> $d [degraded]" -ForegroundColor Green
        if ($Output) { "        [+] provider DLL unresolved $($dg.Clsid) -> $d [degraded]" | Add-Content $Output }
    }

    # Fixed caveat : registration cannot see userland/EDR hooking
    Write-Host "    [i] registration-level : does not detect userland/EDR AMSI hooking without a registered provider" -ForegroundColor DarkGray
    if ($Output) { "    [i] registration-level : does not detect userland/EDR AMSI hooking without a registered provider" | Add-Content $Output }
    if (-not $AmsiProbe) {
        Write-Host "        use -AmsiProbe to actively test this shell (generates an AMSI detection event)" -ForegroundColor DarkGray
        if ($Output) { "        use -AmsiProbe to actively test this shell (generates an AMSI detection event)" | Add-Content $Output }
    }
}

# (2) Active probe : opt-in, deliberate. The benign AMSI test sentinel is rebuilt from char
# codes at runtime (no literal in the source -> this script is not self-flagged on load),
# then fed to AMSI as a string literal. If AMSI is armed in THIS process the scan blocks it
# and the call throws -> armed ; otherwise it returns -> not armed. This is detection, not a
# bypass. It DOES create an AMSI detection event for this process.
if ($AmsiProbe) {
    $amsiProbeCodes = @(65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,55,101,55,50,99,51,99,101,45,56,54,49,98,45,52,51,51,57,45,56,55,52,48,45,48,97,99,49,52,56,52,99,49,51,56,54)
    $sentinel = -join ($amsiProbeCodes | ForEach-Object { [char][int]$_ })
    $armed    = $null   # $true armed, $false not armed, $null inconclusive
    try {
        # Feed the sentinel to the scripting engine as a plain string literal. Benign to run;
        # only AMSI (if armed) objects to its content.
        $null  = Invoke-Expression ("'" + $sentinel + "'")
        $armed = $false
    } catch {
        $armed = $true
    }
    if ($armed -eq $true) {
        Write-Host "    [!] -AmsiProbe : sentinel BLOCKED -> AMSI armed in this shell" -ForegroundColor Red
        if ($Output) { "    [!] -AmsiProbe : sentinel BLOCKED -> AMSI armed in this shell" | Add-Content $Output }
    } elseif ($armed -eq $false) {
        Write-Host "    [+] -AmsiProbe : sentinel ran -> AMSI NOT armed in this shell" -ForegroundColor Green
        if ($Output) { "    [+] -AmsiProbe : sentinel ran -> AMSI NOT armed in this shell" | Add-Content $Output }
    } else {
        Write-Host "    [?] -AmsiProbe : inconclusive" -ForegroundColor Yellow
        if ($Output) { "    [?] -AmsiProbe : inconclusive" | Add-Content $Output }
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

# Candidate findings (condensed for console, exhaustive for file)
$candidateFindings = @($findings | Where-Object { $_.IsCandidate })
$uniqueCandidates  = @($candidateFindings | ForEach-Object { $_.FullName } | Select-Object -Unique)

if ($uniqueCandidates.Count -eq 0) {
    Write-Host "    [-] none : no usable Write+Execute location found" -ForegroundColor DarkGray
    if ($Output) { "    [-] none : no usable Write+Execute location found" | Add-Content $Output }
} else {
    if (-not $hasAppLocker) {
        Write-Host "    [!] AppLocker policy unreadable - listing all W+X dirs (allow-path status unconfirmed)" -ForegroundColor Yellow
        if ($Output) { "    [!] AppLocker policy unreadable - listing all W+X dirs (allow-path status unconfirmed)" | Add-Content $Output }
        Write-Host ""
    }
    # Console : condensed to anchors + collapsed count
    foreach ($row in (Get-CondensedRows $candidateFindings)) {
        $suffix = if ($row.Count -gt 0) { "  (+$($row.Count) inherited)" } else { "" }
        Write-Host "    [+] $($row.Path)$suffix" -ForegroundColor Green
    }
    # File : exhaustive
    if ($Output) {
        foreach ($c in ($uniqueCandidates | Sort-Object)) { "    [+] $c" | Add-Content $Output }
    }

    # Cross-ref : W+X candidate under a Defender ExclusionPath = drop-and-run
    # with AV blind + AppLocker permissive. Reuses Test-PathUnderAny.
    if ($defenderExclusionPaths.Count -gt 0) {
        $excludedFindings = @($candidateFindings | Where-Object { Test-PathUnderAny $_.FullName $defenderExclusionPaths })
        if ($excludedFindings.Count -gt 0) {
            Write-Host ""
            Write-Host "    [!] W+X dirs under a Defender exclusion [AV-blind drop-and-run] :" -ForegroundColor Red
            if ($Output) { "    [!] W+X dirs under a Defender exclusion [AV-blind drop-and-run] :" | Add-Content $Output }
            # Console : condensed
            foreach ($row in (Get-CondensedRows $excludedFindings)) {
                $suffix = if ($row.Count -gt 0) { "  (+$($row.Count) inherited)" } else { "" }
                Write-Host "        $($row.Path)$suffix" -ForegroundColor Red
            }
            # File : exhaustive
            if ($Output) {
                foreach ($x in ($excludedFindings | ForEach-Object { $_.FullName } | Sort-Object)) {
                    "        $x" | Add-Content $Output
                }
            }
        }
    }

    # Cross-reference execution enforcement : if Exe/Script not enforced,
    # a write-exec location may not even require a bypass.
    if ($hasAppLocker) {
        $exeMode    = if ($enforcementModes.ContainsKey("Exe"))    { $enforcementModes["Exe"] }    else { "NotConfigured" }
        $scriptMode = if ($enforcementModes.ContainsKey("Script")) { $enforcementModes["Script"] } else { "NotConfigured" }
        $dllMode    = if ($enforcementModes.ContainsKey("Dll"))    { $enforcementModes["Dll"] }    else { "NotConfigured" }

        $notes = @()
        if ($exeMode -ne "Enabled") {
            $notes += "    [i] Exe=$exeMode : non-enforced classes may run without a bypass"
        }
        if ($scriptMode -ne "Enabled") {
            $notes += "    [i] Script=$scriptMode : non-enforced classes may run without a bypass"
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
$anchorCount = ($findings | Where-Object { $_.AnchorPath -eq $_.FullName }).Count
Write-Host "   $count director(ies) found | $($uniqueCandidates.Count) bypass candidate(s) | $anchorCount anchor(s) shown" -ForegroundColor Yellow
if ($Output) {
    Write-Host "   Results exported : $Output"             -ForegroundColor DarkGray
}
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Mission Accomplished, Decepticons forever !"  -ForegroundColor DarkCyan
Write-Host ""
