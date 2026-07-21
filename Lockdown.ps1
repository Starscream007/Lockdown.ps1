# ============================================================
#   Lockdown.ps1
#   Author  : Starscream
#   Purpose : Detection des repertoires avec ACL Write+Execute
#             accessibles aux utilisateurs low-priv (AppLocker bypass)
#             + LOLBAS check + PS v2 + AppLocker cache
#
#   Usage   :
#     ./Lockdown.ps1
#     ./Lockdown.ps1 -AllTargets
#     ./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"
#     ./Lockdown.ps1 -AllTargets -Output C:\results.txt
# ============================================================

[CmdletBinding()]
param(
    [string[]]$Target,
    [string]$Output,
    [switch]$AllTargets
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

# Current user 
$currentUser   = whoami
$currentGroups = whoami /groups /fo csv 2>$null |
                 ConvertFrom-Csv |
                 Select-Object -ExpandProperty "Group Name"

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

# Helper AppLocker dir 
function Get-AppLockerMatch {
    param([string]$dirPath)
    if (-not $hasAppLocker) { return $null }
    foreach ($p in $appLockerAllowPaths) {
        if ($dirPath -like "$p*" -or $dirPath -eq $p) { return $p }
    }
    return $false
}

# Helper AppLocker binaire
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

# Banner
$alInfo  = if ($hasAppLocker) { "AppLocker Policy Loaded ($($appLockerAllowPaths.Count) allow paths)" } else { "AppLocker Policy non accessible" }
$alColor = if ($hasAppLocker) { "Green" } else { "DarkGray" }

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
Write-Host ""
Write-Host ""
Write-Host "   User       : $currentUser"                           -ForegroundColor Cyan
Write-Host "   Groupes    :"                                        -ForegroundColor Cyan
$currentGroups | ForEach-Object {
    Write-Host "               $_"                                  -ForegroundColor Yellow
}
Write-Host "   AppLocker  : $alInfo"                                -ForegroundColor $alColor
Write-Host "  ============================================="        -ForegroundColor DarkCyan

if ($Output) {
    "Lockdown.ps1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" | Out-File $Output
    "User      : $currentUser"  | Add-Content $Output
    "Groupes   :"               | Add-Content $Output
    $currentGroups | ForEach-Object { "    $_" | Add-Content $Output }
    "AppLocker : $alInfo"       | Add-Content $Output
    ""                          | Add-Content $Output
}

# Scan ACL's 
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
            # Access denied silencieux
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

    # Paths non-standard
    if ($bin -eq "msbuild.exe") {
        $binPath = Get-ChildItem "$env:windir\Microsoft.NET\Framework*" -Recurse -Filter "msbuild.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1 -ExpandProperty FullName
    } elseif ($bin -eq "winget.exe") {
        $binPath = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Recurse -Filter "winget.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1 -ExpandProperty FullName
    } else {
        $binPath = "$env:windir\System32\$bin"
    }

    if (-not $binPath -or -not (Test-Path $binPath)) {
        Write-Host "    [-] $bin : absent"                    -ForegroundColor DarkGray
        if ($Output) { "    [-] $bin : absent" | Add-Content $Output }
        continue
    }

    $status = Get-AppLockerBinaryStatus $binPath

    switch ($status) {
        "allowed" {
            Write-Host "    [+] $bin : disponible [AL:Allow]" -ForegroundColor Green
            if ($Output) { "    [+] $bin : disponible [AL:Allow]" | Add-Content $Output }
        }
        "denied"  {
            Write-Host "    [-] $bin : bloque [AL:Deny]"      -ForegroundColor Red
            if ($Output) { "    [-] $bin : bloque [AL:Deny]" | Add-Content $Output }
        }
        default   {
            Write-Host "    [?] $bin : present [AL:inconnu]"  -ForegroundColor Yellow
            if ($Output) { "    [?] $bin : present [AL:inconnu]" | Add-Content $Output }
        }
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
    Write-Host "    [+] PowerShell v2 : disponible [CL bypass + logging bypass]" -ForegroundColor Green
    if ($Output) { "    [+] PowerShell v2 : disponible [CL bypass + logging bypass]" | Add-Content $Output }
} else {
    Write-Host "    [-] PowerShell v2 : absent ou desactive"                     -ForegroundColor DarkGray
    if ($Output) { "    [-] PowerShell v2 : absent ou desactive" | Add-Content $Output }
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
    Write-Host "    [-] $cacheDir : absent"                  -ForegroundColor DarkGray
    if ($Output) { "    [-] $cacheDir : absent" | Add-Content $Output }
} else {
    foreach ($cf in $cacheFiles) {
        $cfPath = Join-Path $cacheDir $cf
        if (-not (Test-Path $cfPath)) {
            Write-Host "    [-] $cf : absent"                -ForegroundColor DarkGray
            if ($Output) { "    [-] $cf : absent" | Add-Content $Output }
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
                Write-Host "    [-] $cf : non writable"                        -ForegroundColor DarkGray
                if ($Output) { "    [-] $cf : non writable" | Add-Content $Output }
            }
        } catch {
            Write-Host "    [?] $cf : acces refuse"                            -ForegroundColor Yellow
            if ($Output) { "    [?] $cf : acces refuse" | Add-Content $Output }
        }
    }
}

# Footer 
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "   $count repertoire(s) trouve(s)"             -ForegroundColor Yellow
if ($Output) {
    Write-Host "   Resultats exportes : $Output"           -ForegroundColor DarkGray
}
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Conquest is made of the ashes of one's enemies." -ForegroundColor DarkCyan
Write-Host ""
