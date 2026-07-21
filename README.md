# Lockdown: Decepticon AppLocker Auditor
> *"No one escapes Lockdown."*

PowerShell AppLocker enumeration tool — ACL misconfiguration detection, LOLBAS availability check and AppLocker policy analysis from a low-priv context.

## Usage
```powershell
./Lockdown.ps1
./Lockdown.ps1 -AllTargets
./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"
./Lockdown.ps1 -AllTargets -Output C:\results.txt
```

## What it checks

| Module | Description |
|---|---|
| ACL Scan | Writable + Executable directories accessible to low-priv users |
| AppLocker Cross-check | Identifies directories within AppLocker Allow paths |
| LOLBAS Checker | installutil, rundll32, regsvr32, mshta, wscript, cscript, msbuild, certutil, winget |
| PowerShell v2 | Detects availability (CLM + logging bypass) |
| AppLocker Cache | Checks AppCache.dat writability (cache poisoning vector) |

## Parameters

| Parameter | Description |
|---|---|
| `-AllTargets` | Scans Windows, ProgramData, Program Files, inetpub |
| `-Target` | Custom path(s) to scan |
| `-Output` | Export results to file |

## Requirements
- PowerShell 3+
- Low-priv user context (no admin required)

## Disclaimer
For educational purposes and authorized engagements only.  
The author is not responsible for any misuse of this tool.  
Decepticons follow the rules. Sometimes.

---
*Part of the [Decepticons Suite](https://github.com/Starscream007)*

Peace through Tyranny.
