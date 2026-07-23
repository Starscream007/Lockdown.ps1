# Lockdown: Decepticon AppLocker Auditor
> *"No one escapes Lockdown."*

PowerShell AppLocker enumeration tool — ACL misconfiguration detection, LOLBAS availability check and AppLocker policy analysis from a low-priv context. Supports user context simulation for domain and local accounts.

## Usage
```powershell
# Current user
./Lockdown.ps1
./Lockdown.ps1 -AllTargets
./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"
./Lockdown.ps1 -AllTargets -Output C:\results.txt

# Simulate another user context (domain — LDAP auto-resolution)
./Lockdown.ps1 -AsUser "DOMAIN\john"

# Simulate another user context (manual groups — no LDAP required)
./Lockdown.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"

# Simulate a local user context
./Lockdown.ps1 -AsUser "john"
./Lockdown.ps1 -AsUser "MACHINE\john"
```

## What it checks
| Module | Description |
|---|---|
| ACL Scan | Writable + Executable directories accessible to low-priv users |
| AppLocker Cross-check | Identifies directories within AppLocker Allow paths |
| LOLBAS Checker | installutil, rundll32, regsvr32, mshta, wscript, cscript, msbuild, certutil, winget |
| Language Mode | Detects FullLanguage / ConstrainedLanguage / RestrictedLanguage / NoLanguage with bypass implications |
| PowerShell v2 | Detects availability (CLM + logging bypass) — cross-referenced with Language Mode |
| AppLocker Cache | Checks AppCache.dat writability (cache poisoning vector) |

## Parameters
| Parameter | Description |
|---|---|
| `-AllTargets` | Scans Windows, ProgramData, Program Files, inetpub |
| `-Target` | Custom path(s) to scan |
| `-Output` | Export results to file |
| `-AsUser` | Simulate another user context (domain or local) |
| `-Groups` | Manually specify groups for the simulated user (bypasses LDAP) |

## Language Mode detection
Lockdown detects the current PowerShell Language Mode and surfaces actionable bypass paths:

| Mode | Meaning | Implication |
|---|---|---|
| `FullLanguage` | No restrictions | Clean execution environment |
| `ConstrainedLanguage` | CLM active | AppLocker likely enforced — PS v2 bypass if available, LOLBAS may still work |
| `RestrictedLanguage` | Severely restricted | No cmdlets, no variables |
| `NoLanguage` | Fully disabled | Script execution blocked |

When `ConstrainedLanguage` is detected and PowerShell v2 is available, Lockdown flags the combination as an actionable bypass vector.

## User context simulation
When `-AsUser` is provided, Lockdown resolves the target user's group memberships and runs the ACL scan as if executing from that account — without opening a session or generating logon events.

Resolution order:
1. **LDAP** — auto-resolves all groups including nested ones (domain accounts, requires domain connectivity)
2. **WinNT** — fallback for local accounts via `[ADSI]` (no domain required)
3. **Manual** — use `-Groups` to pass groups explicitly when neither LDAP nor WinNT is available
4. **Fallback** — `Authenticated Users` + `BUILTIN\Users` if all resolution methods fail

Group source is displayed in the header (`[LDAP]`, `[manuel]`, `[fallback]`, `[whoami]`) so you always know what the scan is based on.

## Requirements
- PowerShell 3+
- Low-priv user context (no admin required)
- Domain connectivity required for LDAP resolution (`-AsUser` on domain accounts)

## Disclaimer
For educational purposes and authorized engagements only.  
The author is not responsible for any misuse of this tool.  
Decepticons follow the rules. Sometimes.

---
*Part of the [Decepticons Suite](https://github.com/Starscream007)*  
Peace through Tyranny.
