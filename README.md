# Lockdown

AppLocker reconnaissance for low-privilege contexts, in a single PowerShell pass with no external binary.

Lockdown enumerates directories a low-priv user can **write to and execute from**, cross-references them against the effective AppLocker policy, and reports whether a bypass is even required. It is an enumeration and validation tool, **not a novel bypass**. The writable locations it finds under `%WINDIR%` and `%PROGRAMFILES%` are well documented; the value here is getting the *correctness* and the *correlation* right, in one artifact that runs in a constrained shell.

Part of the Decepticons offensive tooling suite.

---

## What it does

In one run:

- **Effective Write+Execute ACL scan** per directory, resolved against the current user's group memberships (or a simulated principal).
- **AppLocker path correlation**, each writable+executable directory is tagged against the policy's Allow and Deny path rules.
- **Enforcement mode per rule collection** (Exe / Dll / Script / Msi / Appx), tells you which bypass classes are actually enforced, and the rest of the output respects it (see below).
- **Bypass Candidates** - a deduplicated summary of directories usable for execution in the current context.
- **LOLBAS availability** against the policy (`installutil`, `rundll32`, `regsvr32`, `mshta`, `wscript`, `cscript`, `msbuild`, `certutil`, `winget`).
- **PowerShell Language Mode** (Full / Constrained / Restricted / NoLanguage).
- **PowerShell v2** availability (registry + feature + .NET 3.5, three-state).
- **AppLocker cache** writability check (`AppCache.dat`).

---

## Design decisions

These are the choices that make the output trustworthy. They are opinions about scope, stated openly so you can disagree.

**"Write" means dropping a file, not creating a subdirectory.**
A directory is only counted as writable if the user has `WriteData` (file creation). `AppendData / AddSubdirectory` is explicitly *not* treated as write - it lets you create a subfolder, not drop a payload. For a drop-and-run scenario this removes a class of false positives. (General-purpose modifiable-path finders such as PowerUp intentionally count subdirectory creation; this tool does not, because the use case is narrower.)

**Write AND Execute, tested bitwise.**
A directory qualifies only if the effective access grants both file-drop and execute. Rights are tested with bitwise masks, including generic masks (`GENERIC_EXECUTE` `0x20000000`, `GENERIC_ALL` `0x10000000`) that the .NET `FileSystemRights` enum does not expand, a string match on `.ToString()` misses them. (PowerUp and accesschk also resolve generic masks; this is correctness, not novelty.)

**Canonical ACL evaluation.**
Effective access per right follows the Windows order: explicit Deny > explicit Allow > inherited Deny > inherited Allow. An explicit Allow correctly overrides an inherited Deny. ORing together Allow ACEs - a common shortcut - produces both false positives and false negatives.

**Deny path rules respected.**
AppLocker path precedence is Deny over Allow. A writable directory under an Allow path but also under a Deny path is **not** a candidate and is tagged `[AL:Deny-override]`.

**Enforcement mode drives the verdict.**
AppLocker only blocks execution when the relevant rule collection is `Enabled`. If the Exe collection is `NotConfigured` or `AuditOnly`, binaries run regardless of the rules - so allow-path membership becomes irrelevant. In that case every writable+executable directory is a usable drop-and-run location (tagged `[AL:not enforced]`) and LOLBAS binaries are reported as runnable, instead of being misreported as blocked. The tool does not assume enforcement; it reads it and applies it everywhere.

**No external binary.**
Everything is native PowerShell. Nothing to drop on the target (which may itself be AppLocker-blocked or flagged), and it runs in a Constrained Language Mode shell.

---

## Usage

```powershell
# scan %WINDIR% (default)
./Lockdown.ps1

# scan all default high-value targets
./Lockdown.ps1 -AllTargets

# specific targets
./Lockdown.ps1 -Target "C:\Windows","C:\ProgramData"

# export results to a file
./Lockdown.ps1 -AllTargets -Output C:\results.txt

# simulate another principal (LDAP resolution of its groups)
./Lockdown.ps1 -AsUser "DOMAIN\john"

# simulate with manually supplied groups (no LDAP)
./Lockdown.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"

# local account
./Lockdown.ps1 -AsUser "MACHINE\localjohn"
```

| Parameter     | Description                                                            |
|---------------|------------------------------------------------------------------------|
| `-Target`     | One or more paths to scan. Defaults to `%WINDIR%`.                      |
| `-AllTargets` | Scan the default high-value set (windir, ProgramData, Program Files, Program Files (x86), inetpub). |
| `-Output`     | Write the full report to a text file in addition to the console.       |
| `-AsUser`     | Simulate another user's access. Groups resolved via LDAP, or local via WinNT. |
| `-Groups`     | Supply the simulated user's groups manually (skips LDAP).              |

---

## Reading the output

Per-directory AppLocker tag:

| Tag                  | Meaning                                                        |
|----------------------|----------------------------------------------------------------|
| `[AL:Allow]`         | Enforced, and the directory sits under an Allow path.         |
| `[AL:Deny-override]` | Under an Allow path but also a Deny path - Deny wins, not usable. |
| `[AL:not in allow]`  | Enforced, writable+executable, but outside any Allow path.    |
| `[AL:not enforced]`  | The Exe collection is not Enabled - execution is not gated, the directory is usable regardless of rules. |
| `[explicit]` / `[inherited]` | Whether the granting ACE is explicit on the directory or inherited. |

Enforcement mode:
- `Enabled` - the collection is enforced; you need a bypass for that class.
- `AuditOnly` / `NotConfigured` - the class runs; logged only, or not checked at all.

---

## Requirements

- Windows PowerShell 5.x (falls back gracefully on PS7 where `GetAccessControl()` differs).
- No elevation required for the ACL and AppLocker-policy reads.
- The PowerShell v2 *runtime* confirmation (`Get-WindowsOptionalFeature`) needs elevation; without it the check reports `unverified` rather than guessing.

---

## Limitations

- Enumeration only. It finds and validates locations; it does not execute anything.
- Enumeration works by **reading DACLs**. A directory where you have Write+Execute but not `READ_CONTROL` (you cannot read its security descriptor) is invisible to the tool - even though it may be a perfectly usable drop location, since write and execute do not require reading the DACL. Running elevated reads every DACL; as a plain low-priv user you only see the locations whose ACLs you are allowed to read.
- Covers AppLocker path rules. Publisher and Hash rules are not parsed - a binary allowed by a Publisher rule may be reported as `not in allow`.
- Default-rule writable directories under `%WINDIR%` are well-known; this tool confirms which ones *your* current context can actually use, it does not claim to discover new ones.
- Path construction trusts the `%WINDIR%` / `%PROGRAMFILES%` environment variables. On a host where those are poisoned (user-scope override), the scan targets will be wrong - resolve them from `HKLM\...\CurrentVersion\SystemRoot` if that is a concern.
- `-AsUser` LDAP resolution requires reachability of the domain from the host.

---

## License

MIT.

---

*"Conquest is made of the ashes of one's enemies."*
