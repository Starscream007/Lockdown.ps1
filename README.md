# Ravage

Execution-control reconnaissance for low-privilege contexts, in a single PowerShell pass with no external binary.

Ravage enumerates directories a low-priv user can **write to and execute from**, cross-references them against the effective AppLocker policy **and the Windows Defender posture**, and reports whether a bypass is even required — or whether the location is simply invisible to the AV. It is an enumeration and correlation tool, **not a novel bypass**. The writable locations it finds under `%WINDIR%` and `%PROGRAMFILES%` are well documented; the value here is getting the *correctness* and the *correlation* right, in one artifact that runs in a constrained shell.

Part of the Decepticons offensive tooling suite.

---

## What it does

In one run:

- **Effective Write+Execute ACL scan** per directory, resolved against the current user's group memberships (or a simulated principal).
- **AppLocker path correlation** — each writable+executable directory is tagged against the policy's Allow and Deny path rules.
- **Enforcement mode per rule collection** (Exe / Dll / Script / Msi / Appx) — tells you which bypass classes are actually enforced, and the rest of the output respects it (see below).
- **Windows Defender posture** — running mode, real-time / behavior / on-access / network protection, tamper protection, cloud (MAPS) and sample-submission level, and signature staleness. Read attacker-first: a protection that is **on** is an obstacle, **off** is a window.
- **ASR rules** — each configured Attack Surface Reduction rule reported by its action (Block / Audit / Warn / Disabled), so you see which classes are actually enforced versus merely logged.
- **Defender exclusions** — path / extension / process exclusions, when readable.
- **AMSI** — answers *is AMSI in place, and whose*. By default (read-only) it enumerates the registered AMSI providers (`HKLM\SOFTWARE\Microsoft\AMSI\Providers`), resolves each `InprocServer32` DLL, and reports whether a working provider is registered and whether it is Defender or a third party (and flags any registered provider whose DLL does not resolve — a degraded chain). An opt-in `-AmsiProbe` additionally feeds the benign AMSI test sentinel to AMSI in the current shell to confirm it is actually armed — the only way to catch userland/EDR hooking that registers no provider. See Limitations for what each layer can and cannot see.
- **AV-blind cross-reference** — any Write+Execute directory that also sits under a Defender `ExclusionPath` is flagged as a drop-and-run location where the AV is blind *and* execution control is permissive. This correlation is the point of the tool.
- **Bypass Candidates** — a summary of directories usable for execution in the current context.
- **LOLBAS availability** against the policy (`installutil`, `rundll32`, `regsvr32`, `mshta`, `wscript`, `cscript`, `msbuild`, `certutil`, `winget`, `regasm`).
- **PowerShell Language Mode** (Full / Constrained / Restricted / NoLanguage).
- **PowerShell v2** availability (registry + feature + .NET 3.5, three-state).
- **AppLocker cache** writability check (`AppCache.dat`).

---

## Design decisions

These are the choices that make the output trustworthy. They are opinions about scope, stated openly so you can disagree.

**"Write" means dropping a file, not creating a subdirectory.**
A directory is only counted as writable if the user has `WriteData` (file creation). `AppendData / AddSubdirectory` is explicitly *not* treated as write — it lets you create a subfolder, not drop a payload. For a drop-and-run scenario this removes a class of false positives. (General-purpose modifiable-path finders such as PowerUp intentionally count subdirectory creation; this tool does not, because the use case is narrower.)

**Write AND Execute, tested bitwise.**
A directory qualifies only if the effective access grants both file-drop and execute. Rights are tested with bitwise masks, including generic masks (`GENERIC_EXECUTE` `0x20000000`, `GENERIC_ALL` `0x10000000`) that the .NET `FileSystemRights` enum does not expand — a string match on `.ToString()` misses them. (PowerUp and accesschk also resolve generic masks; this is correctness, not novelty.)

**Canonical ACL evaluation.**
Effective access per right follows the Windows order: explicit Deny > explicit Allow > inherited Deny > inherited Allow. An explicit Allow correctly overrides an inherited Deny. ORing together Allow ACEs — a common shortcut — produces both false positives and false negatives.

**Deny path rules respected.**
AppLocker path precedence is Deny over Allow. A writable directory under an Allow path but also under a Deny path is **not** a candidate and is tagged `[AL:Deny-override]`.

**Enforcement mode drives the verdict.**
AppLocker only blocks execution when the relevant rule collection is `Enabled`. If the Exe collection is `NotConfigured` or `AuditOnly`, binaries run regardless of the rules — so allow-path membership becomes irrelevant. In that case every writable+executable directory is a usable drop-and-run location (tagged `[AL:not enforced]`) and LOLBAS binaries are reported as runnable, instead of being misreported as blocked. The tool does not assume enforcement; it reads it and applies it everywhere.

**Privileged principals are dropped by default.**
A directory writable by `Administrators`, `SYSTEM` or the operator groups is not a bypass — an admin disables AppLocker, it doesn't evade it. Those principals are removed from the match set by default (matched by SID, so this survives OS localization), which keeps an elevated run from flooding the output with locations no low-priv user can reach. Pass `-IncludePrivileged` for the raw, unfiltered view.

**Defender posture is read, not assumed.**
`Get-MpComputerStatus` / `Get-MpPreference` are readable by a standard user on a default configuration, so the posture section works from a low-priv context. Where it can't read (third-party AV took over, or the call is denied) it says so rather than guessing. Exclusions are the exception — see Limitations.

**The AV-blind cross-reference is the distinctive output.**
ACL scanning, LOLBAS checks and Language-Mode detection exist in other tools. What they don't give you is the *intersection*: a Write+Execute directory that is **also** a Defender exclusion. That is a location where you can drop a payload the AV will not scan and run it with execution control permissive — the highest-value result, surfaced on its own.

**Inherited directories are folded in the console, exhaustive on disk.**
A large writable tree produces one real fact (a writable root) and hundreds of inherited descendants that repeat it. The console folds each inherited descendant under its nearest explicit (or inherited-root) **anchor** and shows a `(+N inherited)` count — but only when the descendant exposes no principal beyond the anchor's, so a deeper directory that grants access to a *new* identity is never hidden. The `-Output` file keeps the full, un-collapsed list for the record.

**No external binary.**
Everything is native PowerShell. Nothing to drop on the target (which may itself be AppLocker-blocked or flagged), and it runs in a Constrained Language Mode shell.

---

## Usage

```powershell
# scan %WINDIR% (default)
./Ravage.ps1

# scan all default high-value targets
./Ravage.ps1 -AllTargets

# specific targets
./Ravage.ps1 -Target "C:\Windows","C:\ProgramData"

# export the full (un-collapsed) report to a file
./Ravage.ps1 -AllTargets -Output C:\results.txt

# simulate another principal (LDAP resolution of its groups)
./Ravage.ps1 -AsUser "DOMAIN\john"

# simulate with manually supplied groups (no LDAP)
./Ravage.ps1 -AsUser "DOMAIN\john" -Groups "DOMAIN\IT Staff","BUILTIN\Users"

# local account
./Ravage.ps1 -AsUser "MACHINE\localjohn"

# keep privileged principals in the match set (raw view)
./Ravage.ps1 -IncludePrivileged

# actively confirm whether AMSI is armed in this shell (generates an AMSI detection event)
./Ravage.ps1 -AmsiProbe
```

| Parameter            | Description                                                            |
|----------------------|------------------------------------------------------------------------|
| `-Target`            | One or more paths to scan. Defaults to `%WINDIR%`.                      |
| `-AllTargets`        | Scan the default high-value set (windir, ProgramData, Program Files, Program Files (x86), inetpub). |
| `-Output`            | Write the full, un-collapsed report to a text file in addition to the console. |
| `-AsUser`            | Simulate another user's access. Groups resolved via LDAP, or local via WinNT. |
| `-Groups`            | Supply the simulated user's groups manually (skips LDAP).              |
| `-IncludePrivileged` | Keep Administrators / SYSTEM / operator groups in the match set (default: dropped). |
| `-AmsiProbe`         | Actively test whether AMSI is armed in the current shell. **Generates an AMSI detection event** (possible EDR response) — opt-in, off by default. |

---

## Reading the output

Per-directory AppLocker tag:

| Tag                  | Meaning                                                        |
|----------------------|----------------------------------------------------------------|
| `[AL:Allow]`         | Enforced, and the directory sits under an Allow path.         |
| `[AL:Deny-override]` | Under an Allow path but also a Deny path — Deny wins, not usable. |
| `[AL:not in allow]`  | Enforced, writable+executable, but outside any Allow path.    |
| `[AL:not enforced]`  | The Exe collection is not Enabled — execution is not gated, the directory is usable regardless of rules. |
| `[explicit]` / `[inherited]` | Whether the granting ACE is explicit on the directory or inherited. |

Console folding:
- An anchor line may end with `(+N inherited)` — N inherited descendants share this location's access and are folded under it. The full list is in `-Output`.
- The footer reports `directories found | bypass candidates | anchors shown`.

Enforcement mode:
- `Enabled` — the collection is enforced; you need a bypass for that class.
- `AuditOnly` / `NotConfigured` — the class runs; logged only, or not checked at all.

Defender:
- Each protection is `ON` (obstacle) or `OFF` (window); `Tamper protection: OFF` means Defender can be disabled outright.
- ASR rules are reported by action: `Block` (enforced), `Audit` (logged, not blocked), `Warn` (user-bypassable), `Disabled`.
- AMSI: `AMSI active : Defender` / `Defender + third-party` / `third-party only, Defender absent` names a working provider and whose it is; `no working provider registered [effectively unarmed]` means none resolves; a `[degraded]` sub-line is a registered provider whose DLL is missing. With `-AmsiProbe`: `sentinel BLOCKED -> AMSI armed in this shell` (or `sentinel ran -> AMSI NOT armed`) is the active confirmation.
- `[!] W+X dirs under a Defender exclusion` lists the AV-blind drop-and-run locations — the correlation result.

---

## Requirements

- Windows PowerShell 5.x (falls back gracefully on PS7 where `GetAccessControl()` differs).
- No elevation required for the ACL, AppLocker-policy and Defender-posture reads.
- The PowerShell v2 *runtime* confirmation (`Get-WindowsOptionalFeature`) needs elevation; without it the check reports `unverified` rather than guessing.

---

## Limitations

- Enumeration only. It finds and validates locations; it does not execute anything.
- Enumeration works by **reading DACLs**. A directory where you have Write+Execute but not `READ_CONTROL` (you cannot read its security descriptor) is invisible to the tool — even though it may be a perfectly usable drop location, since write and execute do not require reading the DACL. Running elevated reads every DACL; as a plain low-priv user you only see the locations whose ACLs you are allowed to read.
- **Defender exclusions are hidden from standard users** (Defender has suppressed `Get-MpPreference` exclusions for non-admins since ~2021). Under a low-priv context the exclusion list — and therefore the AV-blind cross-reference, the tool's flagship output — will usually come back empty. An empty result means *unreadable*, not *none*; it only lights up when you are admin, or on a host where the exclusion registry ACL is permissive.
- The default AMSI check is **registration-based**: it reports which providers are registered and whether each provider's DLL resolves on disk. It does **not**, on its own, confirm AMSI is armed in the running process — an EDR that hooks AMSI in userland without registering a provider is invisible to it, so a clean registration verdict is not an AMSI all-clear.
- `-AmsiProbe` closes that gap but is **opt-in and active**: it feeds the benign AMSI test sentinel to AMSI in the current shell. If AMSI is armed the scan blocks it (that's the confirmation), which **generates an AMSI detection event** — on a real engagement the target's EDR may alert or auto-isolate the host. It is never run by default for that reason, not because of noise. The sentinel is assembled at runtime so the script file itself carries no flaggable string and is not quarantined on load. This is detection, not a bypass.
- ASR rules are reported by **action only**. The GUID→name mapping is not included, so you see a rule's enforcement state but not its friendly name.
- Covers AppLocker **path** rules. Publisher and Hash rules are not parsed — a binary allowed by a Publisher rule may be reported as `not in allow`.
- Default-rule writable directories under `%WINDIR%` are well-known; this tool confirms which ones *your* current context can actually use, it does not claim to discover new ones.
- Path construction trusts the `%WINDIR%` / `%PROGRAMFILES%` environment variables. On a host where those are poisoned (user-scope override), the scan targets will be wrong — resolve them from `HKLM\...\CurrentVersion\SystemRoot` if that is a concern.
- `-AsUser` LDAP resolution requires reachability of the domain from the host.

---

## License

MIT.

---

*"Conquest is made of the ashes of one's enemies."*
