# T1021.002 — Remote Services: SMB / Windows Admin Shares (psexec / smbexec)

## Summary

Impacket's `psexec.py` — and the `smbexec.py` / `wmiexec.py` family — move
laterally by abusing the SMB admin shares (`ADMIN$`, `C$`) and the Service
Control Manager: authenticate over SMB, drop a binary onto `ADMIN$`, register a
Windows service to execute it, run, and clean up.

Wazuh's built-in rule **61138** does flag the resulting service-installation
event (7045) — but at **level 5**, with **no content inspection**. A psexec
backdoor and a Windows Update component produce the identical low-severity
alert. This detection adds custom rule **100205**, a child of 61138 that
inspects the service's `imagePath` and escalates the psexec/smbexec signature
to **level 14**.

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares |
| T1543.003 | Create or Modify System Process: Windows Service |
| T1569.002 | System Services: Service Execution |

## The gap in built-in coverage

Built-in rule 61138 (`0590-win-system_rules.xml`):

```xml
<rule id="61138" level="5">
  <if_sid>61100</if_sid>
  <field name="win.system.eventID">^7045$</field>
  <description>New Windows Service Created</description>
  <mitre><id>T1543.003</id></mitre>
</rule>
```

- Level 5 — informational; no analyst gets paged on it
- No filter on `imagePath`, `serviceName`, or account — every service install
  looks identical, legitimate or malicious
- Tagged only T1543.003 — no lateral-movement (T1021.002) context

The System event channel was confirmed forwarding (rules 61102/61104 had
fired), so no agent reconfiguration was needed — only the missing detection
logic.

## Detection logic — rule 100205

```xml
<rule id="100205" level="14">
  <if_sid>61138</if_sid>
  <field name="win.eventdata.imagePath" type="pcre2">(?i)(cmd\.exe|%comspec%|powershell|\\\\Temp\\\\|\\\\PerfLogs\\\\|\\\\Users\\\\Public\\\\|\\\\Downloads\\\\|\\\\Windows\\\\[^\\]+\.exe|%systemroot%\\\\[^\\]+\.exe)</field>
  <description>High-confidence: Suspicious Windows service installed ($(win.eventdata.serviceName)) - binary is a command interpreter or sits in a non-standard path (psexec/smbexec lateral movement signature)</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1021.002</id>
    <id>T1543.003</id>
    <id>T1569.002</id>
  </mitre>
  <group>lateral_movement,execution,attack,T1021,T1021.002,T1543.003,T1569.002,psexec,service,</group>
</rule>
```

The rule is a child of 61138 (so it only ever sees real 7045 events) and adds
one `imagePath` content filter. The pattern catches two distinct attacker
signatures:

| Signature | Tool | Why it is suspicious |
|-----------|------|----------------------|
| `imagePath` contains `cmd.exe` / `%comspec%` / `powershell` | smbexec.py | A service whose binary *is a command interpreter* — legitimate services run a real binary, not a shell |
| Bare `<random>.exe` directly in `C:\Windows\` or `%systemroot%\` | psexec.py | psexec drops its service binary into the Windows root via `ADMIN$` — legit service binaries live in `System32`, `Program Files`, or a vendor subdirectory |
| Binary under `\Temp\`, `\PerfLogs\`, `\Users\Public\`, `\Downloads\` | various | Service binary staged in a user-writable / non-standard path |

### The key regex detail

```
\\Windows\\[^\]+\.exe        and        %systemroot%\\[^\]+\.exe
```

`[^\\]+` matches one path segment that **cannot cross a separator**. So it
matches `C:\Windows\kGeNDLMz.exe` (psexec's drop) but **not**
`C:\Windows\System32\svchost.exe` — a legitimate System32 service binary has a
`\` after `Windows`, which the character class refuses to cross. This is what
keeps the rule from drowning in false positives on normal Windows services.

## Empirical validation

Attack run from the Wazuh manager (192.168.18.132, acting as attacker) against
the Windows endpoint (192.168.18.134), using a throwaway local-admin account
`labtest`:

```
python3 .../impacket/examples/psexec.py labtest:***@192.168.18.134
[*] Found writable share ADMIN$
[*] Uploading file kGeNDLMz.exe
[*] Creating service zIqO on 192.168.18.134
[*] Starting service zIqO
```

| Event on endpoint | Built-in rule | Custom rule |
|-------------------|---------------|-------------|
| Service `zIqO` installed, `imagePath` = `%systemroot%\kGeNDLMz.exe` | 61138 — level 5 | **100205 — level 14** |

The 100205 alert fired with `serviceName: zIqO` and
`imagePath: %systemroot%\kGeNDLMz.exe` — the random-binary-in-Windows-root
branch of the regex matched on the first attempt. The built-in 61138 and the
custom 100205 both fired on the *same* 7045 event; the analyst now sees a
level-14 lateral-movement alert instead of a level-5 informational one.

## Engineering notes

- **Schema-first design.** Before writing the rule, a benign service was
  installed with `sc.exe create` purely to capture the real 7045 field schema
  (`win.eventdata.imagePath`, `serviceName`, `serviceType`, `accountName`).
  Designing against confirmed field names — rather than guessing — meant the
  rule fired correctly on the first live test.
- **Remote UAC.** psexec with a *local* admin account fails with
  `ACCESS_DENIED` on Windows 11 by default — "Remote UAC" strips the admin
  token from local accounts authenticating over the network. The test set
  `LocalAccountTokenFilterPolicy = 1` to allow it. In a real domain
  environment this filtering does not apply to domain accounts, so the attack
  path is realistic; the registry change simply reproduces it in a
  workgroup lab.

## Limitations

- **`imagePath` evasion.** An attacker who names the service binary to look
  legitimate *and* places it under `System32` would evade the path branches.
  The `cmd.exe`/`powershell` branch still catches smbexec-style execution, and
  defence-in-depth (Sysmon process-creation rules on the service binary
  spawning `cmd.exe`) would cover the gap — out of scope here.
- **Default tool config only.** Tested against Impacket `psexec.py` with
  default options. Operators can supply a custom service name and binary path
  (`-service-name`, custom upload path); a binary placed in `System32` with a
  plausible name would not match.
- **No correlation with the SMB logon.** This rule keys purely on the 7045
  service-install event. It does not (yet) correlate with the preceding
  network logon (4624 type 3) from the same source IP — a correlated version
  would be higher-confidence still.
- **Single-host lab.** Attacker and victim were two hosts on one subnet; the
  attacker box was the Ubuntu Wazuh manager rather than a dedicated Kali host.
  Impacket behaves identically regardless of attacker OS.

## Files

| File | Purpose |
|------|---------|
| `rule.xml` | Wazuh custom rule 100205 |
| `test/setup-and-trigger.md` | Environment prep + attack reproduction |
| `evidence/` | Dashboard / terminal proof |

## References

- MITRE ATT&CK — [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)
- Impacket — `psexec.py`, `smbexec.py`
- Windows event 7045 — Service Control Manager, "A service was installed in the system"
