# T1059.001 — Encoded PowerShell with Evasion Flags

**Status:** Working, verified end-to-end
**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell), [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)
**Severity:** Level 14 (high-confidence overlay above Wazuh built-in rule 92057)

## What this detects

PowerShell launched with `-EncodedCommand <base64>` **and** at least one evasion flag (`-WindowStyle Hidden`, `-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass`, including short forms).

Attackers routinely combine base64 encoding with evasion flags to suppress user-visible artifacts and bypass execution policy. Wazuh's default ruleset already catches the encoding pattern alone at level 12; this rule adds a high-confidence overlay that escalates to level 14 when the combined pattern is observed, which is rare in legitimate scripts.

## The engineering arc

### v1: First attempt — did not fire

The initial rule chained off `if_sid 61603` (intended as the Sysmon Event ID 1 parent) and matched any command line containing `-enc`, `-encodedcommand`, or `-ec` followed by 20+ base64 characters at level 12.

```xml
<rule id="100200" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand|-ec)\s+[A-Za-z0-9+/=]{20,}</field>
  ...
</rule>
```

**Test:** `powershell.exe -EncodedCommand <base64>` on the Windows endpoint.
**Result:** An alert fired in the dashboard at level 12, but `rule.id = 92057`, **not** 100200.

### Discovery: built-in rule 92057 already covered this

Wazuh's default ruleset includes a dedicated rule for the same behaviour:

- **Rule ID:** 92057
- **Description:** "Powershell.exe spawned a powershell process which executed a base64 encoded command"
- **Groups:** `sysmon`, `sysmon_eid1_detections`, `windows`
- **MITRE:** T1059.001
- **Level:** 12

The v1 custom rule never fired because `if_sid 61603` is not in the parent chain that leads to 92057 in Wazuh 4.13.1's ruleset — 92057 lives under `sysmon_eid1_detections`, which has a different parent. The custom rule loaded successfully but never matched any event.

**Takeaway:** Audit built-in coverage before writing custom detections. Custom rules should *add value*, not duplicate work that ships with the platform.

### v2: Refactored as a high-confidence overlay

Rather than replace 92057, v2 chains off it. The custom rule only evaluates once 92057 has already confirmed an encoded PowerShell process, and then escalates the alert if the command line also contains evasion flags.

```xml
<rule id="100200" level="14">
  <if_sid>92057</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-windowstyle\s+hidden|-w\s+hidden|-nop\b|-noprofile\b|-noni\b|-noninteractive\b|-ep\s+bypass|-executionpolicy\s+bypass)</field>
  <description>High-confidence: Encoded PowerShell with evasion flags (T1059.001 + T1027)</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
  <group>powershell,attack,T1059,T1027,defense_evasion,</group>
</rule>
```

Design decisions:

- **`if_sid 92057`** — chain off the built-in rule. The custom rule only evaluates once an encoded PowerShell event is already confirmed, avoiding duplicate regex work and reducing false-positive surface.
- **Evasion-flag regex** — covers long and short forms of `-WindowStyle Hidden`, `-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass`. Each is independently rare in legitimate use.
- **Level 14** — escalates above the built-in's 12 to surface high-severity tradecraft on the dashboard.
- **MITRE T1027 added** — encoded *plus* evasion is textbook obfuscation, beyond execution alone.

## Verification

### Test 1 — Encoded only

```
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAGUAbgBjAG8AZABlAGQAIABwAG8AdwBlAHIAcwBoAGUAbABsACEAIgA=
```

Expected: Rule 92057 fires (level 12). Rule 100200 stays quiet.
Observed: Single alert at `18:56:28` for rule 92057, level 12. Rule 100200 did not fire. ✓

### Test 2 — Encoded plus evasion flags (run twice for reproducibility)

```
powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAGUAbgBjAG8AZABlAGQAIABwAG8AdwBlAHIAcwBoAGUAbABsACEAIgA=
```

Expected: Both 92057 (level 12) and 100200 (level 14) fire each time.
Observed: 100200 fired at `19:17:59` and `19:18:53`, both at level 14, alongside 92057. ✓

The decoded payload in both tests is harmless (`Write-Host "Hello from encoded powershell!"`). The detection fires on the *pattern*, not the payload.

## Evidence

| File | What it shows |
|---|---|
| `evidence/01-dashboard-overview.png` | Threat Hunting dashboard with the alert spike |
| `evidence/02-rule-100200-empty-v1.png` | v1 rule produced no hits (filter `rule.id:100200`) |
| `evidence/03-built-in-92057-fired.png` | Discovery: built-in rule 92057 caught the encoded command |
| `evidence/04-rule-100200-fired-v2.png` | After refactor: rule 100200 firing at level 14 alongside 92057 |

## Files

- `rule.xml` — the deployed rule. In production it lives inside the `<group>` wrapper in `/var/ossec/etc/rules/local_rules.xml` on the manager.
- `README.md` — this writeup.
- `evidence/` — dashboard screenshots from testing.

## Lab context

- **Wazuh manager:** 4.13.1 on Ubuntu 26.04 ARM64 (all-in-one)
- **Endpoint:** Windows 11 ARM (Insider build 26200.5074), user account, no privilege escalation
- **Telemetry:** Sysmon ARM64 with SwiftOnSecurity configuration, shipping via the Wazuh agent's `Microsoft-Windows-Sysmon/Operational` localfile
- **Parent rule 92057:** ships with Wazuh's default `sysmon_eid1_detections` ruleset
