# T1053.005 — Scheduled Task / Job: Scheduled Task

**Status:** Complete
**Detection rule:** `100203`, level 14
**MITRE technique:** T1053.005 (Scheduled Task/Job: Scheduled Task)
**Tactics:** Persistence, Execution, Privilege Escalation
**Telemetry source:** Windows Security log, EID 4698 (Scheduled task created)

## Summary

Wazuh ships a built-in rule (`60228`) for EID 4698 — scheduled task creation — that fires on *every* task regardless of content, at level 4 (informational). It produces high-volume, low-fidelity alerts because Windows itself creates legitimate scheduled tasks constantly (Updates, Defender, telemetry, etc.). This writeup documents the layered detection:

1. A Windows-side telemetry fix: the "Other Object Access Events" audit subcategory is **off by default on Win 11**, so EID 4698 isn't even being generated until enabled.
2. A custom Wazuh rule (`100203`, level 14) that layers on `60228` via `if_sid` and filters the Task Content XML for suspicious interpreters and paths — escalating real risk while leaving 60228's level-4 noise channel intact for everything else.

Two engineering details worth surfacing:

- **PCRE2 dot-matches-newlines gotcha**: the Task Content XML in `win.system.message` spans multiple lines with `\r\n` between `<Command>` and `<Arguments>`. A naïve `powershell\.exe.{0,300}-windowstyle\s+hidden` regex fails because `.` doesn't match newlines without the `(?s)` flag. Discovered empirically: rule didn't fire on the first test, switched `(?i)` → `(?is)`, fired correctly.
- **Wazuh `if_sid` supersession**: when a child rule (100203) matches an event that also matched its parent (60228), Wazuh suppresses the parent alert. So our alert pipeline produces one high-fidelity 100203 *or* one low-fidelity 60228, never both for the same event — clean partition without duplicate alerts.

## Detection target

T1053.005 covers adversary use of the Windows Task Scheduler to establish persistence, gain execution at boot/logon, or escalate privileges via scheduled tasks running as SYSTEM. Typical adversary patterns in the Task Content XML:

- `<Command>` invoking script interpreters: `powershell.exe`, `cmd.exe /c powershell`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`
- `<Arguments>` with PowerShell evasion flags: `-WindowStyle Hidden`, `-NoProfile`, `-NoNi`, `-EncodedCommand`, `-ExecutionPolicy Bypass`
- LOLBin abuse: `certutil.exe -urlcache/-decode/-encode`, `rundll32.exe ... javascript:...`, `hh.exe` for compiled help file execution
- Payload paths in writable user directories: `\Temp\`, `\AppData\Local\Temp\`, `\Users\Public\`, `\Downloads\`, `\ProgramData\`

## Audit findings: Wazuh built-in 60228

Located in `/var/ossec/ruleset/rules/0580-win-security_rules.xml`:

```xml
<rule id="60228" level="4">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4698$</field>
    <description>A scheduled task was created</description>
    <options>no_full_log</options>
    <mitre><id>T1053</id></mitre>
</rule>
```

Three gaps:

1. **No content filtering.** Fires on every task creation — including Microsoft Defender's periodic scans, Windows Update maintenance, OneDrive sync setup. Will drown analysts in noise at scale.
2. **Level 4 (informational).** SIEM dashboards typically suppress level-4 alerts entirely or aggregate them. A real T1053.005 attack would never get attention.
3. **MITRE tag is T1053 parent**, not T1053.005 sub-technique. Loses specificity that ATT&CK navigators expect.

Pre-fix baseline confirmation: `grep -c '"id":"60228"' /var/ossec/logs/alerts/alerts.json` returned `0`. The rule had never fired in this lab — pointing to a telemetry gap below the rule.

## Windows audit policy: EID 4698 disabled by default

Querying Sysmon and the Wazuh agent on the endpoint confirmed events of other types were flowing normally. EID 4698 specifically wasn't being logged. Root cause: Windows 11 ships with the audit subcategory **"Other Object Access Events"** set to *No Auditing* by default. Scheduled task lifecycle events (4698 created, 4699 deleted, 4700 enabled, 4701 disabled, 4702 modified) all require this subcategory to be enabled.

Fix, run once on each endpoint:

```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Takes effect immediately, no reboot. Verified by creating a benign test task (`schtasks /create /tn "WazuhSchTaskTest_Benign" ...`) and confirming 60228 fired on the manager.

## The Wazuh rule

Custom rule 100203, in `rule.xml`:

```xml
<rule id="100203" level="14">
    <if_sid>60228</if_sid>
    <field name="win.system.message" type="pcre2">(?is)(\\\\Temp\\\\|\\\\AppData\\\\Local\\\\Temp\\\\|\\\\Users\\\\Public\\\\|\\\\Downloads\\\\|powershell\.exe.{0,300}(-windowstyle\s+hidden|-w\s+hidden|-nop\b|-noprofile|-noni\b|-ep\s+bypass|-enc(odedcommand)?)|mshta\.exe|certutil\.exe.{0,100}-(urlcache|decode|encode)|rundll32\.exe.{0,200}javascript|wscript\.exe|cscript\.exe|hh\.exe)</field>
    <description>High-confidence: Scheduled task created invoking suspicious interpreter or pointing to suspicious path (T1053.005 + T1059)</description>
    <mitre>
        <id>T1053.005</id>
        <id>T1059</id>
    </mitre>
    <group>persistence,execution,attack,T1053,T1053.005,T1059,scheduled_task,</group>
</rule>
```

Design choices:

- **`if_sid 60228`** — layers on the built-in. Inherits the EID 4698 match, adds content filtering. Wazuh's supersession means the built-in's level-4 alert is replaced by our level-14 alert when content matches.
- **`win.system.message` regex** — the Task Content XML (with `<Command>` and `<Arguments>` blocks) is embedded as a string inside the message field. Matching against the message is cheaper than writing a dedicated decoder to extract the XML.
- **`(?is)` flags** — `i` for case-insensitive, `s` for DOTALL (`.` matches newlines). The DOTALL flag is essential because the Task Content XML has `\r\n` between `<Command>` and `<Arguments>`, and our proximity check `powershell\.exe.{0,300}-windowstyle` would otherwise fail across that newline.
- **Level 14** — high-confidence signal worthy of immediate analyst attention, two ticks above the built-in's level 4.
- **Three MITRE techniques tagged**: `T1053.005` (Scheduled Task) primary, `T1059` (Command and Scripting Interpreter) implicit. PowerShell-via-scheduled-task is a chain across both.

## Empirical validation

Three tasks created in sequence to validate partitioning:

| Task | Content | Built-in 60228 | Custom 100203 |
|------|---------|----------------|---------------|
| `WazuhSchTaskTest_Benign` | `cmd /c echo hello` | fires (level 4) | does not fire — no suspicious indicator |
| `WazuhSchTaskTest_Suspicious` (pre-`(?s)` fix) | `powershell -WindowStyle Hidden -NoProfile -EncodedCommand <b64>` | fires (level 4) | does not fire — regex bug, `.` didn't match `\r\n` |
| `WazuhSchTaskTest_Suspicious2` (post-`(?s)` fix) | same pattern as above | suppressed by 100203 | fires (level 14) |

After fix:
- `60228 count = 2` (benign + first suspicious, both fired before our rule started catching)
- `100203 count = 1` (Suspicious2, after regex fix)

The if_sid supersession is visible in the count: Suspicious2's event matched both 60228 and 100203, but only 100203 was written to alerts.json. That's the desired behaviour — analysts see exactly one alert per task, at the correct severity for its content.

See `evidence/` for the dashboard screenshot of the 100203 alert.

## Limitations

1. **String-regex against XML is fragile.** A future Windows version could change Task Content XML layout (whitespace, element order, namespaces) and break the proximity matches. A more robust approach would be to write a Wazuh decoder that parses the XML into structured fields, but the maintenance burden outweighs the value for a portfolio lab. Production deployments should consider Sigma rules with structured matchers if the underlying SIEM supports them.
2. **Coverage list, not full taxonomy.** The regex covers known practitioner patterns (PowerShell evasion, common LOLBins, writable-path payloads). Novel interpreters or living-off-the-land binaries added to the offensive toolkit will slip through until the regex is updated.
3. **Modification events not covered.** Adversaries can also modify *existing* scheduled tasks (EID 4702) to add a malicious action — a different evasion path. This rule only addresses creation. A symmetric rule for 4702 (with broadly similar content checks) would complete coverage.
4. **No author/principal heuristics.** Tasks created by non-admin user accounts or anomalous principals can also be suspicious, even with benign content. Future iteration could add `subjectUserName` checks against an allowlist.

## Files in this folder

| File | Purpose |
|------|---------|
| `README.md` | This writeup |
| `rule.xml` | Wazuh custom rule 100203 |
| `test/setup-and-trigger.md` | Endpoint commands to enable audit policy and trigger benign/suspicious test events |
| `evidence/01-100203-event-list.png` | Wazuh dashboard: 100203 alert showing 1 hit at level 14 |
| `evidence/02-terminal-empirical-proof.png` | Terminal: alerts.json grep showing partitioning (60228 = 2, 100203 = 1) |

## Application

```bash
# On Wazuh manager
sudo cp rule.xml /var/ossec/etc/rules/local_rules.xml   # or merge into existing
sudo systemctl restart wazuh-manager
```

```cmd
:: On each Windows endpoint (one-time)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

## References

- [MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft: Audit Other Object Access Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events)
- [Microsoft: Event 4698 (Security) — A scheduled task was created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)
- [Wazuh Rule Syntax — `if_sid` and rule hierarchy](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
