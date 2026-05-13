# T1003.001 — OS Credential Dumping: LSASS Memory

**Status:** Complete
**Detection rule:** `100202`, level 14
**MITRE technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Tactic:** Credential Access
**Telemetry source:** Sysmon ProcessAccess (EID 10)

## Summary

Wazuh ships a built-in rule (`92900`) covering T1003.001 — level 12, MITRE-tagged correctly — that looks legitimate at a glance. This writeup documents the layered investigation that revealed why it had never fired in this lab, and the multi-part fix:

1. The built-in's `grantedAccess` regex only catches two access masks (`0x1010`, `0x40`), covering classic mimikatz but missing every modern dumping signature (procdump, Task Manager dump, comsvcs.dll MiniDump, Cobalt Strike variants).
2. The active Sysmon config had no ProcessAccess section at all, so EID 10 telemetry was never collected — the built-in could not fire even on the masks it does support.
3. SwiftOnSecurity's current master config (the industry-standard baseline) ships ProcessAccess intentionally empty due to system-load concerns. "Use SwiftOnSecurity" therefore does not automatically enable T1003.001 telemetry.
4. Windows 11's LSA Protection (`RunAsPPL=1`, enabled by default) prevents non-PPL processes from opening lsass with high access rights AND prevents Sysmon from logging the failed attempt. The rule only fires once an adversary has already disabled or bypassed PPL.

The fix has two parts: a Sysmon config patch (`sysmon-patch.xml`) that enables targeted ProcessAccess monitoring for lsass, and a custom Wazuh rule (`rule.xml`, ID 100202) that extends grantedAccess coverage to modern dumping masks.

## Detection target

T1003.001 covers credential extraction from lsass.exe process memory. Common implementations and their typical Sysmon GrantedAccess signatures:

- **mimikatz** `sekurlsa::logonpasswords` — `0x1010` (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ as reported by Sysmon)
- **procdump** — `0x1FFFFF` (PROCESS_ALL_ACCESS)
- **Task Manager** "Create Dump File" — `0x1FFFFF`, fully signed Microsoft tooling
- **comsvcs.dll MiniDump** via `rundll32` — `0x1F1FFF`, a signed-LOLBin technique
- **Cobalt Strike** `hashdump` and SharpDump variants — `0x1410`, `0x1438`, `0x143A`
- **PROCESS_DUP_HANDLE-based handle stealing** — `0x40`

A detection that catches only the mimikatz mask leaves the most common practitioner tools (procdump, Task Manager, comsvcs) uncovered.

## Audit findings: Wazuh built-in 92900

Located in `/var/ossec/ruleset/rules/0945-sysmon_id_10.xml`:

```xml
<rule id="92900" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)(0x1010|0x40)</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(C:\\\\Program Files|wmiprvse\.exe)</field>
    <description>Lsass process was accessed by $(win.eventdata.sourceImage) with read permissions, possible credential dump</description>
    <mitre><id>T1003.001</id></mitre>
</rule>
```

The `grantedAccess` regex is the bottleneck: it matches `0x1010` and `0x40` only. Everything else — `0x1FFFFF`, `0x1F1FFF`, `0x1F0FFF`, `0x1410`, `0x1438`, `0x143A` — passes through silently.

Pre-fix baseline confirmation: running `grep '"id":"92900"' /var/ossec/logs/alerts/alerts.json | wc -l` and `zgrep` across all rotated archives both returned `0`. **The rule had never fired in the lab's entire history.**

## Investigation: why hasn't it ever fired?

Initial hypothesis was the access-mask gap alone: Defender constantly accesses lsass, but Defender lives under `C:\Program Files\Windows Defender\`, which the rule's sourceImage allowlist excludes — so Defender's accesses wouldn't fire 92900 even if their masks matched.

But adversary-shaped accesses from non-Program-Files sources should still trigger it on `0x1010`. None had. Querying the Sysmon log directly on the endpoint to investigate:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath '*[System[EventID=10]]' -MaxEvents 100
# -> ObjectNotFound: No events were found that match the specified selection criteria
```

**Zero Sysmon EID 10 events. Ever.** Sysmon was running and producing other event types (1, 5, 11, 13, 22 all confirmed in the live log), but ProcessAccess was not being captured at all.

## Discovery: SwiftOnSecurity ships ProcessAccess empty

Dumping the active Sysmon config (`Sysmon64a.exe -c`) and grepping for `ProcessAccess` returned no rule definitions. Pulling SwiftOnSecurity's current master config to inspect the source:

```xml
<!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
<!--COMMENT:    Can cause high system load, disabled by default.-->
<ProcessAccess onmatch="include">
    <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ProcessAccess>
```

SwiftOnSecurity's master ships ProcessAccess **intentionally empty**, with explicit performance rationale. The "industry-standard baseline" everyone reaches for does not enable T1003.001 telemetry out of the box. Detection engineers have to make a deliberate call about whether to incur the event volume.

## The Sysmon config patch

Added a minimal ProcessAccess section in place of SwiftOnSecurity's empty one (full content in `sysmon-patch.xml`):

```xml
<ProcessAccess onmatch="include">
    <TargetImage name="T1003.001,credential_access" condition="image">lsass.exe</TargetImage>
</ProcessAccess>
<ProcessAccess onmatch="exclude">
    <SourceImage condition="end with">\MsMpEng.exe</SourceImage>
    <SourceImage condition="end with">\MsSense.exe</SourceImage>
    <SourceImage condition="end with">\csrss.exe</SourceImage>
    <SourceImage condition="end with">\wininit.exe</SourceImage>
    <SourceImage condition="end with">\services.exe</SourceImage>
    <SourceImage condition="end with">\TrustedInstaller.exe</SourceImage>
    <SourceImage condition="end with">\SearchIndexer.exe</SourceImage>
</ProcessAccess>
```

Design choices:

- **TargetImage include for lsass only**, not a broader process set. Other Sysmon EID 10 use cases (injection into browsers, mstsc.exe access for clipboard credential theft) belong in separate rule groups. Scope discipline reduces the system-load concern that motivated SwiftOnSecurity's default.
- **Sysmon `name=` attribute set to `T1003.001,credential_access`**. The `name` value propagates to the `RuleName` field on the event, giving analysts an at-a-glance MITRE tag on the raw event before any Wazuh rule has matched. Useful for SIEM-side filtering and triage.
- **Exclude list curated by category**: Defender stack (MsMpEng, MsSense), Windows session/service core (csrss, wininit, services, TrustedInstaller), search-related noise (SearchIndexer). Not exhaustive — production deployment would extend this based on observed baseline traffic.

## Discovery: LSA Protection blocks both access and telemetry

With Sysmon now capturing EID 10, running the test harness (`Test-LsassAccess`, see `test/Test-LsassAccess.ps1`) to generate clean events with known access masks. Both calls returned Win32 error 5 (ACCESS_DENIED):

```
[*] Opening lsass (PID 748) with access mask 0x1FFFFF...
[!] OpenProcess FAILED. Win32 error code: 5
[*] Opening lsass (PID 748) with access mask 0x1010...
[!] OpenProcess FAILED. Win32 error code: 5
```

Windows 11 enables **LSA Protection** (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`) by default. This makes lsass a Protected Process Light. Non-PPL callers (like our PowerShell session) cannot open it with elevated access rights regardless of administrator status or `SeDebugPrivilege`.

More importantly: Sysmon also did not log the failed attempts. Querying the Sysmon log for our PowerShell→lsass events returned zero results. Background `svchost.exe → lsass` accesses that *did* succeed appeared, confirming Sysmon was instrumented correctly. **The PPL denial happens before Sysmon's logging path**, which means Sysmon ProcessAccess telemetry only reflects accesses that were actually granted.

### Defensive implication

A real-world finding worth surfacing: **on hardened Win 11 endpoints, Sysmon EID 10 against lsass shows only successful opens.** Failed credential-dumping attempts from non-PPL adversaries leave no trace. Detection therefore fires on:

- Adversaries who have already disabled LSA Protection (T1562.001 — Impair Defenses)
- Adversaries who have loaded a vulnerable signed driver to bypass PPL (BYOVD)
- Adversaries operating from a process that registers as PPL via ELAM

In other words, the rule catches the population we most care about — attackers who have already made it past Windows' default credential-access hardening. Unhardened endpoints (PPL disabled) will produce telemetry for any attempt.

For empirical testing in this lab, LSA Protection was temporarily disabled (`RunAsPPL=0`, reboot), tests were re-run, and Protection was re-enabled afterward (`RunAsPPL=2`, reboot) to keep the lab representative of real-world defaults.

## The Wazuh rule

Custom rule 100202, in `rule.xml`:

```xml
<rule id="100202" level="14">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)(0x1f1fff|0x1fffff|0x1f0fff|0x1410|0x1438|0x143a)</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(C:\\\\Program Files|wmiprvse\.exe|csrss\.exe|wininit\.exe|services\.exe|TrustedInstaller\.exe|SearchIndexer\.exe|MsMpEng\.exe|MsSense\.exe)</field>
    <description>Lsass accessed by $(win.eventdata.sourceImage) with mask $(win.eventdata.grantedAccess) - modern credential dumping signature (procdump/Task Manager/comsvcs class)</description>
    <mitre><id>T1003.001</id></mitre>
    <group>credential_access,attack,T1003,T1003.001,lsass,</group>
</rule>
```

Design choices:

- **Complementary, not replacement.** The rule deliberately does NOT match `0x1010` or `0x40` — those stay 92900's territory. No double-alerts on the same event. The two rules together partition the dumping-mask space.
- **Level 14, vs 92900's level 12.** PROCESS_ALL_ACCESS to lsass is a stronger signal than `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`. The masks 100202 covers are used by tools whose entire purpose is dumping; `0x1010` has more legitimate-process noise around it (see Operational noise below).
- **Broader sourceImage allowlist than 92900.** Adds `MsMpEng.exe`, `MsSense.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `TrustedInstaller.exe`, `SearchIndexer.exe` on top of the Program Files prefix exclusion. These are the System32-resident accessors that the Program Files filter misses.
- **`$()` interpolation in the description.** Wazuh substitutes `$(win.eventdata.sourceImage)` and `$(win.eventdata.grantedAccess)` at alert time, so the alert summary reads cleanly without needing to drill into eventdata.

## Empirical validation

With LSA Protection disabled in the lab, Test-LsassAccess was invoked with both masks. Sysmon captured both events with our `T1003.001,credential_access` RuleName tag. Wazuh's rule engine produced exactly two alerts, perfectly partitioned:

| Test mask | Sysmon EID 10 captured | Wazuh alert |
|-----------|-----------------------|-------------|
| `0x1FFFFF` (procdump-class) | yes, sourceImage=powershell.exe, targetImage=lsass.exe | rule **100202**, level 14 |
| `0x1010` (mimikatz-class) | yes, sourceImage=powershell.exe, targetImage=lsass.exe | rule **92900**, level 12 |

Both Sysmon events were logged 8ms apart with sequential eventRecordIDs (15532, 15533), same source PID (10244), same target lsass PID (776). The only field that differed was `grantedAccess`. The split alerting demonstrates that the gap was purely a coverage issue with the built-in's regex — same actor, same target, exactly the same defensive blind spot.

See `evidence/` for screenshots of both events, both alerts, and the terminal grep showing per-rule counts and full alert bodies.

### Operational noise

92900 also fired twice on background `svchost.exe → lsass` accesses (visible in `evidence/05-92900-event-list-24h.png`). These are legitimate Windows service-host operations using `0x1010` or `0x40` from outside Program Files, which 92900's allowlist doesn't cover. Production tuning would extend 92900's sourceImage exclude to filter these, or override the built-in with a tuned variant. That is a separate exercise from the gap-coverage problem this rule addresses.

## Limitations

1. **PPL-blocked attempts leave no telemetry.** Failed credential-dumping attempts on hardened endpoints do not generate Sysmon EID 10 events, so this rule cannot detect them. It detects successful opens, which on a hardened endpoint implies the adversary has already disabled or bypassed LSA Protection.
2. **Access-mask coverage is empirically derived, not exhaustive.** The six masks in the regex cover known practitioner tools as of authoring. New dumping tools may use novel mask combinations that will not trigger this rule. Periodic review against current red-team tooling is required.
3. **SourceImage allowlist is conservative.** Designed to suppress core Windows noise without over-excluding. A determined adversary running a Living-off-the-Land Binary from System32 might evade detection if its image is added to the allowlist. The allowlist should be revisited as the threat landscape shifts.
4. **Single-endpoint validation.** Tested on Win 11 ARM Insider (build 26200.5074). Mask values for credential dumpers should be consistent across architectures, but other Windows builds may expose subtle differences in legitimate accessor behaviour.

## Files in this folder

| File | Purpose |
|------|---------|
| `README.md` | This writeup |
| `rule.xml` | Wazuh custom rule 100202 |
| `sysmon-patch.xml` | The ProcessAccess RuleGroup added to the Sysmon config |
| `test/Test-LsassAccess.ps1` | PowerShell harness for generating EID 10 events with chosen access masks |
| `evidence/01-100202-event-list.png` | Wazuh dashboard: 100202 alert in list view |
| `evidence/02-100202-eventdata.png` | Wazuh dashboard: 100202 eventdata (grantedAccess 0x1fffff, sourceImage, targetImage) |
| `evidence/03-100202-system-fields.png` | Wazuh dashboard: 100202 Sysmon system fields (EID 10, channel, computer) |
| `evidence/04-100202-rule-metadata.png` | Wazuh dashboard: 100202 rule metadata (level 14, MITRE T1003.001) |
| `evidence/05-92900-event-list-24h.png` | Wazuh dashboard: 92900 over 24h (2 PowerShell tests + 2 svchost background) |
| `evidence/06-92900-eventdata.png` | Wazuh dashboard: 92900 eventdata (grantedAccess 0x1010, same source/target as 100202) |
| `evidence/07-92900-system-fields.png` | Wazuh dashboard: 92900 Sysmon system fields |
| `evidence/08-92900-rule-metadata.png` | Wazuh dashboard: 92900 rule metadata (level 12, MITRE T1003.001) |
| `evidence/09-terminal-empirical-proof.png` | Terminal: alerts.json greps showing per-rule counts and event bodies |

## Application

```bash
# On Wazuh manager
sudo cp rule.xml /var/ossec/etc/rules/local_rules.xml   # or merge into existing
sudo systemctl restart wazuh-manager
```

```cmd
:: On Windows endpoint - after merging sysmon-patch.xml into your active config
Sysmon64.exe -c <path-to-merged-config.xml>
```

## References

- [MITRE ATT&CK T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [SwiftOnSecurity sysmon-config (master)](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft: Configuring Additional LSA Protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
