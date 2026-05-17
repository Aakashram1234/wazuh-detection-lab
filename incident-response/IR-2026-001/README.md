# Incident Report — IR-2026-001
## Multi-Stage Intrusion: Brute Force to Lateral Movement

> **Document type:** Simulated incident / detection-validation case study
> **Environment:** Wazuh Detection Engineering Lab — controlled, isolated.
> This report documents a purple-team exercise: a multi-stage attack chain
> executed by the author against a lab endpoint, then analysed and written up
> as a SOC analyst would handle a real incident. It is not a record of an
> actual breach.

| Field | Value |
|-------|-------|
| Incident ID | IR-2026-001 |
| Classification | Simulated multi-stage intrusion (purple-team exercise) |
| Severity | High |
| Date | 2026-05-16 |
| Incident window | 23:46:12 – 23:55:39 UTC |
| Affected system | `windows-endpoint` (192.168.18.134) — Windows 11 |
| Adversary source | 192.168.18.132 |
| Compromised account | `labtest` (local administrator) |
| Detections triggered | 8 Wazuh rules — 6 custom, 2 built-in — across 5 ATT&CK tactics |
| Analyst | Aakash Ramamoorthy |

---

## 1. Executive Summary

Over a window of roughly nine minutes, a simulated adversary carried out a
complete five-stage intrusion against a Windows 11 endpoint: **initial access,
execution, persistence, credential access, and lateral movement**. The attack
began with an SMB brute-force that compromised a local account, progressed
through obfuscated PowerShell execution and two persistence mechanisms,
escalated to credential theft from LSASS memory, and ended with `psexec`-style
lateral movement.

**Every stage was detected.** Eight Wazuh rules fired — six custom detections
authored for this lab plus two Wazuh built-ins — producing a complete,
high-fidelity alert trail with no blind spots in the kill chain. This report
reconstructs the intrusion from those alerts, walks each stage as a SOC analyst
would investigate it, consolidates the indicators of compromise, and sets out
the containment, eradication, and hardening actions a response team would take.

The exercise validates that the lab's detection coverage catches a realistic,
multi-stage intrusion end to end — and that the custom rules consistently
surface activity at an actionable severity where the built-in ruleset is either
silent or merely informational.

## 2. Scope & Methodology

- The attack was executed in a controlled, isolated lab. The "adversary host"
  (192.168.18.132) is the lab's Linux server doubling as an attack platform;
  network-based stages (brute force, `psexec`) were launched from it, and
  host-based stages (PowerShell, registry, scheduled task, LSASS access) were
  executed directly on the endpoint.
- **Lateral movement caveat:** the lab has a single Windows endpoint, so the
  Stage 5 `psexec` activity targeted that same host. In a production
  environment this stage represents the pivot to an *additional* host; the
  technique and its detection signature are identical either way.
- To make every stage observable, the endpoint was deliberately weakened before
  the exercise (LSA Protection disabled, inbound SMB allowed, remote-admin token
  filtering disabled, the test account granted local admin). Section 8 treats
  the reversal of each of those weakenings as a hardening recommendation.
- All timestamps are UTC. The Wazuh dashboard displays local time (UTC+10);
  e.g. 23:50:38 UTC = 09:50:38 local.

## 3. Timeline of Events

| Time (UTC) | Stage | ATT&CK | Wazuh rule(s) | Activity |
|------------|-------|--------|---------------|----------|
| 23:46:12 | — | — | — | Incident window opens (analyst marker) |
| 23:46:13–55 | 1 — Initial Access | T1110.001 | 60204 (built-in) | 9 failed SMB authentications against `labtest` |
| 23:46:55 / 23:46:57 | 1 — Initial Access | T1110.001 | **100204** | 2 successful logons — `labtest` credential compromised |
| 23:50:38 | 2 — Execution | T1059.001 / T1027 | **100200** | Obfuscated encoded-PowerShell payload executed |
| 23:51:37.339 | 3 — Persistence | T1547.001 | **100201** | Registry Run key `IR2026Updater` created |
| 23:51:37.403 | 3 — Persistence | T1053.005 | **100203** | Scheduled task `IR2026_SyncTask` created |
| 23:52:27.424 | 4 — Credential Access | T1003.001 | **100202** | `lsass.exe` accessed with mask `0x1FFFFF` |
| 23:53:20.041 | 5 — Lateral Movement | T1021.002 | **100205** | `psexec` service `nPNj` installed via `ADMIN$` |
| 23:55:39 | — | — | — | Incident window closes |

Rule 100200 also fired at 23:50:06 and 23:51:37 — see Section 5, Stage 2.

## 4. Attack Narrative

**Stage 1 — Initial Access (T1110.001 — Brute Force: Password Guessing).**
The adversary, operating from 192.168.18.132, targeted the SMB service (TCP 445)
exposed on `windows-endpoint`. Nine consecutive failed authentication attempts
against the local account `labtest` were followed by two successful logons — a
guessed password. Wazuh's built-in correlation rule 60204 flagged the failure
burst; the custom rule 100204 flagged the *successful* logons that followed,
pinpointing the moment of credential compromise — the signal a built-in
brute-force rule never raises.

**Stage 2 — Execution (T1059.001 — PowerShell; T1027 — Obfuscation).**
With a valid credential, the adversary executed an obfuscated PowerShell
payload on the endpoint — a Base64-encoded command run through
`powershell.exe` with `-NoProfile -WindowStyle Hidden -EncodedCommand`. The
combination of an encoded command and window-hiding evasion flags is a
hallmark of malicious PowerShell delivery, and rule 100200 detected it.

**Stage 3 — Persistence (T1547.001 — Run Key; T1053.005 — Scheduled Task).**
The adversary established two independent persistence mechanisms within the
same second — the redundancy a real intruder builds in so that losing one
foothold does not cost them access. A registry **Run key** (`IR2026Updater`)
was set to launch a hidden-window PowerShell script from `C:\Users\Public\`,
and a **scheduled task** (`IR2026_SyncTask`) was created to run hidden encoded
PowerShell at every logon. Rules 100201 and 100203 fired 64 ms apart.

**Stage 4 — Credential Access (T1003.001 — LSASS Memory).**
The adversary moved to their objective: harvesting credentials. `powershell.exe`
opened a handle to `lsass.exe` with access mask `0x1FFFFF` (`PROCESS_ALL_ACCESS`)
— the access required to read process memory and extract cached credentials,
hashes, and tokens. Rule 100202 detected the LSASS access by its dumping-grade
mask.

**Stage 5 — Lateral Movement (T1021.002 — SMB / Admin Shares).**
Using harvested credentials, the adversary performed `psexec`-style lateral
movement: authenticating over SMB, writing a service binary
(`vtTnTEbB.exe`) to the `ADMIN$` share, and registering and starting a Windows
service (`nPNj`) to execute it. Rule 100205 detected the service installation
by its signature — a randomly named binary in the Windows root. The tool
deleted the service and binary on exit; the **7045 service-install event
remained as the durable evidence**, precisely because the on-disk artifacts are
ephemeral.

## 5. Detection Analysis

For each stage: the alert(s) a SOC analyst receives, how they interpret it, and
the investigative pivot.

**Stage 1 — rules 60204 (level 10) + 100204 (level 14).** The analyst sees a
burst of authentication failures from one source IP, immediately followed by a
"successful logon after multiple failures" alert. *Interpretation:* a brute
force that **succeeded** — not just noise. *Pivot:* identify every action taken
by `labtest` from 192.168.18.132 after 23:46:57; treat the account as
compromised.

**Stage 2 — rule 100200 (level 14), 3 hits.** Encoded PowerShell with evasion
flags. *Interpretation:* obfuscated execution — the adversary is running code
they do not want inspected. *Note:* the rule fired three times in the window —
the explicit Stage 2 payload (23:50:38) plus two further hits, including
23:51:37, which coincides with the Stage 3 scheduled-task creation: the encoded
command embedded in that task's action independently tripped the execution
rule. One adversary action surfacing through two detections is defence in
depth working as intended. *Pivot:* decode the Base64 payloads to recover
adversary intent.

**Stage 3 — rules 100201 + 100203 (level 14).** Two persistence alerts within
the same second. *Interpretation:* the adversary is ensuring survival across
reboot — and has built in redundancy. *Pivot:* enumerate **all** autostart
locations, not just the two that alerted; assume more persistence may exist.

**Stage 4 — rule 100202 (level 14).** `powershell.exe` accessed `lsass.exe`
with `0x1FFFFF`. *Interpretation:* credential theft from memory — the likely
objective of the intrusion. *Pivot:* this is the escalation point. Every
credential used on this host must now be considered compromised; widen the
investigation to wherever those credentials are valid.

**Stage 5 — rule 100205 (level 14).** A service named `nPNj` installed with a
binary (`vtTnTEbB.exe`) in the Windows root. *Interpretation:* `psexec`-style
lateral movement — the adversary is using stolen credentials to execute on a
target. *Pivot:* in a multi-host environment, hunt the destination host for the
same indicators and treat it as compromised.

## 6. Indicators of Compromise

| Type | Indicator | Context |
|------|-----------|---------|
| IP address | `192.168.18.132` | Adversary source — brute force and `psexec` origin |
| Account | `labtest` | Compromised local account; elevated to local Administrator |
| Service name | `nPNj` | `psexec` service (randomly named) |
| File | `vtTnTEbB.exe` in `C:\Windows\` | `psexec` service binary; deleted on tool exit |
| Registry key | `HKCU\…\CurrentVersion\Run\IR2026Updater` | Run-key persistence |
| File path | `C:\Users\Public\update.ps1` | Payload referenced by the Run key |
| Scheduled task | `IR2026_SyncTask` | Logon-triggered persistence |
| Process behaviour | `powershell.exe` → `lsass.exe`, `grantedAccess 0x1FFFFF` | LSASS credential access |
| Process behaviour | `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand …` | Obfuscated execution |

## 7. Containment, Eradication & Recovery

**Containment**
- Network-isolate `windows-endpoint` to halt any active adversary access.
- Disable the `labtest` account immediately.
- Block / closely monitor traffic from 192.168.18.132.

**Eradication**
- Delete the Run-key value `IR2026Updater` and the scheduled task `IR2026_SyncTask`.
- Confirm the `nPNj` service and `vtTnTEbB.exe` are removed (the tool self-cleaned — verify rather than assume).
- Remove `labtest` from the Administrators group and delete the account.
- **Because LSASS was accessed, treat every credential present on the host as compromised** — reset passwords for all accounts that authenticated to the endpoint, prioritising any privileged accounts.
- Threat-hunt for persistence beyond the two mechanisms that alerted.

**Recovery**
- Re-enable LSA Protection (`RunAsPPL`), revert `LocalAccountTokenFilterPolicy`, and restore the SMB firewall posture (see Section 8).
- Given a confirmed memory-credential-theft stage, rebuilding the host from a known-good image is the conservative and recommended course.
- Apply heightened monitoring to the host and to the compromised account for a defined watch period.

## 8. Lessons Learned & Recommendations

**What worked.** The detection coverage held across the entire kill chain — all
five stages produced alerts, with no gap an adversary could have slipped
through unobserved. The custom rules consistently outperformed the built-in
ruleset: built-in 60204 flagged the brute-force *failures* but never the
successful logon, which custom rule 100204 caught; built-in 61138 logged the
Stage 5 service install at informational severity (level 5), while custom rule
100205 escalated the same event to level 14. An analyst working only the
built-in alerts would have seen noise and an informational notice — not a
five-stage intrusion.

**Detection gaps / adversary evasion.** This exercise used default tooling and
techniques. A more capable adversary could evade specific detections — for
example, `psexec` configured to drop its binary into `System32` with a
plausible name would not match rule 100205's path signature; a brute force run
from a rotating set of source IPs would break rule 100204's IP correlation;
credential access performed by a tool other than a known interpreter, or via a
technique that does not open a high-access handle to LSASS, would not match
rule 100202. Each detection's own writeup documents these limitations in
detail. Detection coverage should be read as raising the cost to the adversary,
not as a guarantee.

**Hardening recommendations.** Several conditions that enabled this intrusion
are controllable:

- **Re-enable LSA Protection** (`RunAsPPL=1`). It was disabled for this exercise; with it on, the Stage 4 LSASS access would have been denied outright.
- **Restrict SMB exposure.** Inbound TCP 445 should not be broadly reachable; the brute-force and lateral-movement stages both depended on it.
- **Enforce least privilege.** `labtest` was a standard account elevated to local Administrator for the exercise. Local-admin rights should be tightly scoped — `psexec` lateral movement requires them.
- **Restore remote-admin token filtering.** `LocalAccountTokenFilterPolicy` was set to allow remote admin for local accounts; left at its default, the Stage 5 `psexec` would have failed with access denied.
- **Account lockout is working** — the endpoint's policy locks an account after 10 failed attempts, and the exercise was deliberately calibrated to 9 to stay under it. The control is sound; the recommendation is to keep it enforced.

## 9. MITRE ATT&CK Coverage

| Tactic | Technique | Wazuh rule |
|--------|-----------|-----------|
| Credential Access | T1110.001 — Brute Force: Password Guessing | 60204, 100204 |
| Execution | T1059.001 — PowerShell | 100200 |
| Defense Evasion | T1027 — Obfuscated Files or Information | 100200 |
| Persistence | T1547.001 — Registry Run Keys | 100201 |
| Persistence / Execution | T1053.005 — Scheduled Task | 100203 |
| Credential Access | T1003.001 — LSASS Memory | 100202 |
| Lateral Movement | T1021.002 — SMB / Windows Admin Shares | 100205 |
| Persistence / Priv. Esc. | T1543.003 — Windows Service | 61138, 100205 |

---

*Detection rules referenced in this report are documented in full — gap
analysis, logic, validation, and limitations — under [`detections/`](../../detections/)
in this repository.*
