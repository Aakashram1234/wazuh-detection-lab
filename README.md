# Wazuh Detection Engineering Lab

A home-built SOC lab where every alert is a **custom detection rule** — each one built by auditing a real gap in Wazuh's out-of-the-box coverage, then verified against a live, simulated attack.

The point isn't "install a SIEM." It's detection engineering: find where the default rules are blind, write a rule that closes the gap, and prove it fires.

## Overview

Six detections, all mapped to MITRE ATT&CK and empirically validated. Each one started from a specific, demonstrable weakness in a Wazuh built-in rule — for example:

- a credential-dumping rule whose regex matched only 2 of ~7 modern LSASS access masks
- a scheduled-task rule that fired on every task creation with no content inspection
- a brute-force rule that flags the failed logins but never the successful one
- a service-installation rule that fires at informational severity on every service, malicious or not

Every detection in this repo replaces that blind spot with a targeted, higher-severity, ATT&CK-mapped rule.

## Lab architecture

Two virtual machines on an Apple Silicon Mac (VMware Fusion):

| Host | Role | Details |
|------|------|---------|
| `wazuh-server` — 192.168.18.132 | SIEM + attack host | Ubuntu Server 26.04 ARM64 · Wazuh 4.13 all-in-one (manager + indexer + dashboard) |
| `windows-endpoint` — 192.168.18.134 | Monitored endpoint | Windows 11 ARM · Sysmon (SwiftOnSecurity config, extended) · Wazuh agent |

Host-based techniques (PowerShell, registry, scheduled tasks, LSASS access) are triggered directly on the Windows endpoint. Network-based techniques (SMB brute force, psexec lateral movement) are launched from the Wazuh manager, which doubles as the attacker host — Impacket and `smbclient` are OS-agnostic, so a dedicated Kali VM is not required.

## Detection methodology

Every detection in this repo follows the same four steps:

1. **Audit** — examine Wazuh's built-in rule for the technique and find where it is blind: a too-narrow regex, no content filter, only failures flagged, or a severity too low to action.
2. **Design** — write a custom rule (Wazuh XML, rule IDs 100200+) that closes the gap, mapped to MITRE ATT&CK, at a severity an analyst would actually act on.
3. **Trigger** — simulate the technique with a real attack and confirm the expected telemetry reaches Wazuh.
4. **Validate** — verify the custom rule fires on the attack (and that built-in rules do not double-alert), then capture dashboard and terminal evidence.

Each detection folder documents all four steps in full — including the dead ends.

## Detection coverage

| ATT&CK ID | Technique | Tactic | Wazuh rule | Status |
|-----------|-----------|--------|-----------|--------|
| [T1059.001](./detections/T1059.001-powershell-encoded/) | PowerShell Encoded Command | Execution | 100200 | Complete ✓ |
| [T1547.001](./detections/T1547.001-registry-run-key/) | Registry Run Key Persistence | Persistence | 100201 | Complete ✓ |
| [T1003.001](./detections/T1003.001-lsass-memory/) | LSASS Memory Access | Credential Access | 100202 | Complete ✓ |
| [T1053.005](./detections/T1053.005-scheduled-task/) | Scheduled Task Creation | Persistence / Execution | 100203 | Complete ✓ |
| [T1110.001](./detections/T1110.001-brute-force/) | Brute Force — Password Guessing | Credential Access | 100204 | Complete ✓ |
| [T1021.002](./detections/T1021.002-smb-lateral-movement/) | SMB / Admin Share Lateral Movement | Lateral Movement | 100205 | Complete ✓ |

## Incident Response Case Study

The six detections above are not isolated rules — chained together, they cover a
complete attack kill chain. [**IR-2026-001**](./incident-response/IR-2026-001/)
is a full incident-response writeup of a simulated multi-stage intrusion run
against the lab: SMB brute force, encoded-PowerShell execution, registry and
scheduled-task persistence, LSASS credential theft, and psexec lateral movement.

All five stages were detected. The case study reconstructs the incident from the
Wazuh alerts — timeline, attack narrative, per-stage detection analysis,
consolidated IOCs, and containment / eradication / hardening recommendations —
the way a SOC analyst would handle a real incident.

## Repository layout

Each detection lives in `detections/<ATT&CK-ID>-<name>/`:

```
detections/T1021.002-smb-lateral-movement/
├── README.md      # engineering writeup: gap analysis, rule logic, validation, limitations
├── rule.xml       # the custom Wazuh rule
├── test/          # attack reproduction steps / test harness
└── evidence/      # dashboard + terminal screenshots
```

## Tooling

- **SIEM:** Wazuh 4.13 — single-node, all-in-one (manager, indexer, dashboard)
- **Endpoint telemetry:** Sysmon with the SwiftOnSecurity configuration, extended where a detection required it (e.g. a ProcessAccess block added for LSASS monitoring)
- **Attack simulation:** native Windows tooling, PowerShell test harnesses, and Impacket
- **Detection authoring:** Wazuh native rules (XML), every rule mapped to MITRE ATT&CK

## About

Aakash Ramamoorthy — getting into cybersecurity the practical way: build a lab, simulate attacks, write detections, document the lessons.

[LinkedIn](https://www.linkedin.com/in/aakash-ramamoorthy) · [aakashram588@gmail.com](mailto:aakashram588@gmail.com)
