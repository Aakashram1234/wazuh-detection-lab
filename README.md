# Wazuh Detection Engineering Lab

A home-built Security Operations Center lab demonstrating end-to-end detection engineering — from log ingestion to MITRE ATT&CK-mapped alerts triggered by simulated attacks launched from a Kali attacker VM.

## Overview

This lab runs three virtual machines on Apple Silicon (M-series Mac) via VMware Fusion:

- **Wazuh Manager** — Ubuntu Server 26.04 ARM64, all-in-one Wazuh 4.13 deployment (manager + indexer + dashboard)
- **Windows 11 ARM** — instrumented endpoint with Sysmon (SwiftOnSecurity config) and the Wazuh agent
- **Kali Linux** — attacker VM, used to launch ATT&CK-aligned techniques against the Windows endpoint

Every detection rule is written from scratch, mapped to MITRE ATT&CK, and verified by triggering the corresponding technique either from Kali (Impacket) or with Atomic Red Team on Windows.

## Detection coverage

| ATT&CK ID | Technique | Status |
|---|---|---|
| T1059.001 | PowerShell Encoded Command | [Complete ✓](./detections/T1059.001-powershell-encoded/) |
| T1003.001 | LSASS Memory Access | Planned |
| T1110 | Brute Force (Windows logon) | Planned |
| T1547.001 | Registry Run Key Persistence | [Complete ✓](./detections/T1547.001-registry-run-key/) |
| T1053.005 | Scheduled Task Creation | Planned |
| T1021.002 | SMB/Admin Share Lateral Movement | Planned |

## Tooling

- **SIEM:** Wazuh 4.13 (manager, indexer, dashboard — single-node, all-in-one)
- **Endpoint telemetry:** Sysmon with the SwiftOnSecurity configuration
- **Attack simulation:** Impacket from Kali, plus Atomic Red Team on Windows
- **Detection authoring:** Wazuh native rules (XML), mapped to MITRE ATT&CK

## About

Aakash Ramamoorthy - getting into cybersecurity the practical way: build a lab, simulate attacks, write detections, document the lessons. Every rule in this repo is mapped to MITRE ATT&CK and verified against simulated attacks in a self-built lab environment.

Reach me on [LinkedIn](https://www.linkedin.com/in/aakash-ramamoorthy) or at [aakashram588@gmail.com](mailto:aakashram588@gmail.com).
