# T1021.002 — Setup & Trigger

Reproduces the psexec lateral-movement detection for rule 100205.

- **Attacker:** Wazuh manager (Ubuntu, 192.168.18.132) — runs Impacket
- **Target:** Windows 11 endpoint (192.168.18.134) — Wazuh agent installed

> Impacket is OS-agnostic Python; a dedicated Kali host is not required. The
> Ubuntu manager plays the attacker.

## 1. Prerequisites

### Wazuh manager — install Impacket

```bash
sudo apt-get install -y python3-impacket
```

Ubuntu packages `psexec.py` at
`/usr/share/doc/python3-impacket/examples/psexec.py` (it is not exposed as an
`impacket-psexec` wrapper, unlike some other example scripts).

### Windows endpoint — confirm the System channel is forwarded

Event 7045 lives in the **System** log. Verify the Wazuh agent forwards it
(the default agent config does). On the manager, after any service install:

```bash
sudo grep -c '"id":"61138"' /var/ossec/logs/alerts/alerts.json
```

## 2. Prepare the target

On the **Windows endpoint** (PowerShell as Admin).

Create a throwaway local-admin account (psexec needs admin on the target;
using a throwaway keeps real credentials out of history/screenshots):

```powershell
net user labtest /delete          # ignore error if absent
net user labtest "LabPass123!" /add
net localgroup Administrators labtest /add
```

Allow inbound SMB (removed in cleanup):

```powershell
New-NetFirewallRule -DisplayName "LAB-SMB-In-Test" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any
```

Allow remote admin for local accounts — Windows 11 "Remote UAC" otherwise
strips the admin token from local accounts authenticating over the network,
causing psexec to fail with `ACCESS_DENIED`:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

## 3. Trigger the detection

On the **Wazuh manager**:

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py labtest:'LabPass123!'@192.168.18.134
```

Expected output includes:

```
[*] Found writable share ADMIN$
[*] Uploading file <random8>.exe
[*] Creating service <random4> on 192.168.18.134
[*] Starting service <random4>
```

The **"Creating service"** line generates event 7045 on the endpoint. If a
`C:\Windows\system32>` shell appears, type `exit`. (The interactive shell may
fail to attach on Windows 11 — this does not matter; the service install has
already fired the 7045 event.)

## 4. Verify

On the **Wazuh manager**:

```bash
sudo grep -c '"id":"61138"'  /var/ossec/logs/alerts/alerts.json   # built-in, level 5
sudo grep -c '"id":"100205"' /var/ossec/logs/alerts/alerts.json   # custom, level 14

sudo grep '"id":"100205"' /var/ossec/logs/alerts/alerts.json | tail -1 \
  | grep -oE '"(serviceName|imagePath|description)":"[^"]*"'
```

`100205` count should be >= 1, with `imagePath` showing the random `.exe` in
the Windows root. In the Wazuh dashboard: filter `rule.id:100205`.

## 5. Cleanup

Windows endpoint (PowerShell as Admin):

```powershell
net user labtest /delete
Remove-NetFirewallRule -DisplayName "LAB-SMB-In-Test"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /f

# remove any psexec service/binary left behind if its shell exited uncleanly
# (replace <name>/<file> with the values shown in the psexec output)
sc.exe delete <serviceName>
del C:\Windows\<random8>.exe
```

Nothing to remove on the Wazuh manager (`python3-impacket` can stay installed).
