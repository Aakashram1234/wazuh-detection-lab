# T1110.001 — Setup & Trigger

Reproduces the brute-force → successful-logon detection for rule 100204.

- **Attacker:** Wazuh manager (Ubuntu, 192.168.18.132) — runs `smbclient`
- **Target:** Windows 11 endpoint (192.168.18.134) — Wazuh agent installed

## 1. Prerequisites (one-time)

### Windows endpoint — confirm logon auditing

```powershell
auditpol /get /subcategory:"Logon"
```

Expect `Logon  Success and Failure`. If not:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### Windows endpoint — allow inbound SMB (for the test only)

Windows 11 firewall blocks inbound SMB by default. Add a removable rule:

```powershell
New-NetFirewallRule -DisplayName "LAB-SMB-In-Test" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any
```

### Wazuh manager — install the SMB client

```bash
which smbclient || sudo apt-get install -y smbclient
```

## 2. Create the throwaway target account

On the **Windows endpoint** (PowerShell as Admin). Using a throwaway account
keeps real credentials out of shell history and screenshots:

```powershell
net user labtest /delete   # ignore error if it doesn't exist yet
net user labtest "LabPass123!" /add
```

> Recreate the account before each run — it clears any lingering lockout.

## 3. Trigger the detection

On the **Wazuh manager**. Calibrated to **9** failed logins: enough to trip
built-in rule 60204 (threshold 8), but under the Windows 11 account-lockout
limit of 10. Then 2 successful logins to satisfy rule 100204's `frequency 2`.

```bash
# 9 failed SMB authentications -> 9x event 4625 -> trips rule 60204
for i in $(seq 1 9); do
  smbclient -L //192.168.18.134 -U "labtest%WrongPass_${i}" -t 5 2>&1 | grep -oE "NT_STATUS_[A-Z_]+"
  sleep 1
done

sleep 5   # let rule 60204 correlate

# 2 successful SMB authentications -> 2x event 4624 -> trips rule 100204
smbclient -L //192.168.18.134 -U "labtest%LabPass123!" -t 5
sleep 2
smbclient -L //192.168.18.134 -U "labtest%LabPass123!" -t 5
```

## 4. Verify

On the **Wazuh manager**:

```bash
sudo grep -c '"id":"60204"'  /var/ossec/logs/alerts/alerts.json   # built-in brute force
sudo grep -c '"id":"100204"' /var/ossec/logs/alerts/alerts.json   # custom: success after brute force
```

`100204` count should be >= 1. Inspect the alert:

```bash
sudo grep '"id":"100204"' /var/ossec/logs/alerts/alerts.json | tail -1 \
  | grep -oE '"(description|ipAddress|targetUserName)":"[^"]*"'
```

Or in the Wazuh dashboard: filter `rule.id:100204`.

## 5. Cleanup

Windows endpoint:

```powershell
net user labtest /delete
Remove-NetFirewallRule -DisplayName "LAB-SMB-In-Test"
```

Nothing to clean up on the Wazuh manager (`smbclient` can stay installed).
