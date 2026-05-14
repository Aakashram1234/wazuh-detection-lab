# Setup and trigger commands for T1053.005 testing

These commands were used to validate rule 100203. Run on the **Windows endpoint** in
an elevated PowerShell or CMD session.

## 1. One-time audit policy enable

Windows 11 ships with the "Other Object Access Events" audit subcategory disabled,
so EID 4698 (scheduled task created) is not generated until this is turned on:

```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Takes effect immediately. Persists across reboots. Verify with:

```cmd
auditpol /get /subcategory:"Other Object Access Events"
```

## 2. Benign test task

Used to confirm 60228 (built-in) fires on any task creation and that telemetry is
flowing from agent → manager:

```cmd
schtasks /create /tn "WazuhSchTaskTest_Benign" /tr "cmd.exe /c echo hello" /sc once /st 23:59 /f
```

Expected: 60228 fires (level 4), 100203 does NOT fire (no suspicious indicator in
Task Content).

## 3. Suspicious test task

PowerShell with multiple evasion flags. Triggers the regex match against
`win.system.message`:

```cmd
schtasks /create /tn "WazuhSchTaskTest_Suspicious" /tr "powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" /sc once /st 23:58 /f
```

Expected: 100203 fires (level 14, T1053.005). 60228 is *suppressed* by Wazuh's
`if_sid` rule hierarchy (a child rule match supersedes the parent alert).

The base64 in `-EncodedCommand` is a harmless string (decodes to
`IEX (New-Object Net.WebClient)` - a fragment without a URL or actual download).
The task is scheduled for 23:58 and will be deleted before execution.

## 4. Cleanup

After validation:

```cmd
schtasks /delete /tn "WazuhSchTaskTest_Benign" /f
schtasks /delete /tn "WazuhSchTaskTest_Suspicious" /f
schtasks /delete /tn "WazuhSchTaskTest_Suspicious2" /f
```

Each deletion generates EID 4699 (scheduled task deleted), which is not currently
covered by this detection but could be added as a symmetric rule.
