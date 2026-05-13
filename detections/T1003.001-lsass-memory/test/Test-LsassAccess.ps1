<#
.SYNOPSIS
    Generates Sysmon ProcessAccess (EID 10) telemetry against lsass.exe using a
    controlled access mask, for T1003.001 detection rule development and testing.

.DESCRIPTION
    Defines a Win32 P/Invoke wrapper for OpenProcess + CloseHandle and exposes
    Test-LsassAccess as a parameterizable test harness. Used during T1003.001
    detection development to generate clean Sysmon EID 10 events with specific
    GrantedAccess values without running actual credential-dumping tooling.

    Defender-safe: Add-Type with kernel32 P/Invoke is standard admin scripting.
    No memory reads, no dump files, no suspicious strings.

.NOTES
    Requires:   PowerShell as Administrator (for SeDebugPrivilege).
    Caveat:     On Win 11 with LSA Protection enabled (RunAsPPL=1, the default),
                OpenProcess against lsass returns Win32 error 5 (ACCESS_DENIED)
                AND Sysmon does not log the attempt -- the kernel access check
                happens before the Sysmon callback logging path. To generate test
                telemetry, temporarily set RunAsPPL=0 and reboot:

                    reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 0 /f
                    Restart-Computer -Force

                Re-enable after testing to keep the lab realistic:

                    reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 2 /f
                    Restart-Computer -Force

.EXAMPLE
    PS> . .\Test-LsassAccess.ps1
    PS> Test-LsassAccess -Mask 0x1FFFFF   # procdump / Task Manager dump signature
    PS> Test-LsassAccess -Mask 0x1010     # mimikatz classic signature
#>

Add-Type @'
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@

function Test-LsassAccess {
    param([uint32]$Mask)
    $lsass = Get-Process lsass
    $maskHex = "0x{0:X}" -f $Mask
    Write-Host "[*] Opening lsass (PID $($lsass.Id)) with access mask $maskHex..."
    $h = [P]::OpenProcess($Mask, $false, $lsass.Id)
    if ($h -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[!] OpenProcess FAILED. Win32 error code: $err" -ForegroundColor Red
    } else {
        Write-Host "[+] Handle acquired: $h" -ForegroundColor Green
        [P]::CloseHandle($h) | Out-Null
        Write-Host "[+] Handle closed cleanly."
    }
}
