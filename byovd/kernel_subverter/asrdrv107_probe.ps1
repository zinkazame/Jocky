# asrdrv107_probe.ps1 -- brute-force IOCTL probe for AsrDrv107.sys
# Usage: powershell -ExecutionPolicy Bypass -File .\asrdrv107_probe.ps1 ..\..\AsrDrv107.sys
# Requires admin. Driver must not already be loaded.

param([string]$DriverPath = "..\..\AsrDrv107.sys")

$abs = (Resolve-Path $DriverPath -ErrorAction Stop).Path
Write-Host "[*] AsrDrv107 IOCTL probe"
Write-Host "[*] Driver: $abs"

# Load driver via SCM
$svc = "AsrDrv107"
$nt  = "\??\" + $abs

$scm = [System.ServiceProcess.ServiceController]::GetServices() | Where-Object { $_.ServiceName -eq $svc }
if ($scm) {
    try { (New-Object System.ServiceProcess.ServiceController($svc)).Stop() } catch {}
    Start-Sleep -Milliseconds 300
    sc.exe delete $svc | Out-Null
    Start-Sleep -Milliseconds 300
}

sc.exe create $svc binPath= $nt type= kernel start= demand error= normal | Out-Null
sc.exe start $svc | Out-Null
Start-Sleep -Milliseconds 500

$device = "\\.\\AsrDrv107"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwAccess,
        uint dwShare, IntPtr lpSec, uint dwDisp, uint dwFlags, IntPtr hTemp);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDevice, uint dwCode,
        byte[] lpIn, uint nIn, byte[] lpOut, uint nOut,
        ref uint lpRet, IntPtr lpOver);
    
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
}
"@

$handle = [WinAPI]::CreateFile($device, 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($handle -eq [IntPtr](-1)) {
    Write-Host "[-] Cannot open device: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    sc.exe stop $svc | Out-Null; sc.exe delete $svc | Out-Null
    exit 1
}
Write-Host "[+] Device handle: $handle"

# Build test input: 16 bytes = { uint64 PA=0x1000, uint32 UnitSize=4, uint32 Count=1 }
$input16 = [byte[]](0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00, `
                    0x04,0x00,0x00,0x00, `
                    0x01,0x00,0x00,0x00)

# also try 20-byte variant (with Data field)
$input20 = [byte[]](0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00, `
                    0x04,0x00,0x00,0x00, `
                    0x01,0x00,0x00,0x00, `
                    0x00,0x00,0x00,0x00)

$output = [byte[]]::new(64)
$ret = [uint32]0

Write-Host ""
Write-Host "=== TARGETED PROBE (priority codes from binary scan) ==="
Write-Host ""

$priority = @(
    0x802AA058, 0x802AA16E, 0x801A237F,
    0x802A2058, 0x802A2104, 0x802AA104, 0x802AA108,
    0x802A216C, 0x802A216E, 0x802A611C,
    # also try the 0x9C40 family with every access/method combo
    0x9C402104, 0x9C406104, 0x9C40A104, 0x9C40E104,
    0x9C402108, 0x9C406108, 0x9C40A108,
    0x9C402084, 0x9C402088,
    # try broader IOCTL range with dev=0x802A
    0x802A2100, 0x802A2104, 0x802A2108, 0x802A210C,
    0x802A6100, 0x802A6104, 0x802A6108,
    0x802AA100, 0x802AA104, 0x802AA108,
    0x802AE100, 0x802AE104, 0x802AE108
)

$hits = @()
foreach ($code in $priority) {
    $ret = [uint32]0
    [Array]::Clear($output, 0, $output.Length)
    
    # try 16-byte input
    $ok = [WinAPI]::DeviceIoControl($handle, $code, $input16, 16, $output, 64, [ref]$ret, [IntPtr]::Zero)
    $err = [WinAPI]::GetLastError()
    
    if ($ok -or $err -ne 1) {
        $val = [BitConverter]::ToUInt32($output, 0)
        $hits += $code
        Write-Host ("[HIT-16] 0x{0:X8}  ok={1}  err={2}  val=0x{3:X8}  ret={4}" -f $code, $ok, $err, $val, $ret)
        continue
    }
    
    # try 20-byte input
    [Array]::Clear($output, 0, $output.Length)
    $ok = [WinAPI]::DeviceIoControl($handle, $code, $input20, 20, $output, 64, [ref]$ret, [IntPtr]::Zero)
    $err = [WinAPI]::GetLastError()
    
    if ($ok -or $err -ne 1) {
        $val = [BitConverter]::ToUInt32($output, 0)
        $hits += $code
        Write-Host ("[HIT-20] 0x{0:X8}  ok={1}  err={2}  val=0x{3:X8}  ret={4}" -f $code, $ok, $err, $val, $ret)
    }
}

Write-Host ""
if ($hits.Count -gt 0) {
    Write-Host "[+] HITS: $($hits.Count)"
    foreach ($h in $hits) { Write-Host "  0x{0:X8}" -f $h }
} else {
    Write-Host "[-] No hits in priority list -- running wide scan on dev=0x802A..."
    Write-Host "    (scanning fn=0x800-0x87F, all methods, all access)"
    Write-Host ""
    
    $fn_range = 0x800..0x87F
    foreach ($fn in $fn_range) {
        foreach ($meth in 0..3) {
            foreach ($acc in 0..3) {
                $code = (0x802A -shl 16) -bor ($acc -shl 14) -bor ($fn -shl 2) -bor $meth
                $ret = [uint32]0
                [Array]::Clear($output, 0, $output.Length)
                $ok = [WinAPI]::DeviceIoControl($handle, [uint32]$code, $input16, 16, $output, 64, [ref]$ret, [IntPtr]::Zero)
                $err = [WinAPI]::GetLastError()
                if ($ok -or $err -ne 1) {
                    $val = [BitConverter]::ToUInt32($output, 0)
                    Write-Host ("[HIT] 0x{0:X8}  fn=0x{1:X3}  meth={2}  acc={3}  ok={4}  err={5}  val=0x{6:X8}" `
                        -f $code, $fn, $meth, $acc, $ok, $err, $val)
                }
            }
        }
    }
}

[WinAPI]::CloseHandle($handle) | Out-Null
sc.exe stop $svc | Out-Null
Start-Sleep -Milliseconds 300
sc.exe delete $svc | Out-Null
Write-Host ""
Write-Host "[*] Probe complete"