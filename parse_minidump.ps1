param([string]$DumpPath = "C:\Windows\Minidump\091826-29484-01.dmp")

Write-Host ""
Write-Host "[*] Minidump parser"
Write-Host "[*] File: $DumpPath"
Write-Host ""

if (-not (Test-Path $DumpPath)) { Write-Host "[-] File not found"; exit 1 }

$bytes = [System.IO.File]::ReadAllBytes($DumpPath)
$sz    = $bytes.Length
$kb    = [math]::Round($sz / 1024, 1)
Write-Host ("[*] Dump size: {0} bytes ({1} KB)" -f $sz, $kb)

function ru16 { param($b,$o) [BitConverter]::ToUInt16($b,$o) }
function ru32 { param($b,$o) [BitConverter]::ToUInt32($b,$o) }
function ru64 { param($b,$o) [BitConverter]::ToUInt64($b,$o) }

$sig = [System.Text.Encoding]::ASCII.GetString($bytes[0..3])
if ($sig -ne "MDMP") { Write-Host "[-] Not a minidump (sig=$sig)"; exit 1 }
Write-Host "[+] Valid MDMP"

$stream_count = ru32 $bytes 8
$stream_rva   = ru32 $bytes 12
$timestamp    = ru32 $bytes 20
$dt = [DateTimeOffset]::FromUnixTimeSeconds($timestamp).LocalDateTime
Write-Host "[+] Timestamp:    $dt"
Write-Host "[+] Stream count: $stream_count"

$streams = @{}
for ($i = 0; $i -lt $stream_count; $i++) {
    $off  = $stream_rva + $i * 12
    $type = ru32 $bytes $off
    $size = ru32 $bytes ($off + 4)
    $rva  = ru32 $bytes ($off + 8)
    $streams[$type] = @{ Size=$size; Rva=$rva }
}

$type_names = @{3="ThreadList";4="ModuleList";6="Exception";7="SystemInfo";9="MemoryList"}
Write-Host ""
Write-Host "[*] Streams:"
foreach ($t in ($streams.Keys | Sort-Object)) {
    $n = if ($type_names[$t]) { $type_names[$t] } else { "Type$t" }
    $s = $streams[$t]
    Write-Host ("    type={0,-3} {1,-15} size={2} rva=0x{3}" -f $t, $n, $s.Size, $s.Rva.ToString("X8"))
}

# SystemInfo
Write-Host ""
Write-Host "[*] SYSTEM INFO"
if ($streams[7]) {
    $si  = $streams[7].Rva
    $arch  = ru16 $bytes ($si + 0)
    $major = ru32 $bytes ($si + 8)
    $minor = ru32 $bytes ($si + 12)
    $build = ru32 $bytes ($si + 16)
    $aname = if ($arch -eq 9) { "AMD64" } elseif ($arch -eq 0) { "x86" } else { "arch=$arch" }
    Write-Host "[+] Arch:    $aname"
    Write-Host "[+] Windows: $major.$minor build $build"
    $bnames = @{19041="Win10 2004";19044="Win10 21H2";19045="Win10 22H2";22000="Win11 21H2";22621="Win11 22H2";22631="Win11 23H2";26100="Win11 24H2"}
    if ($bnames[$build]) { Write-Host "[+] Version: $($bnames[$build])" }
}

# Exception stream
Write-Host ""
Write-Host "[*] EXCEPTION"
$ex_addr = 0
if ($streams[6]) {
    $er = $streams[6].Rva
    $tid    = ru32 $bytes ($er + 0)
    $code   = ru32 $bytes ($er + 8)
    $flags  = ru32 $bytes ($er + 12)
    $rec    = ru64 $bytes ($er + 16)
    $ex_addr = ru64 $bytes ($er + 24)
    $nparams = ru32 $bytes ($er + 32)
    Write-Host ("[+] Thread ID:         0x{0:X8}" -f $tid)
    Write-Host ("[+] Exception code:    0x{0:X8}" -f $code)
    Write-Host ("[+] Exception address: 0x{0:X16}" -f $ex_addr)
    Write-Host "[+] Num parameters:    $nparams"
    for ($p = 0; $p -lt [Math]::Min($nparams, 4); $p++) {
        $pv = ru64 $bytes ($er + 40 + $p * 8)
        $desc = ""
        if ($p -eq 0) { $desc = if ($pv -eq 0) { " (READ)" } elseif ($pv -eq 1) { " (WRITE)" } else { " (EXEC)" } }
        if ($p -eq 1) { $desc = " <-- faulting virtual address (what driver tried to access)" }
        if ($p -eq 2) { $desc = " <-- instruction that caused the fault" }
        Write-Host ("[+] Param[{0}]:         0x{1:X16}{2}" -f $p, $pv, $desc)
    }
}

# Module list
Write-Host ""
Write-Host "[*] MODULES"
$signed_base = 0
$signed_size = 0
$modules = @()

if ($streams[4]) {
    $mr    = $streams[4].Rva
    $mcount = ru32 $bytes $mr
    Write-Host "[+] Module count: $mcount"
    Write-Host ""

    for ($m = 0; $m -lt $mcount; $m++) {
        $moff     = $mr + 4 + $m * 108
        $base     = ru64 $bytes ($moff + 0)
        $msize    = ru32 $bytes ($moff + 8)
        $mts      = ru32 $bytes ($moff + 16)
        $name_rva = ru32 $bytes ($moff + 20)
        $name = ""
        if ($name_rva -gt 0 -and ($name_rva + 4) -lt $bytes.Length) {
            $nlen = ru32 $bytes $name_rva
            if ($nlen -gt 0 -and ($name_rva + 4 + $nlen) -le $bytes.Length) {
                $nb = $bytes[($name_rva+4)..($name_rva+3+$nlen)]
                $name = [System.Text.Encoding]::Unicode.GetString($nb)
            }
        }
        $leaf = if ($name) { Split-Path $name -Leaf } else { "<unknown>" }
        $modules += [PSCustomObject]@{ Base=$base; Size=$msize; Leaf=$leaf }

        $end = $base + $msize
        if ($leaf -match "signed|winnotify|WinNotify" -or $leaf -ieq "signed.sys") {
            $signed_base = $base
            $signed_size = $msize
            Write-Host ("*** {0,-35} base=0x{1:X16} size=0x{2:X8}" -f $leaf, $base, $msize)
        } elseif ($leaf -match "^(ntoskrnl|hal|win32k|ci\.dll|cng\.sys)") {
            Write-Host ("    {0,-35} base=0x{1:X16} size=0x{2:X8}" -f $leaf, $base, $msize)
        }
    }
}

# Cross-reference exception address
Write-Host ""
Write-Host "[*] CRASH ADDRESS RESOLUTION"
if ($ex_addr -ne 0) {
    Write-Host ("[+] Exception address: 0x{0:X16}" -f $ex_addr)
    $hit = $null
    foreach ($mod in $modules) {
        if ($ex_addr -ge $mod.Base -and $ex_addr -lt ($mod.Base + $mod.Size)) {
            $hit = $mod; break
        }
    }
    if ($hit) {
        $off = $ex_addr - $hit.Base
        Write-Host ("[+] Faulting module:   {0}" -f $hit.Leaf)
        Write-Host ("[+] RVA in module:     0x{0:X}" -f $off)
    } else {
        Write-Host "[-] Address not in any module (kernel code path or unmapped)"
    }

    if ($signed_base -ne 0) {
        $send = $signed_base + $signed_size
        Write-Host ("[+] signed.sys range:  0x{0:X16} -- 0x{1:X16}" -f $signed_base, $send)
        if ($ex_addr -ge $signed_base -and $ex_addr -lt $send) {
            $rva = $ex_addr - $signed_base
            Write-Host ("[+] signed.sys RVA:    0x{0:X}  <-- PASTE THIS" -f $rva)
        } else {
            Write-Host "[-] Crash address is NOT inside signed.sys"
            Write-Host "    (crash is in kernel itself -- driver triggered a kernel bugcheck)"
        }
    }
}

Write-Host ""
Write-Host "[*] Done -- paste full output above"