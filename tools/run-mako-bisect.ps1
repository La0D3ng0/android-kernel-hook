# Manual step-by-step bisect of the shadow selftest control sequence.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/adb.exe'
$fb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/fastboot.exe'
$key = (Get-Content (Join-Path $root 'out/device/pixel8/stage1-superkey-v3.txt') -Raw).Trim()
$out = Join-Path $root 'out/kpm-stage1-pixel8-review'
$remote = '/data/local/tmp/rtgum-stage1-pixel8'
$boot = Join-Path $root 'out/device/pixel8/boot-kp0139-stage1-v5-cp1a.260405.005.img'

function Wait-Adb([int]$tries) {
    for ($i = 0; $i -lt $tries; $i++) {
        $d = & $adb devices 2>&1
        if ($d -match 'device\s*$') { return $true }
        Start-Sleep -Seconds 10
    }
    return $false
}

& $adb reboot bootloader 2>$null
Start-Sleep -Seconds 8
& $fb boot $boot 2>&1 | Select-Object -Last 1
if (-not (Wait-Adb 30)) { 'NO-DEVICE'; exit 1 }
$bc = ''
for ($i = 0; $i -lt 24; $i++) {
    $bc = & $adb shell getprop sys.boot_completed 2>&1
    if ($bc -match '1') { break }
    Start-Sleep -Seconds 5
}
"boot_completed=$bc"
& $adb shell chmod 0755 "$remote/rtgum-stage1-ctl" 2>$null
& $adb push (Join-Path $out 'rtgum-stage1.kpm') "$remote/rtgum-stage1.kpm" | Out-Null
& $adb push (Join-Path $out 'rtgum-stage1-ctl') "$remote/rtgum-stage1-ctl" | Out-Null
& $adb shell chmod 0755 "$remote/rtgum-stage1-ctl" 2>$null
$r = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl ready" 2>&1
if ($r -notmatch 'kpver=0xd09') { "READY-FAILED: $r"; exit 1 }
$r = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl load $remote/rtgum-stage1.kpm" 2>&1
if ($r -notmatch 'loaded') { "LOAD-FAILED: $r"; exit 1 }
$d = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl dmesg" 2>&1
$line = ($d | Select-String 'debug-pair-code=' | Select-Object -Last 1).Line
if ($line -notmatch 'debug-pair-code=(\d{6})') { "PAIR-CODE-MISSING"; exit 1 }
$p = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl session-pair $($Matches[1])" 2>&1
if ($p -notmatch 'session=([0-9a-f]{64})') { "PAIR-FAILED: $p"; exit 1 }
$session = $Matches[1]
Set-Content (Join-Path $out 'last-pixel8-session.txt') $session -NoNewline
$env = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session"
$ctl = "$remote/rtgum-stage1-ctl"

function Step([string]$name, [string]$command, [int]$settle = 2) {
    $r = & $adb shell "$env $ctl $command" 2>&1
    "STEP $name : $($r -join ' | ')"
    Start-Sleep -Seconds $settle
    $p = & $adb shell "$env $ctl ping" 2>&1
    if ($p -match 'pong') { "  ping OK" } else { "  PING-FAILED"; exit 1 }
}

'--- bisect: full hooks, then manual shadow control steps ---'
Step 'hook-full' 'control hook-art-shadow'
Step 'trust-clear' 'control shadow-trust-clear'
Step 'ghost-alloc' "control 'ghost-alloc 4096 3'"
Step 'status' 'control shadow-status'
$page = $null
$r = & $adb shell "$env $ctl control 'ghost-alloc 4096 3'" 2>&1
if ($r -match 'address=0x([0-9a-f]+)') { $page = $Matches[1] }
if (-not $page) { "NO-PAGE: $r"; exit 1 }
"page=0x$page"
Step 'register' "control 'shadow-register 0x$page'" 2
Step 'status2' 'control shadow-status'
Step 'patch' "control 'shadow-patch 0x$page 0x8 0xdeadbeefcafef00d'" 2
Step 'status3' 'control shadow-status'
Step 'read' "control 'shadow-read 0x$page 0x8'" 2
Step 'unregister' "control 'shadow-unregister 0x$page'" 2
Step 'ghost-free' "control 'ghost-free 0x$page'" 2
Step 'status-final' 'control shadow-status'
'BISECT-DONE all control steps survived'
