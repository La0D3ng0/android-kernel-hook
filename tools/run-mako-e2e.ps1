# Full mako end-to-end cycle: reboot -> KP boot -> deploy -> pair -> scenario.
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

& $adb reboot 2>$null
if (-not (Wait-Adb 25)) { 'NO-DEVICE after reboot'; exit 1 }
Start-Sleep -Seconds 10
& $adb reboot bootloader 2>$null
Start-Sleep -Seconds 8
& $fb boot $boot 2>&1 | Select-Object -Last 1
if (-not (Wait-Adb 30)) { 'NO-DEVICE after KP boot'; exit 1 }
$bc = ''
for ($i = 0; $i -lt 24; $i++) {
    $bc = & $adb shell getprop sys.boot_completed 2>&1
    if ($bc -match '1') { break }
    Start-Sleep -Seconds 5
}
"boot_completed=$bc"
foreach ($f in @('rtgum-stage1.kpm', 'rtgum-stage1-ctl', 'rtgum-stage2-daemon.so',
                 'rtgum-stage2-jnicode-mako.ghm', 'libmako-ghost.so')) {
    & $adb push (Join-Path $out $f) "$remote/$f" 2>&1 | Out-Null
}
& $adb shell chmod 0755 "$remote/rtgum-stage1-ctl" 2>$null
$r = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl ready" 2>&1
if ($r -notmatch 'kpver=0xd09') { "READY-FAILED: $r"; exit 1 }
$r = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl load $remote/rtgum-stage1.kpm" 2>&1
if ($r -notmatch 'loaded') { "LOAD-FAILED: $r"; exit 1 }
$d = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl dmesg" 2>&1
$line = ($d | Select-String 'debug-pair-code=' | Select-Object -Last 1).Line
if ($line -notmatch 'debug-pair-code=(\d{6})') { 'PAIR-CODE-MISSING'; exit 1 }
$p = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl session-pair $($Matches[1])" 2>&1
if ($p -notmatch 'session=([0-9a-f]{64})') { "PAIR-FAILED: $p"; exit 1 }
$session = $Matches[1]
Set-Content (Join-Path $out 'last-pixel8-session.txt') $session -NoNewline
$env = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session"
$ctl = "$remote/rtgum-stage1-ctl"
$result = & $adb shell "$env $ctl zygote-jnicode-mako-test" 2>&1
$result
"rc=$LASTEXITCODE"
"--- daemon breadcrumbs ---"
$d = & $adb shell "$env $ctl dmesg" 2>&1
($d | Select-String 'rtgum-daemon\[' | Select-Object -Last 12).Line
"--- shadow status ---"
& $adb shell "$env $ctl control shadow-status" 2>&1
