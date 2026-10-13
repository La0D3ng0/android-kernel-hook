# rt-gum-sdk: one full shadow-selftest cycle (KP boot -> deploy -> pair -> hook -> kmsg -> selftest)
param(
    [switch]$SkipBoot,
    [ValidateSet('full', 'mem', 'dbg')]
    [string]$Hook = 'full',
    [switch]$PermanentServe,
    [switch]$NoStream
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/adb.exe'
$fb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/fastboot.exe'
$key = (Get-Content (Join-Path $root 'out/device/pixel8/stage1-superkey-v3.txt') -Raw).Trim()
$out = Join-Path $root 'out/kpm-stage1-pixel8-review'
$remote = '/data/local/tmp/rtgum-stage1-pixel8'
$boot = Join-Path $root 'out/device/pixel8/boot-kp0139-stage1-v5-cp1a.260405.005.img'
$stream = Join-Path $root 'out/device/pixel8/mako-shadow-kmsg-stream.txt'

function Wait-Adb([int]$tries) {
    for ($i = 0; $i -lt $tries; $i++) {
        $d = & $adb devices 2>&1
        if ($d -match 'device\s*$') { return $true }
        Start-Sleep -Seconds 10
    }
    return $false
}

if (-not $SkipBoot) {
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
} else {
    if (-not (Wait-Adb 3)) { 'NO-DEVICE'; exit 1 }
}

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
$code = $Matches[1]
$p = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl session-pair $code" 2>&1
if ($p -notmatch 'session=([0-9a-f]{64})') { "PAIR-FAILED: $p"; exit 1 }
$session = $Matches[1]
Set-Content (Join-Path $out 'last-pixel8-session.txt') $session -NoNewline
$env = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session"

# kmsg stream in a background job on the device side (skipped with -NoStream)
$streamJob = $null
if (-not $NoStream) {
    $streamJob = Start-Job -ScriptBlock {
        param($adbPath, $envPrefix, $ctlPath, $streamPath)
        & $adbPath shell "$envPrefix $ctlPath dmesg-w" 2>&1 | Out-File $streamPath
    } -ArgumentList $adb, $env, "$remote/rtgum-stage1-ctl", $stream
    Start-Sleep -Seconds 2
}
$hookCmd = if ($Hook -eq 'mem') { 'hook-art-shadow-mem' }
           elseif ($Hook -eq 'dbg') { 'hook-art-shadow-dbg' }
           else { 'hook-art-shadow' }
$r = & $adb shell "$env $remote/rtgum-stage1-ctl control $hookCmd" 2>&1
"${hookCmd}: $r"
if ($Hook -ne 'full') {
    # Isolation soak: keep the single hook installed and ping for a while.
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Seconds 5
        $p = & $adb shell "$env $remote/rtgum-stage1-ctl ping" 2>&1
        if ($p -notmatch 'pong') { "SOAK-FAILED at $($i*5)s"; break }
    }
    "SOAK-DONE"
    if ($streamJob) {
        Wait-Job $streamJob -Timeout 5 | Out-Null
        Stop-Job $streamJob | Out-Null
        Remove-Job $streamJob -Force | Out-Null
        "stream tail:"
        Get-Content $stream | Select-String 'rtgum-stage1' | Select-Object -Last 15
    }
    exit 0
}
if ($PermanentServe) {
    $r = & $adb shell "$env $remote/rtgum-stage1-ctl control shadow-debug-permanent" 2>&1
    "shadow-debug-permanent: $r"
}
$r = & $adb shell "$env $remote/rtgum-stage1-ctl shadow-selftest" 2>&1
"SELFTEST:"
$r
"rc=$LASTEXITCODE"
if ($streamJob) {
    Wait-Job $streamJob -Timeout 5 | Out-Null
    Stop-Job $streamJob | Out-Null
    Remove-Job $streamJob -Force | Out-Null
    "stream tail:"
    Get-Content $stream | Select-String 'rtgum-stage1' | Select-Object -Last 30
}
