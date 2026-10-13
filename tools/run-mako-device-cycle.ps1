# Full ART (mako) device cycle: reboot into the KP boot image, load the KPM,
# deploy the current artifacts, pair a session and run scenario 9.
#
# Scenario 9 is the only path that drives mako's DecodeArtMethod. Its session
# key is one-time and lives in kernel memory, so a run that dies mid-way leaves
# the device unable to answer authenticated control commands at all; a reboot is
# the only way back. Hence the whole cycle in one script.
param(
    [string]$Package = 'dev.rtgum.lab',
    [string]$Component = 'dev.rtgum.lab/.MainActivity',
    [ValidateSet('Acceptance', 'Hold', 'Setup')]
    [string]$Mode = 'Acceptance',
    [string]$KpmPath = '',
    [string]$BootImagePath = '',
    [switch]$SkipReboot
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/adb.exe'
$fb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/fastboot.exe'
$key = (Get-Content (Join-Path $root 'out/device/pixel8/stage1-superkey-v3.txt') -Raw).Trim()
$out = Join-Path $root 'out/kpm-stage1-pixel8-review'
$remote = '/data/local/tmp/rtgum-stage1-pixel8'
$boot = if ($BootImagePath) {
    (Resolve-Path -LiteralPath $BootImagePath).Path
} else {
    Join-Path $root 'out/device/pixel8/boot-kp0139-stage1-v5-cp1a.260405.005.img'
}
$log = Join-Path $root 'out/mako-scenario9.txt'
$selectedKpm = if ($KpmPath) {
    (Resolve-Path -LiteralPath $KpmPath).Path
} else {
    Join-Path $out 'rtgum-stage1.kpm'
}

function Wait-Adb([int]$tries) {
    for ($i = 0; $i -lt $tries; $i++) {
        if ((& $adb devices 2>&1) -match 'device\s*$') { return $true }
        Start-Sleep -Seconds 10
    }
    return $false
}

if (-not $SkipReboot) {
    & $adb reboot 2>$null
    if (-not (Wait-Adb 30)) { 'NO-DEVICE after reboot'; exit 1 }
    Start-Sleep -Seconds 10
    & $adb reboot bootloader 2>$null
    Start-Sleep -Seconds 8
    & $fb boot $boot 2>&1 | Select-Object -Last 1
    if (-not (Wait-Adb 30)) { 'NO-DEVICE after KP boot'; exit 1 }
}
for ($i = 0; $i -lt 30; $i++) {
    if ((& $adb shell getprop sys.boot_completed 2>&1) -match '1') { break }
    Start-Sleep -Seconds 5
}

foreach ($f in @('rtgum-stage1.kpm', 'rtgum-stage1-ctl', 'rtgum-stage2-daemon.so',
                 'rtgum-stage2-jnicode-mako.ghm', 'rtgum-stage2-lab-mako.ghm',
                 'libmako-ghost.so')) {
    $localFile = if ($f -eq 'rtgum-stage1.kpm') {
        $selectedKpm
    } else {
        Join-Path $out $f
    }
    & $adb push $localFile "$remote/$f" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "adb push failed: $f" }
    $localMd5 = (Get-FileHash -Algorithm MD5 -LiteralPath $localFile).Hash.ToLowerInvariant()
    $remoteMd5Line = (& $adb shell "md5sum $remote/$f" 2>&1 | Out-String).Trim()
    $remoteMd5 = ($remoteMd5Line -split '\s+')[0].ToLowerInvariant()
    if ($remoteMd5 -ne $localMd5) {
        throw "push hash mismatch: $f local=$localMd5 remote=$remoteMd5"
    }
}
& $adb shell "chmod 0755 $remote/rtgum-stage1-ctl" 2>$null

$ready = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl ready" 2>&1
"ready: $ready"
if ($ready -notmatch 'kpver=0xd09(?:\s|$)') { 'READY-FAILED (expected kpver=0xd09)'; exit 1 }
$load = & $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl load $remote/rtgum-stage1.kpm" 2>&1
"load: $load"

$pairLine = (& $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl dmesg" 2>&1 |
    Select-String 'debug-pair-code=(\d{6})' | Select-Object -Last 1)
if (-not $pairLine) { 'PAIR-CODE-MISSING'; exit 1 }
$pair = $pairLine.Matches.Groups[1].Value
$pairOut = (& $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl session-pair $pair" 2>&1 | Out-String)
if ($pairOut -notmatch 'session=([0-9a-f]{64})') { "PAIR-FAILED: $pairOut"; exit 1 }
$session = $Matches[1]
Set-Content (Join-Path $out 'last-pixel8-session.txt') $session -NoNewline
"session ok"

if ($Mode -eq 'Setup') {
    'setup-only=1'
    exit 0
}

$testCommand = if ($Mode -eq 'Hold') {
    "mako-hold-test $Package"
} else {
    "mako-target-test $Package $Component"
}
$testOutput = & $adb shell "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session $remote/rtgum-stage1-ctl $testCommand" 2>&1 |
    ForEach-Object { $_.ToString() }
$testExitCode = $LASTEXITCODE
Set-Content -LiteralPath $log -Value $testOutput
"rc=$testExitCode"
$testOutput | Select-Object -Last 6
'=== mako dmesg ==='
& $adb shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl dmesg" 2>&1 |
    Select-String -Pattern 'rtgum-mako|id-candidate' | Select-Object -Last 16
