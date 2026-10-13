# Observe the ART (mako) hook end to end on the device, without tearing it down.
#
# Scenario 9 stops at its first failed assertion and then unlinks everything,
# which hides the evidence. This script walks the same sequence but leaves the
# hook installed and reads the observers directly: the Lab's own logcat, its
# on-screen self-check, the daemon's status word and the kernel's shadow
# counters. It does NOT reboot or re-pair; it reuses the current session key.
#
# Zygote init (link/resolve/bootstrap) is delegated to `zygote-init-test`, which
# is idempotent and already implements the maps staging the resolve step needs.
# Configuration and launch are then done here, one step at a time.
param(
    [string]$Package = 'dev.rtgum.lab',
    [string]$Component = 'dev.rtgum.lab/.MainActivity',
    [int]$SettleSeconds = 20,
    [switch]$SkipInit
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $root '.toolchains/platform-tools-37.0.1/platform-tools/adb.exe'
$key = (Get-Content (Join-Path $root 'out/device/pixel8/stage1-superkey-v3.txt') -Raw).Trim()
$session = (Get-Content (Join-Path $root 'out/kpm-stage1-pixel8-review/last-pixel8-session.txt') -Raw).Trim()
$remote = '/data/local/tmp/rtgum-stage1-pixel8'
$ctl = "$remote/rtgum-stage1-ctl"
$authed = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session"

function Ctl([string]$a) { ((& $adb shell "$authed $ctl $a" 2>&1) | Out-String).Trim() }

$zygote = ((& $adb shell 'pidof zygote64' 2>&1) | Out-String).Trim()
"zygote=$zygote"
if (-not $zygote) { 'NO-ZYGOTE'; exit 1 }

if (-not $SkipInit) {
    'zygote-init: ' + (Ctl 'zygote-init-test')
}

# The daemon-config step is what pushes the mako ELF into the KPM cache, so it
# must run AFTER any new libmako-ghost.so is pushed.
'config: ' + (Ctl "control 'daemon-config $zygote $Package $remote/rtgum-stage2-jnicode-mako.ghm $remote/libmako-ghost.so'")

& $adb shell "logcat -c" 2>&1 | Out-Null
& $adb shell "am force-stop $Package" 2>&1 | Out-Null
Start-Sleep -Seconds 1
& $adb shell "am start -n $Component" 2>&1 | Select-Object -First 1
Start-Sleep -Seconds 6
$lab = ((& $adb shell "pidof $Package" 2>&1) | Out-String).Trim()
"app pid=$lab"
if ($lab) { 'daemon-status: ' + (Ctl "daemon-status $lab") }

Start-Sleep -Seconds $SettleSeconds

if ($lab) { 'daemon-status: ' + (Ctl "daemon-status $lab") }

'=== lab logcat ==='
& $adb shell 'logcat -d -s rtgum-lab:V rtgum-labscan:V' 2>&1 | Select-Object -Last 26

'=== mako kernel log ==='
& $adb shell "RTGUM_SUPERKEY=$key $ctl dmesg" 2>&1 |
    Select-String -Pattern 'rtgum-mako|rk-|jnicode-mako' | Select-Object -Last 20

'=== kernel counters (raw status line) ==='
(Ctl 'capabilities') -split ' ' | Where-Object { $_ -like 'shadow*' -or $_ -like 'hooks=*' }
