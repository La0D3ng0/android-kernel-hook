# rt-gum-sdk stage2 acceptance: one clean window.
# Boots KP, injects, verifies module load, scans proc hygiene, hot reloads module2.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$kpImg = Join-Path $root 'out\device\boot-kernelpatch-0.12.2-grus.img'
$keyFile = Join-Path $root 'out\device\stage0-superkey.txt'
$sessFile = Join-Path $root 'out\device\stage2-session-key.txt'
$ctl = "/data/local/tmp/rtgum-stage1/rtgum-stage1-ctl"
# Target a third-party app (never system Settings: repeated dispatch tests
# damaged com.android.settings once).
$package = "com.storm.smart"
$activity = "com.storm.smart/.activity.LogoActivity"
$module2 = "/data/local/tmp/rtgum-stage1/rtgum-stage2-module2.ghm"

function Wait-Device([int]$tries, [int]$seconds) {
    for ($i = 0; $i -lt $tries; $i++) {
        $d = adb devices | Select-String -Pattern "^\S+\s+device$"
        if ($d) { return $true }
        Start-Sleep -Seconds $seconds
    }
    return $false
}

# ---- boot to KernelPatch ----
adb kill-server 2>$null; adb start-server 2>$null | Out-Null
if (-not (Wait-Device 20 3)) { "NO-DEVICE — enable USB debugging"; exit 1 }
adb reboot bootloader 2>&1 | Out-Null
$f = $null
for ($i=0; $i -lt 40; $i++) { $f = fastboot devices 2>$null; if ($f) { break }; Start-Sleep -Seconds 3 }
if (-not $f) { "TIMEOUT: no fastboot"; exit 1 }
fastboot boot $kpImg 2>&1 | Select-Object -Last 1
if (-not (Wait-Device 60 5)) { "TIMEOUT: adb after KP boot — re-enable USB debugging"; exit 1 }
for ($i=0; $i -lt 40; $i++) { $bc = adb shell getprop sys.boot_completed 2>$null; if ($bc -match '1') { break }; Start-Sleep -Seconds 5 }
Start-Sleep -Seconds 8

# ---- deploy + arm ----
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tools\deploy-stage1.ps1') 2>&1 | Select-Object -Last 1
$key = (Get-Content $keyFile -Raw).Trim()
$sess = (Get-Content $sessFile -Raw).Trim()
$envPrefix = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$sess"
adb shell "$envPrefix $ctl control crashlog-clear" 2>&1
$remote = "$envPrefix $ctl stage2-bisect"
$bisect = cmd /c ('adb shell "{0}"' -f $remote) 2>&1
$bisect | Select-String -Pattern 'BISECT-READY|error' | ForEach-Object { $_.Line } | Select-Object -Last 2
$base = ""
$zygotePid = ""
$bisectLine = $bisect | Select-String -Pattern 'BISECT-READY' | Select-Object -First 1
if ($bisectLine -match 'BISECT-READY pid=(\d+) base=0x([0-9a-f]+)') {
    $zygotePid = $Matches[1]; $base = $Matches[2]
    "zygote=$zygotePid daemon_base=0x$base"
} else {
    "BISECT-READY NOT FOUND"; exit 1
}

# ---- register target package and launch ----
$module1 = "/data/local/tmp/rtgum-stage1/rtgum-stage2-module.ghm"
adb shell "$envPrefix $ctl daemon-config $package $module1" 2>&1
adb shell "am force-stop $package" 2>&1
adb shell "am start -n $activity" 2>&1 | Select-Object -First 1

# ---- wait for package dispatch (phase=3) ----
$appPid = ""; $st = ""; $ready = $false
for ($i=0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 10
    $app = adb shell "ps -A" 2>&1 | Select-String $package | Select-Object -First 1
    $appPid = ($app -split '\s+')[1]
    if ($appPid) {
        $st = adb shell "$envPrefix $ctl daemon-status $appPid" 2>&1
        if ($st -match 'phase=3') { $ready = $true; break }
    }
    if (-not (Wait-Device 1 1)) { "DEVICE DROPPED while waiting for dispatch"; exit 1 }
}
if (-not $ready) { "dispatch did not reach phase=3 in 150s (screen locked? app frozen?)"; $st; exit 1 }
"pid=$appPid"
$st
$mb = if ($st -match 'module_base=0x([0-9a-f]+)') { $Matches[1] } else { '' }
if (-not $mb) { "module_base missing"; exit 1 }

# ---- baseline hygiene scan ----
"--- baseline proc-scan ---"
$scan1 = adb shell "$envPrefix $ctl proc-scan $appPid $base $mb" 2>&1
$scan1
$tasksB = if ($scan1 -match 'tasks=(-?\d+)') { $Matches[1] } else { '' }
$fdsB = if ($scan1 -match 'fds=(-?\d+)') { $Matches[1] } else { '' }
$sockB = if ($scan1 -match 'sockets=(\d+)') { $Matches[1] } else { '' }

# ---- hot reload: module2 (清场再进场) ----
"--- hot reload module2 ---"
$reloadOut = adb shell "$envPrefix $ctl daemon-reload $appPid $package $module2" 2>&1
$reloadOut
if ($reloadOut -notmatch 'ok ') { "reload command failed"; exit 1 }
$st2 = ""
for ($i=0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 6
    $st2 = adb shell "$envPrefix $ctl daemon-status $appPid" 2>&1
    if ($st2 -match 'phase=4') { break }
    if (-not (Wait-Device 1 1)) { "DEVICE DROPPED after reload"; exit 1 }
}
$st2
if ($st2 -notmatch 'phase=4') { "RELOAD phase=4 not reached"; exit 1 }
$mb2 = if ($st2 -match 'module_base=0x([0-9a-f]+)') { $Matches[1] } else { '' }
if ($mb2) {
    "--- post-reload proc-scan ---"
    $scan2 = adb shell "$envPrefix $ctl proc-scan $appPid $base $mb2" 2>&1
    $scan2
    $tasksA = if ($scan2 -match 'tasks=(-?\d+)') { $Matches[1] } else { '' }
    $fdsA = if ($scan2 -match 'fds=(-?\d+)') { $Matches[1] } else { '' }
    $sockA = if ($scan2 -match 'sockets=(\d+)') { $Matches[1] } else { '' }
    "--- state delta: tasks $tasksB -> $tasksA, fds $fdsB -> $fdsA, sockets $sockB -> $sockA"
}
"--- reload markers ---"
$log = adb shell "cat /data/local/tmp/rtgum-stage1/rtgum-stage1-crash.log" 2>&1
$log | Select-String -Pattern 'module2|reload|unload|op=8' | ForEach-Object { $_.Line } | Select-Object -First 10

# ---- multi-app package dispatch (group-send / storm video / qingyu) ----
$module1 = "/data/local/tmp/rtgum-stage1/rtgum-stage2-module.ghm"
"--- third-party packages ---"
$pkgList = adb shell "pm list packages -3" 2>&1
$pkgList | ForEach-Object { $_.Line }
$apps = @("com.yousheng.qunfabao", "com.storm.smart")
foreach ($pkg in $apps) {
    $cfg = adb shell "$envPrefix $ctl daemon-config $pkg $module1" 2>&1
    "config $pkg -> $cfg"
    adb shell "am force-stop $pkg" 2>&1
    Start-Sleep -Seconds 2
    adb shell "monkey -p $pkg -c android.intent.category.LAUNCHER 1" 2>&1 | Select-Object -Last 1
    $ap = ""; $ok = $false
    for ($i=0; $i -lt 12; $i++) {
        Start-Sleep -Seconds 8
        $line = adb shell "ps -A" 2>&1 | Select-String $pkg | Select-Object -First 1
        $ap = ($line -split '\s+')[1]
        if ($ap) {
            $sx = adb shell "$envPrefix $ctl daemon-status $ap" 2>&1
            if ($sx -match 'phase=3') { $ok = $true; "app $pkg pid=$ap phase=3 OK"; break }
        }
        if (-not (Wait-Device 1 1)) { "DEVICE DROPPED at $pkg"; break }
    }
    if (-not $ok) { "app $pkg dispatch NOT reached (pid=$ap)" }
}
"--- per-app dispatch markers ---"
$log2 = adb shell "cat /data/local/tmp/rtgum-stage1/rtgum-stage1-crash.log" 2>&1
$log2 | Select-String -Pattern 'package-dispatch' | ForEach-Object { $_.Line } | Select-Object -Last 8
"--- alive ---"
$t=Get-Date; $r = adb shell "echo alive" 2>&1 | Select-Object -First 1; "shell($([int]((Get-Date)-$t).TotalMilliseconds)ms): $r"
