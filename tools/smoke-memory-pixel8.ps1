param(
    [string]$DeviceSerial = "",
    [switch]$FreshBoot,
    [int]$RestartCycles = 5,
    [int]$ShadowReadCycles = 16,
    [int]$StabilitySeconds = 20,
    [string]$BootImage = "",
    [string]$KpmPath = "",
    [string]$CtlPath = "",
    [string]$LabApk = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BootImage)) {
    $BootImage = Join-Path $projectDirectory "out\device\pixel8\boot-kp0139-manager-v1-cp1a.260405.005.img"
}
if ([string]::IsNullOrWhiteSpace($KpmPath)) {
    $KpmPath = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review\rtgum-stage1.kpm"
}
if ([string]::IsNullOrWhiteSpace($CtlPath)) {
    $CtlPath = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review\rtgum-stage1-ctl"
}
if ([string]::IsNullOrWhiteSpace($LabApk)) {
    $LabApk = Join-Path $projectDirectory "out\lab-apk\rtgum-art-lab.apk"
}
$superkeyPath = Join-Path $projectDirectory "out\device\pixel8\stage1-superkey-v3.txt"
if ($RestartCycles -lt 1) { throw "RestartCycles must be at least 1" }
if ($ShadowReadCycles -lt 1) { throw "ShadowReadCycles must be at least 1" }
foreach ($path in @($BootImage, $KpmPath, $CtlPath, $LabApk, $superkeyPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}

if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    $devices = @(adb devices | Select-String "\sdevice$" | ForEach-Object {
        ($_.Line -split "\s+")[0]
    })
    if ($devices.Count -ne 1) { throw "Specify -DeviceSerial (online devices=$($devices.Count))" }
    $DeviceSerial = $devices[0]
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & adb -s $DeviceSerial @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed ($($Arguments -join ' ')): $($output -join ' ')"
    }
    return @($output)
}

if ($FreshBoot) {
    Invoke-Adb reboot bootloader | Out-Null
    $fastbootReady = $false
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        Start-Sleep -Seconds 1
        if ((fastboot devices) -match [regex]::Escape($DeviceSerial)) {
            $fastbootReady = $true
            break
        }
    }
    if (-not $fastbootReady) { throw "fastboot device timeout" }
    & fastboot -s $DeviceSerial boot $BootImage
    if ($LASTEXITCODE -ne 0) { throw "fastboot boot failed" }
    & adb -s $DeviceSerial wait-for-device
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        if (((& adb -s $DeviceSerial shell getprop sys.boot_completed 2>$null) -join "").Trim() -eq "1") {
            break
        }
        Start-Sleep -Seconds 1
    }
    if ($attempt -ge 60) { throw "Android boot timeout" }
}

$remoteCtl = "/data/local/tmp/rtgum-stage1-ctl"
$remoteKpm = "/data/local/tmp/rtgum-stage1.kpm"
Invoke-Adb push $CtlPath $remoteCtl | Out-Null
Invoke-Adb push $KpmPath $remoteKpm | Out-Null
Invoke-Adb shell chmod 755 $remoteCtl | Out-Null
Invoke-Adb shell sync | Out-Null

foreach ($pair in @(@($CtlPath, $remoteCtl), @($KpmPath, $remoteKpm))) {
    $localHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteHash = ((Invoke-Adb shell sha256sum $pair[1]) -join " " -split "\s+")[0].ToLowerInvariant()
    if ($localHash -ne $remoteHash) { throw "SHA-256 mismatch for $($pair[0])" }
    Write-Host "sha256 verified $localHash"
}

$superkey = [IO.File]::ReadAllText($superkeyPath).Trim()
$ready = (& adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl ready 2>&1) -join " "
if ($LASTEXITCODE -ne 0 -or $ready -notmatch "kpver=0xd09") {
    throw "KernelPatch readiness check failed: $ready"
}
Write-Host $ready

$info = (& adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl info 2>&1) -join " "
if ($LASTEXITCODE -ne 0) {
    $loaded = (& adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl load $remoteKpm 2>&1) -join " "
    if ($LASTEXITCODE -ne 0) { throw "KPM load failed: $loaded" }
    Write-Host $loaded
} else {
    Write-Host "reuse loaded rtgum-stage1"
}

$sessionReply = (& adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl session-manager 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "session-manager failed" }
$sessionMatch = [regex]::Match($sessionReply, "(?:session(?:-key)?|key)=([0-9A-Fa-f]+)")
if (-not $sessionMatch.Success) { $sessionMatch = [regex]::Match($sessionReply, "([0-9A-Fa-f]{32,})") }
if (-not $sessionMatch.Success) { throw "session-manager response did not contain a key" }
$session = $sessionMatch.Groups[1].Value

function Invoke-Ctl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" "RTGUM_SESSION_KEY=$session" $remoteCtl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ctl failed ($($Arguments -join ' ')): $($output -join ' ')"
    }
    return ($output -join " ")
}

function Invoke-CtlRaw {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" "RTGUM_SESSION_KEY=$session" $remoteCtl @Arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join " ") }
}

function Start-Lab {
    Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
    Invoke-Adb logcat -c | Out-Null
    & adb -s $DeviceSerial shell monkey -p dev.rtgum.lab -c android.intent.category.LAUNCHER 1 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Lab launch failed" }
    $line = ""
    for ($attempt = 0; $attempt -lt 30; ++$attempt) {
        Start-Sleep -Milliseconds 400
        # `-d` is also the PowerShell common-parameter abbreviation for
        # `-Debug`; passing it through an advanced helper silently turned
        # `logcat -d` into streaming `logcat`. Invoke adb directly here.
        $logOutput = & adb -s $DeviceSerial logcat -d 2>&1
        if ($LASTEXITCODE -ne 0) { throw "adb logcat -d failed" }
        $line = ($logOutput | Select-String "memory-selfcheck" | Select-Object -Last 1).Line
        if ($line) { break }
    }
    $match = [regex]::Match($line, "pid=(\d+).*magic-va=(0x[0-9a-fA-F]+).*code-va=(0x[0-9a-fA-F]+).*tracer=(\d+).*pass=(\w+)")
    if (-not $match.Success) { throw "Lab self-check log timeout or parse failure" }
    return [pscustomobject]@{
        Pid = $match.Groups[1].Value
        Magic = $match.Groups[2].Value
        Code = $match.Groups[3].Value
        Tracer = $match.Groups[4].Value
        Pass = $match.Groups[5].Value
    }
}

& adb -s $DeviceSerial install -r -t $LabApk 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Lab APK install failed" }
$bootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
$lab = Start-Lab
if ($lab.Tracer -ne "0" -or $lab.Pass -ne "true") { throw "Lab self-check failed" }

$magicRead = Invoke-Ctl memory-read $lab.Pid $lab.Magic 4
if ($magicRead -notmatch "hex=0142414c") { throw "magic baseline mismatch: $magicRead" }
$codeRead = Invoke-Ctl memory-read $lab.Pid $lab.Code 8
$codeMatch = [regex]::Match($codeRead, "hex=([0-9a-fA-F]{16})")
if (-not $codeMatch.Success) { throw "code baseline parse failed: $codeRead" }
$originalCode = $codeMatch.Groups[1].Value.ToLowerInvariant()

Invoke-Ctl memory-write $lab.Pid $lab.Magic 78563412 | Out-Null
if ((Invoke-Ctl memory-read $lab.Pid $lab.Magic 4) -notmatch "hex=78563412") {
    throw "ordinary write verification failed"
}
Invoke-Ctl memory-write $lab.Pid $lab.Magic 0142414c | Out-Null
if ((Invoke-Ctl memory-read $lab.Pid $lab.Magic 4) -notmatch "hex=0142414c") {
    throw "ordinary write restore failed"
}

$denied = Invoke-CtlRaw memory-read 1 0x0 4
if ($denied.ExitCode -eq 0 -or $denied.Output -notmatch "code=-13") {
    throw "default-deny policy failed: $($denied.Output)"
}

Invoke-Ctl shadow-hook-enable | Out-Null
Invoke-Ctl shadow-prepare $lab.Pid $lab.Code | Out-Null
Invoke-Ctl shadow-install $lab.Pid $lab.Code | Out-Null
Invoke-Ctl shadow-patch-code $lab.Pid $lab.Code 000020d4 | Out-Null
for ($shadowCycle = 1; $shadowCycle -le $ShadowReadCycles; ++$shadowCycle) {
    $shadowRead = Invoke-Ctl memory-read $lab.Pid $lab.Code 8
    if ($shadowRead -notmatch "view=shadow-original" -or
        $shadowRead -notmatch "hex=$originalCode") {
        throw "shadow original-view read failed in cycle ${shadowCycle}: $shadowRead"
    }
}
$blockedWrite = Invoke-CtlRaw memory-write $lab.Pid $lab.Code 1f2003d5
if ($blockedWrite.ExitCode -eq 0 -or $blockedWrite.Output -notmatch "code=-1") {
    throw "generic write was not blocked on a shadow page: $($blockedWrite.Output)"
}
$shadowStatus = Invoke-Ctl shadow-hook-status
if ($shadowStatus -notmatch "gup-switches=([1-9][0-9]*)" -or
    $shadowStatus -notmatch "gup-restores=([1-9][0-9]*)") {
    throw "GUP original-view switch was not observed: $shadowStatus"
}

Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
Start-Sleep -Seconds 2
$afterExit = Invoke-Ctl shadow-hook-status
if ($afterExit -notmatch "pages=0" -or $afterExit -notmatch "owned=0") {
    throw "shadow exit cleanup failed: $afterExit"
}

$pids = @()
for ($cycle = 1; $cycle -le $RestartCycles; ++$cycle) {
    $current = Start-Lab
    if ($current.Tracer -ne "0") { throw "TracerPid changed in cycle $cycle" }
    $read = Invoke-Ctl memory-read $current.Pid $current.Magic 4
    if ($read -notmatch "hex=0142414c") { throw "magic mismatch in cycle $cycle" }
    $pids += $current.Pid
    Write-Host "restart-cycle=$cycle pid=$($current.Pid) magic=0x4c414201 tracer=0"
    Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
    Start-Sleep -Milliseconds 500
}

if ($StabilitySeconds -gt 0) { Start-Sleep -Seconds $StabilitySeconds }
$finalBootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($finalBootId -ne $bootId) { throw "device rebooted during smoke test" }
$memoryStatus = Invoke-Ctl memory-status
if ($memoryStatus -notmatch "mm-balance=0" -or $memoryStatus -notmatch "inflight=0") {
    throw "mm reference accounting failed: $memoryStatus"
}
$finalShadow = Invoke-Ctl shadow-hook-status
if ($finalShadow -notmatch "pages=0" -or $finalShadow -notmatch "owned=0") {
    throw "shadow resources remain: $finalShadow"
}

Write-Host "memory-smoke PASS"
Write-Host "magic=0x4c414201 tracer=0 shadow-original=$originalCode"
Write-Host $memoryStatus
Write-Host $finalShadow
