param(
    [string]$DeviceSerial = "",
    [switch]$FreshBoot,
    [string]$BootImage = "",
    [string]$KpmPath = "",
    [string]$CtlPath = "",
    [string]$LabApk = "",
    [string]$LabElf = ""
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
if ([string]::IsNullOrWhiteSpace($LabElf)) {
    $LabElf = Join-Path $projectDirectory "out\lab-apk\work\jni\arm64-v8a\libghostlab.so"
}
$superkeyPath = Join-Path $projectDirectory "out\device\pixel8\stage1-superkey-v3.txt"
foreach ($path in @($BootImage, $KpmPath, $CtlPath, $LabApk, $LabElf, $superkeyPath)) {
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
    for ($attempt = 0; $attempt -lt 90; ++$attempt) {
        if (((& adb -s $DeviceSerial shell getprop sys.boot_completed 2>$null) -join "").Trim() -eq "1") {
            break
        }
        Start-Sleep -Seconds 1
    }
    if ($attempt -ge 90) { throw "Android boot timeout" }
}

$remoteRoot = "/data/local/tmp/rtgum-vma"
$remoteCtl = "$remoteRoot/rtgum-stage1-ctl"
$remoteKpm = "$remoteRoot/rtgum-stage1.kpm"
$remoteElf = "$remoteRoot/libghostlab.so"
Invoke-Adb shell "mkdir -p $remoteRoot" | Out-Null
foreach ($pair in @(@($CtlPath, $remoteCtl), @($KpmPath, $remoteKpm), @($LabElf, $remoteElf))) {
    Invoke-Adb push $pair[0] $pair[1] | Out-Null
}
Invoke-Adb shell chmod 755 $remoteCtl | Out-Null
Invoke-Adb shell sync | Out-Null
foreach ($pair in @(@($CtlPath, $remoteCtl), @($KpmPath, $remoteKpm), @($LabElf, $remoteElf))) {
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

function Invoke-CtlLines {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" "RTGUM_SESSION_KEY=$session" $remoteCtl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ctl failed ($($Arguments -join ' ')): $($output -join ' ')"
    }
    return @($output)
}

function Invoke-Ctl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    return (Invoke-CtlLines @Arguments) -join " "
}

function Get-DumpRanges([string[]]$Lines) {
    return @($Lines | ForEach-Object {
        if ($_ -match '^vma ([0-9a-fA-F]+)-([0-9a-fA-F]+)$') {
            $start = [Convert]::ToUInt64($Matches[1], 16)
            $end = [Convert]::ToUInt64($Matches[2], 16)
            ('{0:x16}-{1:x16}' -f $start, $end)
        }
    } | Sort-Object -Unique)
}

function Get-ProcRanges([string[]]$Lines) {
    return @($Lines | ForEach-Object {
        if ($_ -match '^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s') {
            $start = [Convert]::ToUInt64($Matches[1], 16)
            $end = [Convert]::ToUInt64($Matches[2], 16)
            ('{0:x16}-{1:x16}' -f $start, $end)
        }
    } | Sort-Object -Unique)
}

function Range-Contains([string[]]$Ranges, [UInt64]$Address) {
    foreach ($range in $Ranges) {
        $pieces = $range -split '-'
        $start = [Convert]::ToUInt64($pieces[0], 16)
        $end = [Convert]::ToUInt64($pieces[1], 16)
        if ($Address -ge $start -and $Address -lt $end) { return $true }
    }
    return $false
}

Invoke-Adb install -r -t $LabApk | Out-Null
$bootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
Invoke-Adb logcat -c | Out-Null
& adb -s $DeviceSerial shell monkey -p dev.rtgum.lab -c android.intent.category.LAUNCHER 1 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Lab launch failed" }
$selfCheck = ""
for ($attempt = 0; $attempt -lt 30; ++$attempt) {
    Start-Sleep -Milliseconds 400
    $logOutput = & adb -s $DeviceSerial logcat -d 2>&1
    $selfCheck = ($logOutput | Select-String "memory-selfcheck" | Select-Object -Last 1).Line
    if ($selfCheck) { break }
}
$match = [regex]::Match($selfCheck, "pid=(\d+).*code-va=(0x[0-9a-fA-F]+).*tracer=(\d+).*pass=(\w+)")
if (-not $match.Success -or $match.Groups[3].Value -ne "0" -or
    $match.Groups[4].Value -ne "true") {
    throw "Lab self-check failed: $selfCheck"
}
$labPid = $match.Groups[1].Value
$labPc = $match.Groups[2].Value

$ghostReply = Invoke-Ctl vma-test-ghost-alloc $labPid
$ghostMatch = [regex]::Match($ghostReply, 'address=(0x[0-9a-fA-F]+)')
if (-not $ghostMatch.Success) { throw "ghost acceptance allocation failed: $ghostReply" }
$ghostText = $ghostMatch.Groups[1].Value
$ghostAddress = [Convert]::ToUInt64($ghostText.Substring(2), 16)
try {
    $matched = $false
    for ($attempt = 1; $attempt -le 5; ++$attempt) {
        $dumpLines = Invoke-CtlLines vma-dump $labPid
        if (($dumpLines -join "`n") -notmatch 'ghost=excluded-vmaless') {
            throw "VMA dump omitted the ghost exclusion contract"
        }
        # Independent acceptance baseline only. The production dump and
        # symbolizer never touch procfs; this helper elevates because Android's
        # shell domain cannot read another process' maps on this device.
        $procLines = & adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$SuperKey" `
            $remoteCtl vma-proc-baseline $labPid 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "privileged /proc maps baseline failed: $($procLines -join ' ')"
        }
        $dumpRanges = Get-DumpRanges $dumpLines
        $procRanges = Get-ProcRanges $procLines
        $delta = @(Compare-Object -ReferenceObject $procRanges -DifferenceObject $dumpRanges)
        if ($delta.Count -eq 0 -and $dumpRanges.Count -gt 0) {
            $matched = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $matched) {
        throw "kernel VMA ranges differ from /proc maps (dump=$($dumpRanges.Count) proc=$($procRanges.Count) delta=$($delta.Count))"
    }
    if ((Range-Contains $dumpRanges $ghostAddress) -or
        (Range-Contains $procRanges $ghostAddress)) {
        throw "VMA-less ghost address appeared in a visible range: $ghostText"
    }

    $symbolized = Invoke-Ctl vma-symbolize $labPid $labPc $remoteElf
    if ($symbolized -notmatch 'result=libghostlab\.so!lab_add\+0x0' -or
        $symbolized -notmatch 'identity=elf-header') {
        throw "unexpected symbolization result: $symbolized"
    }
    Write-Host $symbolized
    Write-Host "vma-ranges=$($dumpRanges.Count) proc-ranges=$($procRanges.Count) ghost=$ghostText hidden=1 tracer=0"
} finally {
    $freed = Invoke-Ctl vma-test-ghost-free $labPid $ghostText
    if ($freed -notmatch 'freed=1') { throw "ghost cleanup failed: $freed" }
}

Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
Start-Sleep -Seconds 2
$memoryStatus = Invoke-Ctl memory-status
if ($memoryStatus -notmatch 'mm-balance=0' -or $memoryStatus -notmatch 'inflight=0') {
    throw "mm reference accounting failed: $memoryStatus"
}
$finalBootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($finalBootId -ne $bootId) { throw "device rebooted during VMA smoke test" }

Write-Host "vma-smoke PASS"
Write-Host "symbol=libghostlab.so!lab_add+0x0 tracer=0 ghost-hidden=1"
Write-Host $memoryStatus
