param(
    [string]$DeviceSerial = "",
    [switch]$FreshBoot,
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
    for ($attempt = 0; $attempt -lt 90; ++$attempt) {
        if (((& adb -s $DeviceSerial shell getprop sys.boot_completed 2>$null) -join "").Trim() -eq "1") {
            break
        }
        Start-Sleep -Seconds 1
    }
    if ($attempt -ge 90) { throw "Android boot timeout" }
}

$remoteRoot = "/data/local/tmp/rtgum-trace"
$remoteCtl = "$remoteRoot/rtgum-stage1-ctl"
$remoteKpm = "$remoteRoot/rtgum-stage1.kpm"
Invoke-Adb shell "mkdir -p $remoteRoot" | Out-Null
foreach ($pair in @(@($CtlPath, $remoteCtl), @($KpmPath, $remoteKpm))) {
    Invoke-Adb push $pair[0] $pair[1] | Out-Null
}
Invoke-Adb shell chmod 755 $remoteCtl | Out-Null
Invoke-Adb shell sync | Out-Null
foreach ($pair in @(@($CtlPath, $remoteCtl), @($KpmPath, $remoteKpm))) {
    $localSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteSha = (((Invoke-Adb shell sha256sum $pair[1]) -join " ") -split "\s+")[0].ToLowerInvariant()
    $localMd5 = (Get-FileHash -Algorithm MD5 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteMd5 = (((Invoke-Adb shell md5sum $pair[1]) -join " ") -split "\s+")[0].ToLowerInvariant()
    if ($localSha -ne $remoteSha -or $localMd5 -ne $remoteMd5) {
        throw "push hash mismatch for $($pair[0])"
    }
    Write-Host "hash verified sha256=$localSha md5=$localMd5"
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
if ($LASTEXITCODE -ne 0) { throw "session-manager failed: $sessionReply" }
$sessionMatch = [regex]::Match($sessionReply, "(?:session(?:-key)?|key)=([0-9A-Fa-f]+)")
if (-not $sessionMatch.Success) { $sessionMatch = [regex]::Match($sessionReply, "([0-9A-Fa-f]{32,})") }
if (-not $sessionMatch.Success) { throw "session-manager response did not contain a key" }
$session = $sessionMatch.Groups[1].Value

function Invoke-CtlLines {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" `
        "RTGUM_SESSION_KEY=$session" $remoteCtl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ctl failed ($($Arguments -join ' ')): $($output -join ' ')"
    }
    return @($output)
}

function Invoke-Ctl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    return (Invoke-CtlLines @Arguments) -join " "
}

# `control` accepts one opaque command string. Passing it as separate adb
# arguments lets Android's shell split the string before rtgum-stage1-ctl sees
# it, so preserve it as one quoted remote argument. The smoke commands placed
# here contain only numeric fields and fixed command names.
function Invoke-CtlControl {
    param([Parameter(Mandatory = $true)][string]$Command)
    if ($Command.Contains("'")) { throw "Unsupported quote in control command" }
    $remote = "env RTGUM_SUPERKEY=$superkey RTGUM_SESSION_KEY=$session " +
              "$remoteCtl control '$Command'"
    $output = & adb -s $DeviceSerial shell $remote 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ctl control failed ($Command): $($output -join ' ')"
    }
    return ($output -join "`n")
}

function Get-VmaRanges {
    param([string[]]$Lines)
    return @($Lines | ForEach-Object {
        if ($_ -match '^vma ([0-9a-fA-F]+)-([0-9a-fA-F]+)$') {
            ('{0:x16}-{1:x16}' -f [Convert]::ToUInt64($Matches[1], 16),
                                    [Convert]::ToUInt64($Matches[2], 16))
        }
    } | Sort-Object -Unique)
}

function Wait-TraceResult {
    param([int]$MinimumCount = 1)
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        Start-Sleep -Milliseconds 150
        $lines = & adb -s $DeviceSerial logcat -d -s rtgum-lab:I '*:S' 2>&1
        $hits = @($lines | Select-String 'kernel-trace-result')
        if ($hits.Count -ge $MinimumCount) { return $hits[-1].Line }
    }
    throw "kernel-trace-result log timeout"
}

Invoke-Adb install -r -t $LabApk | Out-Null
$bootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
Invoke-Adb logcat -c | Out-Null
& adb -s $DeviceSerial shell monkey -p dev.rtgum.lab -c android.intent.category.LAUNCHER 1 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Lab launch failed" }
$selfCheck = ""
for ($attempt = 0; $attempt -lt 40; ++$attempt) {
    Start-Sleep -Milliseconds 250
    $logs = & adb -s $DeviceSerial logcat -d 2>&1
    $selfCheck = ($logs | Select-String "memory-selfcheck" | Select-Object -Last 1).Line
    if ($selfCheck) { break }
}
$match = [regex]::Match($selfCheck, "pid=(\d+).*code-va=(0x[0-9a-fA-F]+).*tracer=(\d+).*pass=(\w+)")
if (-not $match.Success -or $match.Groups[3].Value -ne "0" -or
    $match.Groups[4].Value -ne "true") {
    throw "Lab self-check failed: $selfCheck"
}
$labPid = $match.Groups[1].Value
$labPcText = $match.Groups[2].Value
$labPc = [Convert]::ToUInt64($labPcText.Substring(2), 16)
$rangeEnd = '0x{0:x}' -f ($labPc + 0x1000UL)

# Warm until one complete untraced invocation leaves the VMA set unchanged.
# ART may lazily map receiver/JIT metadata during its first few calls; taking a
# baseline before that settles attributes normal runtime work to the tracer.
$beforeRanges = @()
$vmaStable = $false
$stableRounds = 0
for ($round = 0; $round -lt 12; ++$round) {
    $candidateBefore = Get-VmaRanges (Invoke-CtlLines vma-dump $labPid)
    Invoke-Adb logcat -c | Out-Null
    Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
    $warmup = Wait-TraceResult
    if ($warmup -notmatch 'value=3' -or $warmup -notmatch 'tracer=0') {
        throw "Lab warmup failed: $warmup"
    }
    Start-Sleep -Milliseconds 250
    $candidateAfter = Get-VmaRanges (Invoke-CtlLines vma-dump $labPid)
    $warmDelta = @(Compare-Object -ReferenceObject $candidateBefore `
                                  -DifferenceObject $candidateAfter)
    if ($warmDelta.Count -eq 0) {
        ++$stableRounds
    } else {
        $stableRounds = 0
    }
    $beforeRanges = $candidateAfter
    # A single quiet call is insufficient during app startup: ART can perform
    # another lazy map a few broadcasts later. Require at least six warm calls
    # and three consecutive unchanged snapshots.
    if ($round -ge 5 -and $stableRounds -ge 3) {
        $vmaStable = $true
        break
    }
}
if (-not $vmaStable -or $beforeRanges.Count -eq 0) {
    throw "Lab VMA set did not stabilize before trace"
}

$startReply = Invoke-Ctl trace-start $labPid $labPid $labPcText $labPcText $rangeEnd 64
$handleMatch = [regex]::Match($startReply, 'handle=(\d+)')
if (-not $handleMatch.Success -or $startReply -notmatch 'armed=1') {
    throw "trace arm failed: $startReply"
}
$handle = $handleMatch.Groups[1].Value
Write-Host $startReply

try {
    Invoke-Adb logcat -c | Out-Null
    Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
    $result = Wait-TraceResult
    if ($result -notmatch 'value=3' -or $result -notmatch "pid=$labPid" -or
        $result -notmatch "tid=$labPid" -or $result -notmatch 'tracer=0') {
        throw "traced Lab call failed: $result"
    }

    $status = ""
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        $status = Invoke-Ctl trace-status $handle
        if ($status -match 'state=complete' -and $status -match 'affinity-restored=1') { break }
        Start-Sleep -Milliseconds 100
    }
    if ($status -notmatch 'state=complete' -or $status -notmatch 'steps=64' -or
        $status -notmatch 'reason=maximum' -or $status -notmatch 'buffered=64' -or
        $status -notmatch 'dropped=0' -or $status -notmatch 'affinity-restored=1' -or
        $status -notmatch 'affinity-match=1') {
        throw "trace completion contract failed: $status"
    }
    Write-Host $status

    $traceText = ((Invoke-CtlLines trace-read $handle 32) +
                  (Invoke-CtlLines trace-read $handle 32)) -join "`n"
    $records = [regex]::Matches(
        $traceText,
        '(?m)^trace seq=(\d+) pc=(0x[0-9a-fA-F]+) timestamp=(\d+) (.*)$')
    if ($records.Count -ne 64) { throw "expected 64 trace records, got $($records.Count)" }
    [UInt64]$lastTimestamp = 0
    for ($index = 0; $index -lt $records.Count; ++$index) {
        $record = $records[$index]
        $sequence = [UInt64]$record.Groups[1].Value
        $pcText = $record.Groups[2].Value
        $pc = [Convert]::ToUInt64($pcText.Substring(2), 16)
        $timestamp = [UInt64]$record.Groups[3].Value
        $tail = $record.Groups[4].Value
        $expectedPc = $labPc + [UInt64](4 * $index)
        if ($sequence -ne [UInt64]($index + 1) -or $pc -ne $expectedPc) {
            throw "non-contiguous trace at index=$index seq=$sequence pc=$pcText expected=0x$($expectedPc.ToString('x'))"
        }
        if ($index -gt 0 -and $timestamp -lt $lastTimestamp) {
            throw "trace timestamps regressed at sequence=$sequence"
        }
        foreach ($register in 0..30) {
            if ($tail -notmatch "(?:^| )x$register=0x[0-9a-fA-F]+(?: |$)") {
                throw "trace sequence=$sequence omitted x$register"
            }
        }
        if ($tail -notmatch ' sp=0x[0-9a-fA-F]+ pstate=0x[0-9a-fA-F]+$') {
            throw "trace sequence=$sequence omitted SP/PSTATE"
        }
        $lastTimestamp = $timestamp
    }
    $emptyRead = Invoke-Ctl trace-read $handle 1
    if ($emptyRead -notmatch 'batch=0' -or $emptyRead -notmatch 'remaining=0') {
        throw "trace ring did not drain: $emptyRead"
    }

    $vmaDelta = @()
    for ($attempt = 0; $attempt -lt 5; ++$attempt) {
        $afterRanges = Get-VmaRanges (Invoke-CtlLines vma-dump $labPid)
        $vmaDelta = @(Compare-Object -ReferenceObject $beforeRanges `
                                      -DifferenceObject $afterRanges)
        if ($vmaDelta.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($vmaDelta.Count -ne 0) {
        throw "trace changed visible VMA ranges (delta=$($vmaDelta.Count))"
    }
} finally {
    $stopped = Invoke-Ctl trace-stop $handle
    $cleared = Invoke-Ctl trace-clear $handle
    if ($cleared -notmatch 'cleared=1') { throw "trace cleanup failed: $stopped / $cleared" }
}

# The target main loop must remain responsive after affinity restoration.
Invoke-Adb logcat -c | Out-Null
Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
$responsive = Wait-TraceResult
if ($responsive -notmatch 'value=3' -or $responsive -notmatch 'tracer=0') {
    throw "Lab was not responsive after trace: $responsive"
}

# An armed session must also be cancellable before its entry breakpoint fires.
# This exercises explicit stop, entry-HWBP removal, and affinity restoration
# independently of the automatic range/step-budget completion paths below.
$cancelReply = Invoke-Ctl trace-start $labPid $labPid $labPcText $labPcText $rangeEnd 64
$cancelMatch = [regex]::Match($cancelReply, 'handle=(\d+)')
if (-not $cancelMatch.Success) { throw "cancellable trace arm failed: $cancelReply" }
$cancelHandle = $cancelMatch.Groups[1].Value
$cancelStop = Invoke-Ctl trace-stop $cancelHandle
if ($cancelStop -notmatch 'stopped=1' -or $cancelStop -notmatch 'pending=0') {
    throw "armed trace did not stop synchronously: $cancelStop"
}
$cancelStatus = Invoke-Ctl trace-status $cancelHandle
if ($cancelStatus -notmatch 'state=complete' -or
    $cancelStatus -notmatch 'steps=0' -or
    $cancelStatus -notmatch 'reason=requested' -or
    $cancelStatus -notmatch 'affinity-restored=1' -or
    $cancelStatus -notmatch 'affinity-match=1') {
    throw "explicit stop contract failed: $cancelStatus"
}
$cancelClear = Invoke-Ctl trace-clear $cancelHandle
if ($cancelClear -notmatch 'cleared=1') { throw "explicit stop cleanup failed: $cancelClear" }

# A short range must stop independently of the much larger step budget.
$shortEnd = '0x{0:x}' -f ($labPc + 16UL)
$shortReply = Invoke-Ctl trace-start $labPid $labPid $labPcText $labPcText $shortEnd 64
$shortMatch = [regex]::Match($shortReply, 'handle=(\d+)')
if (-not $shortMatch.Success) { throw "short-range trace arm failed: $shortReply" }
$shortHandle = $shortMatch.Groups[1].Value
try {
    Invoke-Adb logcat -c | Out-Null
    Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
    $shortResult = Wait-TraceResult
    if ($shortResult -notmatch 'value=3' -or $shortResult -notmatch 'tracer=0') {
        throw "short-range Lab call failed: $shortResult"
    }
    $shortStatus = Invoke-Ctl trace-status $shortHandle
    if ($shortStatus -notmatch 'state=complete' -or $shortStatus -notmatch 'steps=4' -or
        $shortStatus -notmatch 'reason=range' -or $shortStatus -notmatch 'buffered=4' -or
        $shortStatus -notmatch 'affinity-restored=1' -or
        $shortStatus -notmatch 'affinity-match=1') {
        throw "short-range stop contract failed: $shortStatus"
    }
    $shortRead = (Invoke-CtlLines trace-read $shortHandle 4) -join "`n"
    if ([regex]::Matches($shortRead, '(?m)^trace seq=').Count -ne 4) {
        throw "short-range ring count failed"
    }
} finally {
    Invoke-Ctl trace-stop $shortHandle | Out-Null
    $shortClear = Invoke-Ctl trace-clear $shortHandle
    if ($shortClear -notmatch 'cleared=1') { throw "short-range cleanup failed: $shortClear" }
}

# 160 retired NOPs exceed the 128-entry ring. The oldest 32 records must be
# overwritten, with an exact drop count and a contiguous surviving suffix.
$overflowReply = Invoke-Ctl trace-start $labPid $labPid $labPcText $labPcText $rangeEnd 160
$overflowMatch = [regex]::Match($overflowReply, 'handle=(\d+)')
if (-not $overflowMatch.Success) { throw "overflow trace arm failed: $overflowReply" }
$overflowHandle = $overflowMatch.Groups[1].Value
try {
    Invoke-Adb logcat -c | Out-Null
    Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
    $overflowResult = Wait-TraceResult
    if ($overflowResult -notmatch 'value=3' -or $overflowResult -notmatch 'tracer=0') {
        throw "overflow Lab call failed: $overflowResult"
    }
    $overflowStatus = Invoke-Ctl trace-status $overflowHandle
    if ($overflowStatus -notmatch 'state=complete' -or
        $overflowStatus -notmatch 'steps=160' -or
        $overflowStatus -notmatch 'buffered=128' -or
        $overflowStatus -notmatch 'dropped=32' -or
        $overflowStatus -notmatch 'reason=maximum' -or
        $overflowStatus -notmatch 'affinity-restored=1' -or
        $overflowStatus -notmatch 'affinity-match=1') {
        throw "ring overwrite contract failed: $overflowStatus"
    }
    $overflowText = ""
    for ($batch = 0; $batch -lt 4; ++$batch) {
        $overflowText += ((Invoke-CtlLines trace-read $overflowHandle 32) -join "`n") + "`n"
    }
    $overflowRecords = [regex]::Matches($overflowText, '(?m)^trace seq=(\d+) pc=(0x[0-9a-fA-F]+)')
    if ($overflowRecords.Count -ne 128 -or
        $overflowRecords[0].Groups[1].Value -ne '33' -or
        $overflowRecords[127].Groups[1].Value -ne '160') {
        throw "ring overwrite suffix failed: records=$($overflowRecords.Count) first=$($overflowRecords[0].Groups[1].Value) last=$($overflowRecords[127].Groups[1].Value)"
    }
} finally {
    Invoke-Ctl trace-stop $overflowHandle | Out-Null
    $overflowClear = Invoke-Ctl trace-clear $overflowHandle
    if ($overflowClear -notmatch 'cleared=1') { throw "overflow cleanup failed: $overflowClear" }
}

# Exercise a real collision in the shared Software Step dispatcher. The
# shadow REPLACE breakpoint at the ninth NOP temporarily owns SS to execute
# the original instruction. CPU trace must observe that retired instruction,
# let Shadow Hook finish its one-shot transition, and then rearm itself.
Invoke-Ctl shadow-hook-enable | Out-Null
$shadowBefore = Invoke-Ctl shadow-hook-status
$shadowBeforeMatch = [regex]::Match($shadowBefore, 'hits=(\d+)')
if (-not $shadowBeforeMatch.Success) { throw "shadow hit baseline unavailable: $shadowBefore" }
[UInt64]$shadowHitsBefore = $shadowBeforeMatch.Groups[1].Value
$shadowSite = '0x{0:x}' -f ($labPc + 32UL)
$shadowInstalled = $false
try {
    $shadowInstall = Invoke-Ctl shadow-install $labPid $labPcText
    if ($shadowInstall -notmatch 'state=shadow-x') {
        throw "trace/shadow install failed: $shadowInstall"
    }
    $shadowInstalled = $true
    $shadowArm = Invoke-CtlControl "shadow-set-bp $labPid $shadowSite 0 0 0"
    if ($shadowArm -notmatch 'mode=0') { throw "trace/shadow arm failed: $shadowArm" }

    $coexistReply = Invoke-Ctl trace-start $labPid $labPid $labPcText $labPcText $rangeEnd 64
    $coexistMatch = [regex]::Match($coexistReply, 'handle=(\d+)')
    if (-not $coexistMatch.Success) { throw "trace/shadow trace arm failed: $coexistReply" }
    $coexistHandle = $coexistMatch.Groups[1].Value
    try {
        Invoke-Adb logcat -c | Out-Null
        Invoke-Adb shell "am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -p dev.rtgum.lab" | Out-Null
        $coexistResult = Wait-TraceResult
        if ($coexistResult -notmatch 'value=3' -or $coexistResult -notmatch 'tracer=0') {
            throw "trace/shadow Lab call failed: $coexistResult"
        }
        $coexistStatus = ""
        for ($attempt = 0; $attempt -lt 40; ++$attempt) {
            $coexistStatus = Invoke-Ctl trace-status $coexistHandle
            if ($coexistStatus -match 'state=complete' -and
                $coexistStatus -match 'affinity-restored=1') { break }
            Start-Sleep -Milliseconds 100
        }
        if ($coexistStatus -notmatch 'steps=64' -or
            $coexistStatus -notmatch 'reason=maximum' -or
            $coexistStatus -notmatch 'affinity-match=1') {
            throw "trace/shadow completion failed: $coexistStatus"
        }
        $coexistText = ((Invoke-CtlLines trace-read $coexistHandle 32) +
                        (Invoke-CtlLines trace-read $coexistHandle 32)) -join "`n"
        $coexistRecords = [regex]::Matches(
            $coexistText, '(?m)^trace seq=(\d+) pc=(0x[0-9a-fA-F]+)')
        if ($coexistRecords.Count -ne 64) {
            throw "trace/shadow expected 64 records, got $($coexistRecords.Count)"
        }
        for ($index = 0; $index -lt $coexistRecords.Count; ++$index) {
            $sequence = [UInt64]$coexistRecords[$index].Groups[1].Value
            $pcText = $coexistRecords[$index].Groups[2].Value
            $pc = [Convert]::ToUInt64($pcText.Substring(2), 16)
            if ($sequence -ne [UInt64]($index + 1) -or
                $pc -ne $labPc + [UInt64](4 * $index)) {
                throw "trace/shadow discontinuity at index=$index seq=$sequence pc=$pcText"
            }
        }
        $shadowAfter = Invoke-Ctl shadow-hook-status
        $shadowAfterMatch = [regex]::Match($shadowAfter, 'hits=(\d+)')
        if (-not $shadowAfterMatch.Success -or
            [UInt64]$shadowAfterMatch.Groups[1].Value -le $shadowHitsBefore) {
            throw "Shadow BRK did not collide with trace: before=$shadowBefore after=$shadowAfter"
        }
    } finally {
        Invoke-Ctl trace-stop $coexistHandle | Out-Null
        $coexistClear = Invoke-Ctl trace-clear $coexistHandle
        if ($coexistClear -notmatch 'cleared=1') {
            throw "trace/shadow cleanup failed: $coexistClear"
        }
    }
} finally {
    if ($shadowInstalled) {
        $shadowRelease = Invoke-Ctl shadow-release-page $labPid $labPcText
        if ($shadowRelease -notmatch 'shadow-release=1') {
            throw "trace/shadow page release failed: $shadowRelease"
        }
    }
}

$finalRanges = Get-VmaRanges (Invoke-CtlLines vma-dump $labPid)
$finalVmaDelta = @(Compare-Object -ReferenceObject $beforeRanges -DifferenceObject $finalRanges)
if ($finalVmaDelta.Count -ne 0) {
    throw "bounded/overflow trace changed visible VMA ranges (delta=$($finalVmaDelta.Count))"
}

# Regression proof for the two existing single-step consumers.
$hwbp = Invoke-Ctl hwbp-test
if ($hwbp -notmatch 'stage1-hwbp-test PASS') { throw "HWBP regression: $hwbp" }
$shadow = Invoke-Ctl shadow-brk-test
if ($shadow -notmatch 'stage2-shadow-brk PASS') { throw "Shadow step regression: $shadow" }

$finalBootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($finalBootId -ne $bootId) { throw "device rebooted during trace smoke test" }

Write-Host "trace-smoke PASS"
Write-Host "records=64 explicit-stop=1 range-stop=4 ring=128 dropped=32 coexist-shadow=1 result=3 tracer=0 maps-delta=0 affinity-restored=1"
Write-Host $hwbp
Write-Host $shadow
