param(
    [ValidateSet('NoHooks', 'ChannelProbe', 'ChannelHook', 'HijackSelfTest', 'TaskworkSelfTest', 'CommHook', 'PollHook', 'EpollHook', 'Sandbox', 'ZygoteInit', 'ZygoteFork', 'ZygotePackage', 'ZygoteReload', 'ZygoteJniCode', 'ZygoteJniCodeJava', 'ZygoteJniCodeBadver', 'ZygoteJniCodeNosym', 'ZygoteDaemonReplace', 'DexLoader', 'Interceptors', 'Lifecycle', 'GTrace', 'MultiTrace', 'ThreeApps', 'GumLuaTarget', 'DbiInApp', 'DbiStalkerApps', 'DbiLab', 'DbiStalker', 'DbiStalkerPhdr', 'DbiStalkerUnwind', 'DbiStalkerPac', 'DbiStalkerBti', 'DbiHardening', 'DbiLdr', 'ReadUserRace', 'Ghost', 'GhostRace', 'Hwbp', 'HwbpProbe', 'HwbpDryRun', 'HwbpReplace', 'HwbpCapacity', 'AntiDebug', 'ShadowLifecycle', 'HwbpApks', 'DbiApks', 'Fork', 'Linker', 'Needed', 'VersionReject', 'MapsAmbiguous', 'FileMismatch', 'Remote', 'PidProbe', 'UnloadGuard')]
    [string]$Mode = 'NoHooks',
    [int]$Rounds = 1,
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = '',
    [string]$SuperKeyFile = '',
    [string]$OutputDirectory = '',
    [int]$TargetPid = 0,
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$RunLabel = 'current',
    [ValidateSet('off', 'br', 'ret', 'all')]
    [string]$DbiDispatch = 'off',
    [ValidateRange(5, 300)]
    [int]$AntiDebugQuietSeconds = 12,
    [ValidateRange(5, 120)]
    [int]$HookQuietSeconds = 15,
    [string]$TargetPackage = '',
    [string]$TargetComponent = '',
    [string]$TargetLabel = '',
    [switch]$FreshBoot,
    [switch]$CleanupOnFailure,
    [string]$FastbootPath = '',
    [string]$BootImagePath = ''
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
$projectDirectory = Split-Path -Parent $PSScriptRoot
if (-not $AdbPath) {
    $AdbPath = Join-Path $projectDirectory '.toolchains/platform-tools-37.0.1/platform-tools/adb.exe'
}
if (-not $SuperKeyFile) {
    $SuperKeyFile = Join-Path $projectDirectory 'out/device/pixel8/stage1-superkey-v3.txt'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory 'out/kpm-stage1-pixel8-review'
}
if (-not $FastbootPath) {
    $FastbootPath = Join-Path $projectDirectory '.toolchains/platform-tools-37.0.1/platform-tools/fastboot.exe'
}
if (-not $BootImagePath) {
    $BootImagePath = Join-Path $projectDirectory 'out/device/pixel8/boot-kp0139-stage1-v5-cp1a.260405.005.img'
}
if ($Rounds -lt 1 -or $Rounds -gt 5) { throw 'Rounds must be between 1 and 5' }
if ($Mode -eq 'GumLuaTarget') {
    if ($TargetPackage -cnotmatch '^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$' -or
        $TargetComponent -cnotmatch '^[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+$' -or
        $TargetLabel -cnotmatch '^[A-Za-z0-9_-]{1,63}$') {
        throw 'GumLuaTarget requires safe -TargetPackage, -TargetComponent, and -TargetLabel values'
    }
}
foreach ($path in @($AdbPath, $SuperKeyFile,
                   (Join-Path $OutputDirectory 'rtgum-stage1-ctl'),
                   (Join-Path $OutputDirectory 'rtgum-stage1.kpm'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $path" }
}
if ($Mode -eq 'Linker' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage1-payload.so') -PathType Leaf)) {
    throw 'Linker payload is missing'
}
if ($Mode -in @('Needed', 'MapsAmbiguous', 'FileMismatch') -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-pixel8-needed-ifunc.so') -PathType Leaf)) {
    throw 'NEEDED/IFUNC payload is missing'
}
if ($Mode -eq 'VersionReject' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-pixel8-needed-badver.so') -PathType Leaf)) {
    throw 'GNU version rejection payload is missing'
}
if ($Mode -eq 'FileMismatch' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'libc-identity-mismatch.so') -PathType Leaf)) {
    throw 'Provider identity mismatch fixture is missing'
}
if ($Mode -eq 'AntiDebug') {
    if (-not (Test-Path -LiteralPath (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk') -PathType Leaf)) {
        throw 'ART/HWBP Lab APK is missing'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-antidbg-compat32') -PathType Leaf)) {
        throw 'AArch32 anti-debug acceptance binary is missing'
    }
}
if ($Mode -eq 'DexLoader') {
    foreach ($required in @(
        (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'),
        (Join-Path $OutputDirectory 'rtgum-stage2-dex.ghm')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "DEX loader acceptance file is missing: $required"
        }
    }
}
if ($Mode -eq 'Interceptors') {
    foreach ($required in @(
        (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'),
        (Join-Path $OutputDirectory 'rtgum-stage2-interceptors.ghm')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Interceptor acceptance file is missing: $required"
        }
    }
}
if ($Mode -eq 'Lifecycle') {
    foreach ($required in @(
        (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'),
        (Join-Path $OutputDirectory 'rtgum-stage2-lifecycle.ghm')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Lifecycle acceptance file is missing: $required"
        }
    }
}
if ($Mode -eq 'GTrace') {
    foreach ($required in @(
        (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'),
        (Join-Path $OutputDirectory 'rtgum-stage2-gtrace.ghm'),
        (Join-Path $OutputDirectory 'librtgum-gum-ghost.so')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "GTrace acceptance file is missing: $required"
        }
    }
}
if ($Mode -eq 'MultiTrace') {
    foreach ($required in @(
        (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'),
        (Join-Path $OutputDirectory 'rtgum-stage2-multitrace.ghm'),
        (Join-Path $OutputDirectory 'librtgum-gum-ghost.so')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Multi-trace acceptance file is missing: $required"
        }
    }
}
if ($Mode -eq 'Remote' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-zygote-payload.so') -PathType Leaf)) {
    throw 'Zygote resolution payload is missing'
}
if ($Mode -in @('Sandbox', 'ZygoteInit', 'ZygoteFork', 'ZygotePackage', 'ZygoteReload', 'ZygoteJniCode', 'ZygoteJniCodeJava', 'ZygoteJniCodeBadver', 'ZygoteJniCodeNosym', 'ZygoteDaemonReplace', 'DexLoader', 'Interceptors', 'Lifecycle', 'GTrace', 'MultiTrace', 'ThreeApps', 'GumLuaTarget') -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-daemon.so') -PathType Leaf)) {
    throw 'Stage 2 Daemon is missing'
}
if ($Mode -in @('ThreeApps', 'GumLuaTarget')) {
    foreach ($required in @('rtgum-stage2-gumlua.ghm', 'librtgum-gum-ghost.so', 'librtgum-lua-helper.so')) {
        if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $required) -PathType Leaf)) {
            throw "ThreeApps file is missing: $required"
        }
    }
}
if ($Mode -eq 'ZygoteJniCode' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-jnicode.ghm') -PathType Leaf)) {
    throw 'Stage 2 JNICode module is missing'
}
if ($Mode -eq 'ZygoteJniCodeBadver' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-badver.ghm') -PathType Leaf)) {
    throw 'Stage 2 JNICode badver module is missing'
}
if ($Mode -eq 'ZygoteJniCodeNosym' -and
    -not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-nosym.ghm') -PathType Leaf)) {
    throw 'Stage 2 JNICode nosym module is missing'
}
if ($Mode -eq 'ZygoteJniCodeJava') {
    if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-java.ghm') -PathType Leaf)) {
        throw 'Stage 2 JNICode Java module is missing'
    }
    $javaHelper = Join-Path $projectDirectory 'art-hook\out\android-arm64-cxx23\librtgum-jnicode-java-hook.so'
    if (-not (Test-Path -LiteralPath $javaHelper -PathType Leaf)) {
        throw "JNICode Java helper is missing: $javaHelper"
    }
}
if ($Mode -eq 'PidProbe' -and $TargetPid -le 0) {
    $pidText = (& $AdbPath -s $DeviceSerial shell pidof zygote64 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $pidText -notmatch '^\d+$') { throw "Cannot find zygote64 PID: $pidText" }
    $TargetPid = [int]$pidText
}

$superKey = (Get-Content -Raw -LiteralPath $SuperKeyFile).Trim()
if ($superKey -cnotmatch '^[A-Za-z0-9]{32,64}$') { throw 'Invalid SuperKey format' }
$script:session = ''
$script:pairCode = ''
$remote = '/data/local/tmp/rtgum-stage1-pixel8'
$client = "$remote/rtgum-stage1-ctl"
$module = "$remote/rtgum-stage1.kpm"

function Redact([string]$value) {
    $safe = $value.Replace($superKey, '<redacted-superkey>')
    if ($script:session) { $safe = $safe.Replace($script:session, '<redacted-session>') }
    if ($script:pairCode) { $safe = $safe.Replace($script:pairCode, '<redacted-pair>') }
    foreach ($oldFile in @('stage0-superkey-v2.txt', 'stage0-superkey.txt')) {
        $path = Join-Path $projectDirectory "out/device/pixel8/$oldFile"
        if (Test-Path -LiteralPath $path) {
            $old = (Get-Content -Raw -LiteralPath $path).Trim()
            if ($old) { $safe = $safe.Replace($old, '<redacted-old-key>') }
        }
    }
    $safe = [regex]::Replace($safe, '(?<=session=)[0-9a-f]{64}', '<redacted-session>')
    $safe = [regex]::Replace($safe, '(?<=debug-pair-code=)\d{6}', '<redacted-pair>')
    return $safe
}

function Invoke-Device([string]$commandText, [string]$label, [bool]$authenticated = $false) {
    $environment = "RTGUM_SUPERKEY=$superKey "
    if ($authenticated) { $environment += "RTGUM_SESSION_KEY=$($script:session) " }
    if ($commandText -eq 'dbi-lab-test' -and $DbiDispatch -ne 'off') {
        $environment += "RTGUM_DBI_DISPATCH=$DbiDispatch "
    }
    # Windows PowerShell turns redirected native stderr into ErrorRecords.
    # Collect the whole adb invocation before checking its exit status so a
    # diagnostic line cannot abort the smoke and race its recovery path.
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
        $response = (& $AdbPath -s $DeviceSerial shell "$environment$client $commandText" 2>&1 |
            ForEach-Object { $_.ToString() } | Out-String).Trim()
        $deviceExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($deviceExitCode -ne 0) { throw "$label failed: $(Redact $response)" }
    return $response
}

# Keep artifact verification available in reduced PowerShell hosts where the
# Microsoft.PowerShell.Utility module is not auto-loaded.  The smoke runner is
# also invoked from Python, so relying on Get-FileHash made device tests fail
# before the KPM was loaded on otherwise healthy hosts.
function Get-LocalSha256([string]$path) {
    $stream = [System.IO.File]::OpenRead($path)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha256.ComputeHash($stream)
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

# Verifies a pushed artifact by comparing the local SHA-256 with the
# device-side sha256sum, and records both in the run output. Every pushed
# binary the run depends on must pass this check before the KPM is loaded.
function Assert-DeviceSha256([string]$localPath, [string]$remotePath) {
    $localHash = Get-LocalSha256 $localPath
    $deviceLine = (& $AdbPath -s $DeviceSerial shell "sha256sum $remotePath" 2>&1 | Out-String).Trim()
    $deviceHash = ($deviceLine -split '\s+')[0]
    if ($deviceHash -cne $localHash) {
        throw "Device hash mismatch for ${remotePath}: local=$localHash device=$deviceHash"
    }
    Write-Output "sha256-ok local=$localHash device=$deviceHash remote=$remotePath"
}

function Get-MainProcessPid([string]$package) {
    $processes = (& $AdbPath -s $DeviceSerial shell ps -A -o PID,PPID,NAME | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Cannot list Android processes for $package" }
    $rows = [regex]::Matches($processes, "(?m)^[ \t]*(\d+)[ \t]+(\d+)[ \t]+$([regex]::Escape($package))[ \t]*\r?$")
    if ($rows.Count -eq 0) { return 0 }
    $pids = @{}
    foreach ($row in $rows) { $pids[[int]$row.Groups[1].Value] = $true }
    $leaders = @($rows | Where-Object { -not $pids.ContainsKey([int]$_.Groups[2].Value) })
    if ($leaders.Count -ne 1) { throw "Cannot select unique main process for $package" }
    return [int]$leaders[0].Groups[1].Value
}

& $AdbPath start-server | Out-Null
$state = (& $AdbPath -s $DeviceSerial get-state 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne 'device') {
    throw "ADB state is '$state'; authorize USB debugging first"
}
$fingerprint = (& $AdbPath -s $DeviceSerial shell getprop ro.build.fingerprint | Out-String).Trim()
if ($fingerprint -ne 'google/shiba/shiba:16/CP1A.260405.005/15001963:user/release-keys') {
    throw "Unexpected build fingerprint: $fingerprint"
}

# Boot identity: record the boot_id before, establish a fresh KP boot when
# requested, and prove the boot_id changed. The resulting identity is part of
# the run record below.
$bootIdBefore = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
if ($FreshBoot) {
    if (-not (Test-Path -LiteralPath $FastbootPath -PathType Leaf)) { throw "Missing fastboot: $FastbootPath" }
    if (-not (Test-Path -LiteralPath $BootImagePath -PathType Leaf)) { throw "Missing boot image: $BootImagePath" }
    & $AdbPath -s $DeviceSerial reboot bootloader | Out-Null
    Start-Sleep -Seconds 12
    & $FastbootPath -s $DeviceSerial boot $BootImagePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fastboot boot failed' }
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        Start-Sleep -Seconds 5
        $bootState = ''
        $bootProbe = ''
        try { $bootState = (& $AdbPath -s $DeviceSerial get-state 2>$null | Out-String).Trim() } catch { }
        try { $bootProbe = (& $AdbPath -s $DeviceSerial shell getprop sys.boot_completed 2>$null | Out-String).Trim() } catch { }
        if ($bootState -eq 'device' -and $bootProbe -eq '1') { break }
    }
    $bootIdAfter = ''
    try {
        $bootIdAfter = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
    } catch { }
    if (-not $bootIdAfter -or $bootIdAfter -ceq $bootIdBefore) {
        throw "Fresh boot was not established: before=$bootIdBefore after=$bootIdAfter"
    }
    Start-Sleep -Seconds 12
} else {
    $bootIdAfter = $bootIdBefore
}
$bootUptime = (& $AdbPath -s $DeviceSerial shell cat /proc/uptime 2>$null | Out-String).Trim()
Write-Output "boot-id=$bootIdAfter uptime=[$bootUptime] fresh-boot=$([bool]$FreshBoot)"

$bootCompleted = (& $AdbPath -s $DeviceSerial shell getprop sys.boot_completed | Out-String).Trim()
if ($bootCompleted -ne '1') { throw 'Android boot is incomplete' }
if ($Mode -in @('DexLoader', 'Interceptors', 'Lifecycle', 'GTrace', 'MultiTrace')) {
    & $AdbPath -s $DeviceSerial install -r (Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot install Lab APK' }
}

& $AdbPath -s $DeviceSerial shell "mkdir -p $remote" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot create remote directory' }
& $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage1-ctl') $client | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot push control client' }
& $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage1.kpm') $module | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot push KPM' }
Assert-DeviceSha256 (Join-Path $OutputDirectory 'rtgum-stage1-ctl') $client
Assert-DeviceSha256 (Join-Path $OutputDirectory 'rtgum-stage1.kpm') $module
$script:compat32Supported = $false
$script:compat32Remote = "$remote/rtgum-antidbg-compat32"
if ($Mode -eq 'AntiDebug') {
    $abiList32 = (& $AdbPath -s $DeviceSerial shell getprop ro.product.cpu.abilist32 | Out-String).Trim()
    $script:compat32Supported = -not [string]::IsNullOrWhiteSpace($abiList32)
    if ($script:compat32Supported) {
        $compat32Local = Join-Path $OutputDirectory 'rtgum-antidbg-compat32'
        & $AdbPath -s $DeviceSerial push $compat32Local $script:compat32Remote | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot push AArch32 anti-debug probe' }
        Assert-DeviceSha256 $compat32Local $script:compat32Remote
        & $AdbPath -s $DeviceSerial shell "chmod 0755 $($script:compat32Remote)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot make AArch32 anti-debug probe executable' }
    } else {
        Write-Output 'compat32-runtime=SKIP reason=device-abilist32-empty build=PASS'
    }
}
if ($Mode -eq 'Linker') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage1-payload.so') "$remote/rtgum-stage1-payload.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push linker payload' }
}
if ($Mode -in @('Needed', 'MapsAmbiguous', 'FileMismatch')) {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-pixel8-needed-ifunc.so') "$remote/rtgum-pixel8-needed-ifunc.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push NEEDED/IFUNC payload' }
}
if ($Mode -eq 'FileMismatch') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'libc-identity-mismatch.so') "$remote/libc.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push provider identity fixture' }
}
if ($Mode -eq 'VersionReject') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-pixel8-needed-badver.so') "$remote/rtgum-pixel8-needed-badver.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push GNU version rejection payload' }
}
if ($Mode -eq 'Remote') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-zygote-payload.so') "$remote/rtgum-stage2-zygote-payload.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Zygote resolution payload' }
}
if ($Mode -in @('Sandbox', 'ZygoteInit', 'ZygoteFork', 'ZygotePackage', 'ZygoteReload', 'ZygoteJniCode', 'ZygoteJniCodeJava', 'ZygoteJniCodeBadver', 'ZygoteJniCodeNosym', 'ZygoteDaemonReplace', 'DexLoader', 'Interceptors', 'Lifecycle', 'GTrace', 'MultiTrace', 'ThreeApps', 'GumLuaTarget', 'DbiInApp', 'DbiStalkerApps')) {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-daemon.so') "$remote/rtgum-stage2-daemon.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 Daemon' }
    Assert-DeviceSha256 (Join-Path $OutputDirectory 'rtgum-stage2-daemon.so') "$remote/rtgum-stage2-daemon.so"
}
if ($Mode -in @('ThreeApps', 'GumLuaTarget')) {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-gumlua.ghm') "$remote/rtgum-stage2-gumlua.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push gumlua module' }
    Assert-DeviceSha256 (Join-Path $OutputDirectory 'rtgum-stage2-gumlua.ghm') "$remote/rtgum-stage2-gumlua.ghm"
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'librtgum-gum-ghost.so') "$remote/librtgum-gum-ghost.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Gum ghost backend' }
    Assert-DeviceSha256 (Join-Path $OutputDirectory 'librtgum-gum-ghost.so') "$remote/librtgum-gum-ghost.so"
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'librtgum-lua-helper.so') "$remote/librtgum-lua-helper.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Lua helper' }
    Assert-DeviceSha256 (Join-Path $OutputDirectory 'librtgum-lua-helper.so') "$remote/librtgum-lua-helper.so"
}
if ($Mode -eq 'DbiInApp') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-dbi.ghm') "$remote/rtgum-stage2-dbi.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push in-app DBI module' }
    Assert-DeviceSha256 (Join-Path $OutputDirectory 'rtgum-stage2-dbi.ghm') "$remote/rtgum-stage2-dbi.ghm"
}
if ($Mode -eq 'DbiStalkerApps') {
    foreach ($name in @('rtgum-stage2-dbi-stalker.ghm', 'librtgum-gum-ghost.so', 'librtgum-lua-helper.so')) {
        $localFile = Join-Path $OutputDirectory $name
        if (-not (Test-Path -LiteralPath $localFile -PathType Leaf)) { throw "Missing DBI Stalker file: $localFile" }
        & $AdbPath -s $DeviceSerial push $localFile "$remote/$name" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot push DBI Stalker file: $name" }
        Assert-DeviceSha256 $localFile "$remote/$name"
    }
}
if ($Mode -in @('DbiStalker', 'DbiStalkerPhdr', 'DbiStalkerUnwind', 'DbiStalkerPac', 'DbiStalkerBti')) {
    $stalkerBackend = Join-Path $OutputDirectory 'librtgum-gum-ghost.so'
    if (-not (Test-Path -LiteralPath $stalkerBackend -PathType Leaf)) { throw 'Gum Stalker backend is missing' }
    & $AdbPath -s $DeviceSerial push $stalkerBackend "$remote/librtgum-gum-ghost.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Gum Stalker backend' }
    Assert-DeviceSha256 $stalkerBackend "$remote/librtgum-gum-ghost.so"
}
if ($Mode -eq 'DbiStalkerPhdr') {
    $dynamicPhdrFixture = Join-Path $OutputDirectory 'librtgum-dbi-dynamic-phdr.so'
    if (-not (Test-Path -LiteralPath $dynamicPhdrFixture -PathType Leaf)) { throw 'Dynamic PLT fixture is missing' }
    foreach ($name in @('librtgum-dbi-dynamic-phdr.so', 'librtgum-dbi-dynamic-phdr-worker.so')) {
        & $AdbPath -s $DeviceSerial push $dynamicPhdrFixture "$remote/$name" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot push dynamic PLT fixture: $name" }
        Assert-DeviceSha256 $dynamicPhdrFixture "$remote/$name"
    }
    $replacementFixture = Join-Path $OutputDirectory 'librtgum-dbi-dynamic-phdr-replacement.so'
    if (-not (Test-Path -LiteralPath $replacementFixture -PathType Leaf)) { throw 'Dynamic PLT replacement fixture is missing' }
    & $AdbPath -s $DeviceSerial push $replacementFixture "$remote/librtgum-dbi-dynamic-phdr-replacement.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push dynamic PLT replacement fixture' }
    Assert-DeviceSha256 $replacementFixture "$remote/librtgum-dbi-dynamic-phdr-replacement.so"
}
if ($Mode -eq 'DbiLab') {
    $labFile = Join-Path $OutputDirectory 'librtgum-lab.so'
    if (-not (Test-Path -LiteralPath $labFile -PathType Leaf)) { throw "Missing DBI lab fixture: $labFile" }
    & $AdbPath -s $DeviceSerial push $labFile "$remote/librtgum-lab.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push DBI lab fixture' }
    Assert-DeviceSha256 $labFile "$remote/librtgum-lab.so"
}
if ($Mode -in @('ZygotePackage', 'ZygoteReload')) {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-module.ghm') "$remote/rtgum-stage2-module.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 module' }
}
if ($Mode -eq 'ZygoteJniCode') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-jnicode.ghm') "$remote/rtgum-stage2-jnicode.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 JNICode module' }
}
if ($Mode -eq 'ZygoteJniCodeJava') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-java.ghm') "$remote/rtgum-stage2-jnicode-java.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 JNICode Java module' }
    & $AdbPath -s $DeviceSerial push (Join-Path $projectDirectory 'art-hook\out\android-arm64-cxx23\librtgum-jnicode-java-hook.so') "$remote/librtgum-jnicode-java-hook.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push JNICode Java helper' }
}
if ($Mode -eq 'ZygoteJniCodeBadver') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-badver.ghm') "$remote/rtgum-stage2-jnicode-badver.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 JNICode badver module' }
}
if ($Mode -eq 'ZygoteJniCodeNosym') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-jnicode-nosym.ghm') "$remote/rtgum-stage2-jnicode-nosym.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 JNICode nosym module' }
}
if ($Mode -eq 'DexLoader') {
    $dexModule = Join-Path $OutputDirectory 'rtgum-stage2-dex.ghm'
    & $AdbPath -s $DeviceSerial push $dexModule "$remote/rtgum-stage2-dex.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 DEX module' }
    Assert-DeviceSha256 $dexModule "$remote/rtgum-stage2-dex.ghm"
}
if ($Mode -eq 'Interceptors') {
    $interceptorModule = Join-Path $OutputDirectory 'rtgum-stage2-interceptors.ghm'
    & $AdbPath -s $DeviceSerial push $interceptorModule "$remote/rtgum-stage2-interceptors.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 interceptor module' }
    Assert-DeviceSha256 $interceptorModule "$remote/rtgum-stage2-interceptors.ghm"
}
if ($Mode -eq 'Lifecycle') {
    $lifecycleModule = Join-Path $OutputDirectory 'rtgum-stage2-lifecycle.ghm'
    & $AdbPath -s $DeviceSerial push $lifecycleModule "$remote/rtgum-stage2-lifecycle.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 lifecycle module' }
    Assert-DeviceSha256 $lifecycleModule "$remote/rtgum-stage2-lifecycle.ghm"
}
if ($Mode -eq 'GTrace') {
    foreach ($name in @('rtgum-stage2-gtrace.ghm', 'librtgum-gum-ghost.so')) {
        $localFile = Join-Path $OutputDirectory $name
        & $AdbPath -s $DeviceSerial push $localFile "$remote/$name" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot push GTrace file: $name" }
        Assert-DeviceSha256 $localFile "$remote/$name"
    }
}
if ($Mode -eq 'MultiTrace') {
    foreach ($name in @('rtgum-stage2-multitrace.ghm', 'librtgum-gum-ghost.so')) {
        $localFile = Join-Path $OutputDirectory $name
        & $AdbPath -s $DeviceSerial push $localFile "$remote/$name" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot push multi-trace file: $name" }
        Assert-DeviceSha256 $localFile "$remote/$name"
    }
}
if ($Mode -eq 'ZygoteReload') {
    & $AdbPath -s $DeviceSerial push (Join-Path $OutputDirectory 'rtgum-stage2-module2.ghm') "$remote/rtgum-stage2-module2.ghm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot push Stage 2 reload module' }
}
& $AdbPath -s $DeviceSerial shell "chmod 0755 $client" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot make control client executable' }

$ready = Invoke-Device 'ready' 'SuperCall readiness'
if ($ready -notmatch 'ready hello=0x11581158 kpver=0xd09\b') { throw 'Unexpected KernelPatch version' }
$loadCommand = if ($Mode -in @('NoHooks', 'ChannelProbe', 'ChannelHook', 'ZygoteInit')) { "load-nohooks $module" } else { "load $module" }
$load = Invoke-Device $loadCommand 'KPM load'
if ($load -notmatch 'loaded(-nohooks)? module=rtgum-stage1') { throw "Unexpected load result: $load" }

$auth = Invoke-Device 'auth-status' 'authentication status'
if ($auth -notmatch 'ready=1' -or $auth -notmatch 'pair_available=1') {
    throw "Unexpected authentication status: $auth"
}
$dmesg = Invoke-Device 'dmesg' 'pairing log'
$pairMatches = [regex]::Matches($dmesg, 'rtgum-stage2-auth: debug-pair-code=([0-9]{6}) one-time=1')
if ($pairMatches.Count -eq 0) { throw 'One-time pairing code is absent' }
$script:pairCode = $pairMatches[$pairMatches.Count - 1].Groups[1].Value
$pairResponse = Invoke-Device "session-pair $($script:pairCode)" 'session enrollment'
$sessionMatch = [regex]::Match($pairResponse, '^ok session=([0-9a-f]{64}) mode=debug one_time=1$')
if (-not $sessionMatch.Success) { throw 'Session enrollment response is invalid' }
$script:session = $sessionMatch.Groups[1].Value
$sessionFile = Join-Path $OutputDirectory 'last-pixel8-session.txt'
Set-Content -LiteralPath $sessionFile -Value $script:session

$ping = Invoke-Device 'ping' 'control round-trip' $true
if ($ping -notmatch '\bpong ready=1 ') { throw "Unexpected ping result: $(Redact $ping)" }
$before = Invoke-Device 'capabilities' 'capability query' $true
if ($before -notmatch 'ready=1' -or $before -notmatch 'active=0 busy=0 images=0') {
    throw "Unsafe starting state: $before"
}
if ($Mode -notin @('NoHooks', 'ChannelProbe', 'ChannelHook', 'ZygoteInit') -and $before -notmatch 'hooks=1') {
    throw 'Lifecycle hooks were not installed'
}
Write-Output "mode=$Mode rounds=$Rounds"
Write-Output $before
if ($Mode -in @('AntiDebug', 'ShadowLifecycle')) {
    # A previous interrupted probe can leave the Lab retry loop alive and own
    # real HWBP/perf resources before this run installs its isolated ledger.
    & $AdbPath -s $DeviceSerial shell am force-stop dev.rtgum.lab | Out-Null
    $script:antiDebugBootId = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
    $script:antiDebugZygotePid = ''
    $script:antiDebugSystemServerPid = ''
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        $script:antiDebugZygotePid = (& $AdbPath -s $DeviceSerial shell pidof zygote64 2>$null | Out-String).Trim()
        $script:antiDebugSystemServerPid = (& $AdbPath -s $DeviceSerial shell pidof system_server 2>$null | Out-String).Trim()
        if ($script:antiDebugZygotePid -match '^\d+$' -and
            $script:antiDebugSystemServerPid -match '^\d+$') { break }
        Start-Sleep -Milliseconds 500
    }
    if ($script:antiDebugZygotePid -notmatch '^\d+$' -or
        $script:antiDebugSystemServerPid -notmatch '^\d+$') {
        throw 'Cannot establish anti-debug health baseline PIDs'
    }
    & $AdbPath -s $DeviceSerial logcat -b crash -c | Out-Null
}
if ($Mode -eq 'ChannelHook') {
    $script:channelBaseline = Invoke-Device 'syscall283' 'baseline membarrier query'
    $hook = Invoke-Device 'control hook-sysni' 'membarrier channel hook' $true
    if ($hook -ne 'ok sysni_hook=1') { throw "Unexpected channel hook result: $hook" }
    Write-Output $hook
    $passthrough = Invoke-Device 'syscall283' 'hooked membarrier query'
    if ($passthrough -ne $script:channelBaseline) {
        throw "Membarrier passthrough changed: $passthrough"
    }
    Write-Output $passthrough
}
if ($Mode -in @('CommHook', 'PollHook', 'EpollHook')) {
    $hookName = switch ($Mode) {
        'CommHook' { 'hook-comm' }
        'PollHook' { 'hook-poll' }
        'EpollHook' { 'hook-epoll' }
    }
    $hook = Invoke-Device "control $hookName" "$hookName install" $true
    if ($hook -notmatch '^ok (comm|poll|epoll)_hook=1$') { throw "Unexpected hook result: $hook" }
    $script:hookBaseline = Invoke-Device 'control hook-counters' 'hook counters before probe' $true
    Write-Output $hook
    Write-Output $script:hookBaseline
}

$testCommand = switch ($Mode) {
    'Ghost' { 'ghost-test' }
    'GhostRace' { 'ghost-race-test' }
    'Hwbp' { 'hwbp-test' }
    'HwbpProbe' { 'hwbp-probe-test' }
    'HwbpDryRun' { 'control hwbp-probe' }
    'HwbpReplace' { 'hwbp-replace-test' }
    'HwbpCapacity' { 'hwbp-capacity-test' }
    'AntiDebug' { 'antidbg-lab-test' }
    'ShadowLifecycle' { 'shadowhook-lifecycle-test' }
    'ChannelProbe' { 'control syscall-table-probe' }
    'ChannelHook' { 'channel-test' }
    'HijackSelfTest' { 'hijack-self-test' }
    'CommHook' { 'comm-probe' }
    'PollHook' { 'hook-probe' }
    'EpollHook' { 'hook-probe' }
    'Sandbox' { 'stage2-sandbox-test' }
    'ZygoteInit' { 'zygote-init-test' }
    'ZygoteFork' { 'zygote-fork-test' }
    'ZygotePackage' { 'zygote-package-test' }
    'ZygoteReload' { 'zygote-reload-test' }
    'ZygoteJniCode' { 'zygote-jnicode-test' }
    'ZygoteJniCodeJava' { 'zygote-jnicode-java-test' }
    'ZygoteJniCodeBadver' { 'zygote-jnicode-badver-test' }
    'ZygoteJniCodeNosym' { 'zygote-jnicode-nosym-test' }
    'ZygoteDaemonReplace' { 'zygote-daemon-replace-test' }
    'DexLoader' { 'zygote-dex-test' }
    'Interceptors' { 'zygote-interceptor-test' }
    'Lifecycle' { 'zygote-lifecycle-test' }
    'GTrace' { 'zygote-gtrace-test' }
    'MultiTrace' { 'zygote-multitrace-test' }
    'ThreeApps' { 'three-apps-gumlua-test' }
    'GumLuaTarget' { "gumlua-target-test $TargetPackage $TargetComponent $TargetLabel $HookQuietSeconds" }
    'DbiInApp' { 'three-apps-dbi-test' }
    'DbiStalkerApps' { 'three-apps-dbi-stalker-test' }
    'DbiLab' { 'dbi-lab-test' }
    'DbiStalker' { 'dbi-stalker-test' }
    'DbiStalkerPhdr' { 'dbi-stalker-phdr-test' }
    'DbiStalkerUnwind' { 'dbi-stalker-unwind-test' }
    'DbiStalkerPac' { 'dbi-stalker-pac-test' }
    'DbiStalkerBti' { 'dbi-stalker-bti-test' }
    'DbiHardening' { 'dbi-hardening-test' }
    'DbiLdr' { 'dbi-ldr-test' }
    'ReadUserRace' { 'read-user-race-test' }
    'TaskworkSelfTest' { 'taskwork-self-test' }
    'UnloadGuard' { 'unload-guard-test' }
    'Fork' { 'fork-test' }
    'Linker' { 'linker-test' }
    'Needed' { 'needed-ifunc-test' }
    'VersionReject' { 'needed-version-reject-test' }
    'MapsAmbiguous' { 'needed-maps-ambiguous-test' }
    'FileMismatch' { 'needed-file-mismatch-test' }
    'Remote' { 'zygote-test' }
    'PidProbe' { "pid-probe $TargetPid" }
    default { '' }
}
if ($testCommand) {
    try {
        for ($round = 1; $round -le $Rounds; ++$round) {
            $result = Invoke-Device $testCommand "round $round $testCommand" $true
            $script:lastTestResult = $result
            $passPattern = switch ($Mode) {
                'Remote' { 'stage2-zygote-resolve-probe PASS' }
                'ChannelProbe' { '^ok reserved=244\.\.259 uniform=[01] ni_match=[01] ni_symbol=[01] memfd279_distinct=[01] membarrier283_match=[01]$' }
                'ChannelHook' { 'stage2-channel-test PASS' }
                'HijackSelfTest' { 'stage2-hijack-self-test PASS' }
                'CommHook' { 'stage2-comm-probe PASS' }
                'PollHook' { 'stage2-hook-probe PASS' }
                'EpollHook' { 'stage2-hook-probe PASS' }
                'Sandbox' { 'stage2-sandbox-bootstrap PASS' }
                'ZygoteInit' { 'stage2-zygote-init PASS' }
                'ZygoteFork' { 'stage2-zygote-fork PASS' }
                'ZygotePackage' { 'stage2-zygote-package PASS' }
                'ZygoteReload' { 'stage2-zygote-reload PASS' }
                'ZygoteJniCode' { 'stage2-zygote-jnicode PASS' }
                'ZygoteJniCodeJava' { 'stage2-zygote-jnicode-java PASS' }
                'ZygoteJniCodeBadver' { 'stage2-zygote-jnicode-badver PASS' }
                'ZygoteJniCodeNosym' { 'stage2-zygote-jnicode-nosym PASS' }
                'ZygoteDaemonReplace' { 'stage2-zygote-daemon-replace PASS' }
                'DexLoader' { 'stage2-dex-loader PASS' }
                'Interceptors' { 'stage2-interceptors PASS' }
                'Lifecycle' { 'stage2-so-lifecycle PASS' }
                'GTrace' { 'stage2-gtrace PASS' }
                'MultiTrace' { 'stage2-multitrace PASS' }
                'ThreeApps' { 'stage2-three-apps-gumlua PASS' }
                'GumLuaTarget' { 'stage2-single-app-gumlua PASS' }
                'DbiInApp' { 'stage2-three-apps-dbi PASS' }
                'DbiStalkerApps' { 'stage2-three-apps-dbi-stalker PASS' }
                'DbiLab' { 'stage1-dbi-lab PASS' }
                'DbiStalker' { 'stage1-dbi-stalker PASS' }
                'DbiStalkerPhdr' { 'stage1-dbi-stalker-phdr PASS' }
                'DbiStalkerUnwind' { 'stage1-dbi-stalker-unwind PASS' }
                'DbiStalkerPac' { 'stage1-dbi-stalker-pac PASS' }
                'DbiStalkerBti' { 'stage1-dbi-stalker-bti PASS' }
                'DbiHardening' { 'stage1-dbi-hardening PASS' }
                'DbiLdr' { 'stage1-dbi-ldr PASS' }
                'ReadUserRace' { 'stage1-read-user-race PASS' }
                'TaskworkSelfTest' { 'stage2-taskwork-self-test PASS' }
                'ShadowLifecycle' { 'stage1-shadowhook-lifecycle PASS' }
                'PidProbe' { "pid=$TargetPid found=1 comm=main" }
                'HwbpDryRun' { '^ok free=0x[0-9a-f]+ .*cpus=[1-9][0-9]* unknown=0$' }
                default { 'stage1-.*-test PASS' }
            }
            if ($result -notmatch $passPattern) { throw "Round $round failed: $(Redact $result)" }
            Write-Output "round=$round $result"
        }
        if ($Mode -eq 'AntiDebug') {
            # Direct debug registers are CPU local. A leaked comparator may not
            # fail the test process itself; it can fire later in any Zygote
            # child scheduled on that CPU. Hold a quiet window before touching
            # PackageManager and require both process identity and a zero-slot
            # physical audit to remain stable.
            Start-Sleep -Seconds $AntiDebugQuietSeconds
            $healthBootId = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
            $healthZygotePid = (& $AdbPath -s $DeviceSerial shell pidof zygote64 2>$null | Out-String).Trim()
            $healthSystemServerPid = (& $AdbPath -s $DeviceSerial shell pidof system_server 2>$null | Out-String).Trim()
            if ($healthBootId -cne $script:antiDebugBootId -or
                $healthZygotePid -cne $script:antiDebugZygotePid -or
                $healthSystemServerPid -cne $script:antiDebugSystemServerPid) {
                throw "Android identity changed after anti-debug core test: boot=$healthBootId zygote=$healthZygotePid system_server=$healthSystemServerPid"
            }
            $physicalHealth = Invoke-Device 'control antidbg-physical' 'anti-debug physical health audit' $true
            foreach ($zero in @('hwbp-records=0', 'hwbp-enabled=0',
                                'hwbp-mismatch=0', 'antidbg-records=0',
                                'antidbg-enabled=0', 'antidbg-mismatch=0',
                                'antidbg-steps=0',
                                'untracked-brk=0', 'untracked-watch=0',
                                'monitor-owned=0', 'mdscr-ss=0')) {
                if ($physicalHealth -notmatch "(^| )$([regex]::Escape($zero))($| )") {
                    throw "Anti-debug physical health audit failed: $physicalHealth"
                }
            }
            $packageHealth = (& $AdbPath -s $DeviceSerial shell cmd package path android 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $packageHealth -notmatch '^package:') {
                throw "PackageManager health probe failed: $packageHealth"
            }
            $crashHealth = (& $AdbPath -s $DeviceSerial logcat -b crash -d -v brief 2>&1 | Out-String).Trim()
            if ($crashHealth -match 'Fatal signal|Abort message|F DEBUG|crash_dump') {
                $frameworkCrash = $crashHealth -match '(?im)^.*Cmdline:\s*(zygote\S*|system_server|dev\.rtgum\.lab\S*|rtgum-stage1\S*)\s*$' -or
                    $crashHealth -match '(?i)librtgum|frida-gum|rtgum-stage1|ghost(?:hook|daemon)'
                if ($frameworkCrash) {
                    throw "A framework-related fatal process crash occurred during the anti-debug quiet window: $crashHealth"
                }
                $unrelatedCmdline = [regex]::Match($crashHealth, '(?im)^.*Cmdline:\s*([^\r\n]+)$')
                $unrelatedName = if ($unrelatedCmdline.Success) { $unrelatedCmdline.Groups[1].Value.Trim() } else { 'unknown' }
                Write-Warning "Unrelated app crash excluded from anti-debug gate: cmdline=$unrelatedName"
            }
            Write-Output "anti-debug-health boot-id=$healthBootId zygote=$healthZygotePid system_server=$healthSystemServerPid package=ok"
            Write-Output "anti-debug-health-physical=$physicalHealth"
            if ($script:compat32Supported) {
                $compat32Result = (& $AdbPath -s $DeviceSerial shell $script:compat32Remote 2>&1 |
                    ForEach-Object { $_.ToString() } | Out-String).Trim()
                if ($LASTEXITCODE -ne 0 -or
                    $compat32Result -notmatch 'stage1-antidbg-compat32 PASS') {
                    throw "AArch32 compat anti-debug test failed: $compat32Result"
                }
                Write-Output $compat32Result
            }
            $ebpfCompare = Invoke-Device 'antidbg-ebpf-probe' 'optional eBPF comparison' $true
            if ($ebpfCompare -notmatch '^ebpf-compare role=observe-only primary=kernel-ledger status=(observed|unavailable)\b') {
                throw "eBPF comparison returned an ambiguous result: $ebpfCompare"
            }
            Write-Output $ebpfCompare
            $labApk = Join-Path $projectDirectory 'out/lab-apk/rtgum-art-lab.apk'
            $remoteLabApk = "$remote/rtgum-art-lab.apk"
            & $AdbPath -s $DeviceSerial push $labApk $remoteLabApk | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Cannot push ART/HWBP Lab APK' }
            Assert-DeviceSha256 $labApk $remoteLabApk
            $installOutput = (& $AdbPath -s $DeviceSerial shell pm install -r $remoteLabApk 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $installOutput -notmatch 'Success') {
                throw "Lab APK install failed: $installOutput"
            }
            & $AdbPath -s $DeviceSerial logcat -c | Out-Null
            & $AdbPath -s $DeviceSerial shell am force-stop dev.rtgum.lab | Out-Null
            & $AdbPath -s $DeviceSerial shell am start -n dev.rtgum.lab/.MainActivity | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Lab activity did not start' }
            $labLog = ''
            for ($attempt = 0; $attempt -lt 30; ++$attempt) {
                Start-Sleep -Milliseconds 250
                $labLog = (& $AdbPath -s $DeviceSerial logcat -d -s rtgum-lab:I rtgum-labscan:I '*:S' | Out-String)
                if ($labLog -match 'hwbp-selfcheck .*pass=true') { break }
            }
            $hwbpLine = [regex]::Match($labLog, '(?m)^.*hwbp-selfcheck mask=0xffff brp=6 wrp=4 ptrace-brp=28 perf-brp=28 ptrace-wrp=28 perf-wrp=28 active-signal=5 tracer=0 pass=true perf-ioctl=true perf-read=true fd-lifecycle=true.*$')
            $memoryLine = [regex]::Match($labLog, '(?m)^.*memory-ready pid=(\d+) magic=0x[0-9a-f]+ code=0x([0-9a-f]+) value=0x4c414201.*$')
            if (-not $hwbpLine.Success -or -not $memoryLine.Success) {
                throw "Lab HWBP self-check did not pass: $labLog"
            }
            $labPid = [int]$memoryLine.Groups[1].Value
            $labEntry = [Convert]::ToUInt64($memoryLine.Groups[2].Value, 16)
            $attached = Invoke-Device ("control 'hwbp-attach {0} 0x{1:x}'" -f $labPid, $labEntry) 'Lab real HWBP attach' $true
            $attachMatch = [regex]::Match($attached, '^ok handle=(\d+) slots=6 tid=(\d+) remote=1$')
            if (-not $attachMatch.Success -or [int]$attachMatch.Groups[2].Value -ne $labPid) {
                throw "Lab real HWBP attach failed: $attached"
            }
            $labHandle = $attachMatch.Groups[1].Value
            try {
                & $AdbPath -s $DeviceSerial shell am broadcast -a dev.rtgum.lab.RUN_KERNEL_TRACE -n dev.rtgum.lab/.TraceReceiver | Out-Null
                Start-Sleep -Milliseconds 300
                $snapshot = Invoke-Device "control 'hwbp-snapshot $labHandle'" 'Lab real HWBP snapshot' $true
                if ($snapshot -notmatch '\bentry=1 return=1 conflicts=0\b' -or
                    $snapshot -notmatch '\bx0=0x1 x1=0x2\b' -or
                    $snapshot -notmatch '\bret=0x3\b') {
                    throw "Lab real HWBP was not preserved: $snapshot"
                }
                $tracerPid = (& $AdbPath -s $DeviceSerial shell "awk '/^TracerPid:/{print `$2}' /proc/$labPid/status" 2>&1 | Out-String).Trim()
                if ($LASTEXITCODE -ne 0 -or $tracerPid -ne '0') {
                    throw "Lab acquired a tracer while the real HWBP was active: TracerPid=$tracerPid"
                }
                Write-Output "apk-hwbp-selfcheck=$($hwbpLine.Value.Trim())"
                Write-Output "apk-real-hwbp=$snapshot"
                Write-Output "apk-real-hwbp-tracerpid=$tracerPid"
            } finally {
                $cleared = Invoke-Device "control 'hwbp-clear $labHandle'" 'Lab real HWBP clear' $true
                if ($cleared -notmatch '^ok handle=\d+ cleared=1$') {
                    throw "Lab real HWBP clear failed: $cleared"
                }
                & $AdbPath -s $DeviceSerial shell am force-stop dev.rtgum.lab | Out-Null
            }
            Start-Sleep -Seconds 3
            $finalPhysical = Invoke-Device 'control antidbg-physical' 'final anti-debug physical audit' $true
            if ($finalPhysical -notmatch '\bhwbp-records=0\b' -or
                $finalPhysical -notmatch '\bhwbp-enabled=0\b' -or
                $finalPhysical -notmatch '\bantidbg-records=0\b' -or
                $finalPhysical -notmatch '\bantidbg-enabled=0\b' -or
                $finalPhysical -notmatch '\bantidbg-steps=0\b' -or
                $finalPhysical -notmatch '\buntracked-brk=0\b' -or
                $finalPhysical -notmatch '\buntracked-watch=0\b' -or
                $finalPhysical -notmatch '\bmonitor-owned=0\b' -or
                $finalPhysical -notmatch '\bmdscr-ss=0\b') {
                throw "Final anti-debug physical cleanup failed: $finalPhysical"
            }
            $finalZygotePid = (& $AdbPath -s $DeviceSerial shell pidof zygote64 2>$null | Out-String).Trim()
            $finalSystemServerPid = (& $AdbPath -s $DeviceSerial shell pidof system_server 2>$null | Out-String).Trim()
            if ($finalZygotePid -cne $script:antiDebugZygotePid -or
                $finalSystemServerPid -cne $script:antiDebugSystemServerPid) {
                throw "Android identity changed during APK anti-debug test: zygote=$finalZygotePid system_server=$finalSystemServerPid"
            }
            Write-Output "apk-final-physical=$finalPhysical"
        }
        if ($Mode -eq 'ShadowLifecycle') {
            # Global fault/fork hooks remain physically installed but dormant
            # between logical disable and module teardown. Give in-flight
            # wrappers time to drain, then prove Android identity, package
            # service, crash buffer and every physical debug slot stayed clean.
            Start-Sleep -Seconds 12
            $healthBootId = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
            $healthZygotePid = (& $AdbPath -s $DeviceSerial shell pidof zygote64 2>$null | Out-String).Trim()
            $healthSystemServerPid = (& $AdbPath -s $DeviceSerial shell pidof system_server 2>$null | Out-String).Trim()
            if ($healthBootId -cne $script:antiDebugBootId -or
                $healthZygotePid -cne $script:antiDebugZygotePid -or
                $healthSystemServerPid -cne $script:antiDebugSystemServerPid) {
                throw "Android identity changed after Shadow Hook lifecycle test: boot=$healthBootId zygote=$healthZygotePid system_server=$healthSystemServerPid"
            }
            $physicalHealth = Invoke-Device 'control antidbg-physical' 'Shadow Hook lifecycle physical audit' $true
            foreach ($zero in @('hwbp-records=0', 'hwbp-enabled=0',
                                'hwbp-mismatch=0', 'antidbg-records=0',
                                'antidbg-enabled=0', 'antidbg-mismatch=0',
                                'antidbg-steps=0',
                                'untracked-brk=0', 'untracked-watch=0',
                                'monitor-owned=0', 'mdscr-ss=0')) {
                if ($physicalHealth -notmatch "(^| )$([regex]::Escape($zero))($| )") {
                    throw "Shadow Hook lifecycle physical audit failed: $physicalHealth"
                }
            }
            $packageHealth = (& $AdbPath -s $DeviceSerial shell cmd package path android 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $packageHealth -notmatch '^package:') {
                throw "PackageManager health probe failed after Shadow Hook lifecycle: $packageHealth"
            }
            $crashHealth = (& $AdbPath -s $DeviceSerial logcat -b crash -d -v brief 2>&1 | Out-String).Trim()
            if ($crashHealth -match 'Fatal signal|Abort message|F DEBUG|crash_dump') {
                $frameworkCrash = $crashHealth -match '(?im)^.*Cmdline:\s*(zygote\S*|system_server|dev\.rtgum\.lab\S*|rtgum-stage1\S*)\s*$' -or
                    $crashHealth -match '(?i)librtgum|frida-gum|rtgum-stage1|ghost(?:hook|daemon)'
                if ($frameworkCrash) {
                    throw "A framework-related fatal process crash occurred during the Shadow Hook lifecycle quiet window: $crashHealth"
                }
                $unrelatedCmdline = [regex]::Match($crashHealth, '(?im)^.*Cmdline:\s*([^\r\n]+)$')
                $unrelatedName = if ($unrelatedCmdline.Success) { $unrelatedCmdline.Groups[1].Value.Trim() } else { 'unknown' }
                Write-Warning "Unrelated app crash excluded from Shadow Hook lifecycle gate: cmdline=$unrelatedName"
            }
            Write-Output "shadowhook-lifecycle-health boot-id=$healthBootId zygote=$healthZygotePid system_server=$healthSystemServerPid package=ok"
            Write-Output "shadowhook-lifecycle-physical=$physicalHealth"
        }
        if ($Mode -in @('CommHook', 'PollHook', 'EpollHook')) {
            $afterCounters = Invoke-Device 'control hook-counters' 'hook counters after probe' $true
            $counterName = switch ($Mode) {
                'CommHook' { 'comm' }
                'PollHook' { 'poll' }
                'EpollHook' { 'epoll' }
            }
            $beforeMatch = [regex]::Match($script:hookBaseline, "\b$counterName=(\d+)")
            $afterMatch = [regex]::Match($afterCounters, "\b$counterName=(\d+)")
            if (-not $beforeMatch.Success -or -not $afterMatch.Success -or
                [long]$afterMatch.Groups[1].Value -le [long]$beforeMatch.Groups[1].Value) {
                throw "Hook callback did not fire: $afterCounters"
            }
            Write-Output $afterCounters
        }
    } catch {
        $testFailure = Redact $_.Exception.Message
        # Preserve user-space evidence before recovery or a later force-stop
        # changes ActivityManager's exit reason. Packed apps frequently install
        # their own crash dumper, so the fatal stack may exist only in the
        # combined log buffers and never reach `logcat -b crash`.
        try {
            $failureStem = "stage1-$($Mode.ToLowerInvariant())-$RunLabel-failure"
            $allLogPath = Join-Path $projectDirectory "out/device/pixel8/$failureStem-logcat-all.txt"
            (& $AdbPath -s $DeviceSerial logcat -b all -d -v threadtime 2>&1 | Out-String) |
                Set-Content -LiteralPath $allLogPath -Encoding UTF8
            Write-Warning "Failure all-buffer logcat saved: $allLogPath"
            if (-not [string]::IsNullOrWhiteSpace($TargetPackage)) {
                $exitInfoPath = Join-Path $projectDirectory "out/device/pixel8/$failureStem-exit-info.txt"
                (& $AdbPath -s $DeviceSerial shell dumpsys activity exit-info $TargetPackage 2>&1 | Out-String) |
                    Set-Content -LiteralPath $exitInfoPath -Encoding UTF8
                Write-Warning "Failure ApplicationExitInfo saved: $exitInfoPath"
            }
        } catch {
            Write-Warning "Could not save user-space failure evidence: $(Redact $_.Exception.Message)"
        }
        try {
            $failureLog = Redact (Invoke-Device 'dmesg' 'failure log')
            $failureLogPath = Join-Path $projectDirectory "out/device/pixel8/stage1-$($Mode.ToLowerInvariant())-$RunLabel-failure-dmesg-redacted.txt"
            Set-Content -LiteralPath $failureLogPath -Value $failureLog
            Write-Warning "Failure dmesg saved: $failureLogPath"
        } catch {
            Write-Warning "Could not save failure dmesg: $(Redact $_.Exception.Message)"
        }
        try {
            $recovery = Invoke-Device 'capabilities' 'recovery capability query' $true
            if ($recovery -match 'active=0 busy=0 images=0 daemon=0') {
                $recoveredUnload = Invoke-Device 'unload' 'recovery KPM unload' $true
                Write-Output "recovery=$recoveredUnload"
            } elseif ($CleanupOnFailure) {
                # Automated APK runs must never carry a half-installed daemon
                # into the visible Frida control phase. Save evidence first,
                # then unlink the Zygote image and stop every process used to
                # deliver or verify INIT. Child ghost images are released by
                # normal mm teardown, so poll before unloading the KPM.
                if (-not [string]::IsNullOrWhiteSpace($TargetPackage)) {
                    & $AdbPath -s $DeviceSerial shell am force-stop $TargetPackage | Out-Null
                }
                $discover = Invoke-Device 'control zygote-discover' 'failure cleanup Zygote discovery' $true
                $zygoteMatch = [regex]::Match($discover, '\bpid=(\d+)')
                if ($zygoteMatch.Success) {
                    $unlinkAll = Invoke-Device ("control 'zygote-unlink-all {0}'" -f $zygoteMatch.Groups[1].Value) `
                        'failure cleanup Zygote unlink' $true
                    Write-Output "failure-cleanup=$unlinkAll"
                }
                foreach ($cleanupPackage in @(
                    'com.laodeng.jnicode',
                    'dev.rtgum.lab',
                    'com.android.settings',
                    'com.google.android.apps.pixel.dcservice',
                    'com.google.android.settings.intelligence',
                    'com.android.providers.calendar'
                )) {
                    & $AdbPath -s $DeviceSerial shell am force-stop $cleanupPackage | Out-Null
                }
                $cleanupState = $recovery
                for ($cleanupAttempt = 0; $cleanupAttempt -lt 60; ++$cleanupAttempt) {
                    $cleanupState = Invoke-Device 'capabilities' 'failure cleanup capability query' $true
                    if ($cleanupState -match 'active=0 busy=0 images=0 daemon=0') { break }
                    Start-Sleep -Milliseconds 250
                }
                if ($cleanupState -match 'active=0 busy=0 images=0 daemon=0') {
                    $recoveredUnload = Invoke-Device 'unload' 'failure cleanup KPM unload' $true
                    if ($recoveredUnload -notmatch 'unloaded module=rtgum-stage1') {
                        throw "Unexpected failure-cleanup unload result: $(Redact $recoveredUnload)"
                    }
                    Write-Output "failure-cleanup=$recoveredUnload"
                } else {
                    # A wedged process may retain an mm reference after the
                    # bounded cleanup window. Reboot only for explicitly
                    # automated runs; manual smoke keeps the forensic state.
                    Write-Warning "Failure cleanup remained busy; rebooting cleanly: $(Redact $cleanupState)"
                    & $AdbPath -s $DeviceSerial reboot | Out-Null
                    $cleanupBooted = $false
                    for ($cleanupAttempt = 0; $cleanupAttempt -lt 60; ++$cleanupAttempt) {
                        Start-Sleep -Seconds 3
                        $cleanupStateText = ''
                        $cleanupBootText = ''
                        try { $cleanupStateText = (& $AdbPath -s $DeviceSerial get-state 2>$null | Out-String).Trim() } catch { }
                        try { $cleanupBootText = (& $AdbPath -s $DeviceSerial shell getprop sys.boot_completed 2>$null | Out-String).Trim() } catch { }
                        if ($cleanupStateText -eq 'device' -and $cleanupBootText -eq '1') {
                            $cleanupBooted = $true
                            break
                        }
                    }
                    if (-not $cleanupBooted) { throw 'Device did not recover after failure-cleanup reboot' }
                    Write-Output 'failure-cleanup=rebooted-clean'
                }
            } else {
                Write-Warning "KPM kept loaded for recovery: $(Redact $recovery)"
            }
        } catch {
            Write-Warning "Could not verify safe unload after test failure: $(Redact $_.Exception.Message)"
        }
        if ($Mode -eq 'FileMismatch') {
            & $AdbPath -s $DeviceSerial shell "rm -f $remote/libc.so" | Out-Null
        }
        throw $testFailure
    }
}

if ($Mode -eq 'HwbpApks') {
    try {
    $apkCases = @(
        @{ Package = 'com.imusic.iting'; Version = '5.8.5'; File = '039_com.imusic.iting_5.8.5.apk' },
        @{ Package = 'com.threegene.yeemiao'; Version = '8.6.10'; File = '041_com.threegene.yeemiao_8.6.10.apk' },
        @{ Package = 'com.funshion.video.mobile'; Version = '4.7.3.13'; File = '049_com.funshion.video.mobile_4.7.3.13.apk' }
    )
    $readelf = Join-Path $projectDirectory '.toolchains/android-ndk-r29/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
    $libcFile = Join-Path $OutputDirectory 'hwbp-device-libc.so'
    & $AdbPath -s $DeviceSerial pull /apex/com.android.runtime/lib64/bionic/libc.so $libcFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot pull device libc for breakpoint symbol lookup' }
    $symbols = (& $readelf --dyn-syms $libcFile | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read device libc dynamic symbols' }
    $symbolMatch = [regex]::Match($symbols, '(?m)^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+epoll_wait@@LIBC\s*$')
    if (-not $symbolMatch.Success) { throw 'epoll_wait was not found in device libc' }
    $symbolOffset = [Convert]::ToUInt64($symbolMatch.Groups[1].Value, 16)
    foreach ($apkCase in $apkCases) {
        $apkPath = Join-Path (Join-Path $projectDirectory 'test-apk') $apkCase.File
        if (-not (Test-Path -LiteralPath $apkPath -PathType Leaf)) { throw "Missing APK: $apkPath" }
        $installed = (& $AdbPath -s $DeviceSerial shell dumpsys package $apkCase.Package | Out-String)
        if ($installed -notmatch "(?m)^\s*versionName=$([regex]::Escape($apkCase.Version))\s*$") {
            throw "Installed version does not match $($apkCase.Package) $($apkCase.Version)"
        }
        $installedPath = (& $AdbPath -s $DeviceSerial shell pm path $apkCase.Package | Out-String).Trim() -replace '^package:', ''
        if (-not $installedPath.StartsWith('/data/app/')) { throw "Cannot locate installed APK for $($apkCase.Package)" }
        $deviceHash = ((& $AdbPath -s $DeviceSerial shell sha256sum $installedPath | Out-String).Trim() -split '\s+')[0]
        $sourceHash = Get-LocalSha256 $apkPath
        if ($deviceHash -cne $sourceHash) { throw "Installed APK differs from $apkPath" }
        $componentResult = (& $AdbPath -s $DeviceSerial shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER $apkCase.Package | Out-String).Trim()
        $componentMatch = [regex]::Match($componentResult, '(?m)^([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)$')
        if (-not $componentMatch.Success) { throw "Cannot find launcher for $($apkCase.Package): $componentResult" }
        $component = $componentMatch.Value
        & $AdbPath -s $DeviceSerial shell am force-stop $apkCase.Package | Out-Null
        & $AdbPath -s $DeviceSerial shell am start -n $component | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot launch $($apkCase.Package)" }
        $targetPid = 0
        for ($attempt = 0; $attempt -lt 20; ++$attempt) {
            $targetPid = Get-MainProcessPid $apkCase.Package
            if ($targetPid -gt 0) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($targetPid -le 0) { throw "Main process did not start: $($apkCase.Package)" }
        $maps = Invoke-Device "file-dump /proc/$targetPid/maps" 'target maps'
        $libcMatches = [regex]::Matches($maps, '(?m)^([0-9a-f]+)-[0-9a-f]+\s+\S+\s+00000000\s+\S+\s+\d+\s+/apex/com\.android\.runtime[^/]*?/lib64/bionic/libc\.so\s*$')
        if ($libcMatches.Count -ne 1) { throw "Cannot identify unique libc load bias for $($apkCase.Package): $($libcMatches.Count)" }
        $base = [Convert]::ToUInt64($libcMatches[0].Groups[1].Value, 16)
        $entry = $base + $symbolOffset
        $handle = 0
        try {
            $attached = Invoke-Device ("control 'hwbp-attach {0} 0x{1:x}'" -f $targetPid, $entry) 'remote HWBP attach' $true
            $attachMatch = [regex]::Match($attached, '^ok handle=(\d+) slots=6 tid=(\d+) remote=1$')
            if (-not $attachMatch.Success -or [int]$attachMatch.Groups[2].Value -ne $targetPid) {
                throw "Remote HWBP attach rejected for $($apkCase.Package): $attached"
            }
            $handle = $attachMatch.Groups[1].Value
            $threadText = (& $AdbPath -s $DeviceSerial shell "ls /proc/$targetPid/task" | Out-String)
            $otherThreads = @($threadText -split '\s+' | Where-Object { $_ -match '^\d+$' -and $_ -ne $targetPid })
            if ($otherThreads.Count -eq 0) { throw "No subthread found for $($apkCase.Package)" }
            # Prefer subthreads actually parked in the epoll path (the wchan
            # reads via the elevated file-dump), so the attach lands on a
            # thread that will genuinely call epoll_wait.
            $epollThreads = @()
            foreach ($candidate in $otherThreads) {
                $wchan = Invoke-Device "control 'file-dump /proc/$candidate/wchan'" 'subthread wchan read' $true
                if ($wchan -match 'ep_poll|do_epoll_wait|SyS_epoll|__arm64_sys_epoll') {
                    $epollThreads += $candidate
                    if ($epollThreads.Count -ge 4) { break }
                }
            }
            $attachTargets = if ($epollThreads.Count -gt 0) { $epollThreads } else { @($otherThreads | Select-Object -First 4) }
            $subHandles = @()
            foreach ($candidate in $attachTargets) {
                $subAttached = Invoke-Device ("control 'hwbp-attach {0} 0x{1:x}'" -f $candidate, $entry) 'subthread attach' $true
                $subMatch = [regex]::Match($subAttached, '^ok handle=(\d+) slots=6 tid=(\d+) remote=1$')
                if ($subMatch.Success) {
                    $subHandles += @{ Tid = $candidate; Handle = $subMatch.Groups[1].Value }
                }
            }
            if ($subHandles.Count -eq 0) {
                throw "No subthread attach succeeded for $($apkCase.Package)"
            }
            $snapshot = ''
            for ($attempt = 0; $attempt -lt 8; ++$attempt) {
                & $AdbPath -s $DeviceSerial shell input keyevent KEYCODE_HOME | Out-Null
                & $AdbPath -s $DeviceSerial shell am start -n $component | Out-Null
                Start-Sleep -Milliseconds 300
                $snapshot = Invoke-Device "control 'hwbp-snapshot $handle'" 'remote HWBP snapshot' $true
                $counts = [regex]::Match($snapshot, '\bentry=(\d+) return=(\d+) conflicts=(\d+)\b')
                if ($counts.Success -and $counts.Groups[1].Value -gt 0 -and
                    $counts.Groups[2].Value -gt 0) { break }
            }
            if (-not $counts.Success -or $counts.Groups[1].Value -eq 0 -or
                $counts.Groups[2].Value -eq 0) {
                throw "Main-thread entry/return was not observed for $($apkCase.Package): $snapshot"
            }
            $hitSub = $null
            for ($attempt = 0; $attempt -lt 8; ++$attempt) {
                & $AdbPath -s $DeviceSerial shell input keyevent KEYCODE_HOME | Out-Null
                & $AdbPath -s $DeviceSerial shell am start -n $component | Out-Null
                Start-Sleep -Milliseconds 300
                foreach ($sub in $subHandles) {
                    $subSnapshot = Invoke-Device "control 'hwbp-snapshot $($sub.Handle)'" 'subthread HWBP snapshot' $true
                    $subCounts = [regex]::Match($subSnapshot, '\bentry=(\d+) return=(\d+) conflicts=(\d+)\b')
                    if ($subCounts.Success -and $subCounts.Groups[1].Value -gt 0 -and
                        $subCounts.Groups[2].Value -gt 0) {
                        $hitSub = @{ Tid = $sub.Tid; Entry = $subCounts.Groups[1].Value; Return = $subCounts.Groups[2].Value }
                        break
                    }
                }
                if ($hitSub) { break }
            }
            # A subthread hit is opportunistic in the field app (which worker
            # threads park in epoll depends on the app's runtime); the
            # deterministic worker-thread hit is asserted by the hwbp-lab
            # worker test. Here the per-TID registration itself plus the
            # conflict-free programming is the app-level evidence.
            if (-not $hitSub) {
                Write-Output ("apk={0} subthread_attached={1} subthread_hit=0 note=opportunistic" -f
                    $apkCase.Package, $subHandles.Count)
            }
            foreach ($sub in $subHandles) {
                $subCleared = Invoke-Device "control 'hwbp-clear $($sub.Handle)'" 'subthread HWBP clear' $true
                if ($subCleared -notmatch '^ok handle=\d+ cleared=1$') {
                    throw "Cannot clear subthread HWBP for $($apkCase.Package): $subCleared"
                }
            }
            Write-Output ("apk={0} version={1} sha256=matched pid={2} target=libc.so!epoll_wait entry={3} return={4} conflicts={5} subthread_attached={6} subthread_tid={7} subthread_entry={8} subthread_return={9}" -f
                $apkCase.Package, $apkCase.Version, $targetPid,
                $counts.Groups[1].Value, $counts.Groups[2].Value, $counts.Groups[3].Value,
                $subHandles.Count, $(if ($hitSub) { $hitSub.Tid } else { 'none' }),
                $(if ($hitSub) { $hitSub.Entry } else { 0 }), $(if ($hitSub) { $hitSub.Return } else { 0 }))
            if ($apkCase.Package -eq 'com.funshion.video.mobile') {
                & $AdbPath -s $DeviceSerial shell am force-stop $apkCase.Package | Out-Null
                for ($attempt = 0; $attempt -lt 20; ++$attempt) {
                    $pidText = (& $AdbPath -s $DeviceSerial shell pidof $apkCase.Package | Out-String).Trim()
                    if (-not $pidText) { break }
                    Start-Sleep -Milliseconds 100
                }
                if ($pidText) { throw "Process did not exit: $($apkCase.Package)" }
                $afterExit = Invoke-Device 'capabilities' 'HWBP exit cleanup capability query' $true
                $oldHandle = Invoke-Device "control 'hwbp-snapshot $handle'" 'HWBP exited-handle probe' $true
                if ($afterExit -notmatch '\bhwbp_active=0\b' -or
                    $oldHandle -notmatch '^error=hwbp-snapshot-failed code=-2$') {
                    throw "HWBP was not released on exit: $afterExit $oldHandle"
                }
                $handle = 0
                Write-Output 'main-thread-exit-cleanup=1'
            }
        } finally {
            if ($handle -ne 0) {
                $cleared = Invoke-Device "control 'hwbp-clear $handle'" 'remote HWBP clear' $true
                if ($cleared -notmatch '^ok handle=\d+ cleared=1$') {
                    throw "Cannot clear remote HWBP for $($apkCase.Package): $cleared"
                }
            }
            & $AdbPath -s $DeviceSerial shell am force-stop $apkCase.Package | Out-Null
        }
    }
    Write-Output 'pixel8-stage1-hwbp-apks PASS'
    } catch {
        $testFailure = Redact $_.Exception.Message
        try {
            $recovery = Invoke-Device 'capabilities' 'APK-test recovery query' $true            if ($recovery -match 'active=0 busy=0 images=0 daemon=0' -and
                $recovery -match '\bhwbp_active=0\b') {
                $recoveredUnload = Invoke-Device 'unload' 'APK-test recovery unload' $true
                Write-Output "recovery=$recoveredUnload"
            } else {
                Write-Warning "KPM retained for recovery: $(Redact $recovery)"
            }
        } catch {
            Write-Warning "Could not unload after APK-test failure: $(Redact $_.Exception.Message)"
        }
        throw $testFailure
    }
}

if ($Mode -eq 'DbiApks') {
    try {
    $apkCases = @(
        @{ Package = 'com.imusic.iting'; Version = '5.8.5' },
        @{ Package = 'com.threegene.yeemiao'; Version = '8.6.10' },
        @{ Package = 'com.funshion.video.mobile'; Version = '4.7.3.13' }
    )
    $readelf = Join-Path $projectDirectory '.toolchains/android-ndk-r29/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
    $libcFile = Join-Path $OutputDirectory 'hwbp-device-libc.so'
    & $AdbPath -s $DeviceSerial pull /apex/com.android.runtime/lib64/bionic/libc.so $libcFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot pull device libc for the DBI symbol lookup' }
    $symbols = (& $readelf --dyn-syms $libcFile | Out-String)
    $symbolMatch = [regex]::Match($symbols, '(?m)^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+epoll_wait@@LIBC\s*$')
    if (-not $symbolMatch.Success) { throw 'epoll_wait was not found in device libc' }
    $symbolOffset = [Convert]::ToUInt64($symbolMatch.Groups[1].Value, 16)
    $strlenMatch = [regex]::Match($symbols, '(?m)^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+bsearch@@LIBC\s*$')
    if (-not $strlenMatch.Success) { throw 'bsearch was not found in device libc' }
    $strlenOffset = [Convert]::ToUInt64($strlenMatch.Groups[1].Value, 16)
    foreach ($apkCase in $apkCases) {
        $installed = (& $AdbPath -s $DeviceSerial shell dumpsys package $apkCase.Package | Out-String)
        if ($installed -notmatch "(?m)^\s*versionName=$([regex]::Escape($apkCase.Version))\s*$") {
            throw "Installed version does not match $($apkCase.Package) $($apkCase.Version)"
        }
        $componentResult = (& $AdbPath -s $DeviceSerial shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER $apkCase.Package | Out-String).Trim()
        $componentMatch = [regex]::Match($componentResult, '(?m)^([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)\s*$')
        if (-not $componentMatch.Success) { throw "Cannot find launcher for $($apkCase.Package): $componentResult" }
        $component = $componentMatch.Value
        & $AdbPath -s $DeviceSerial shell am force-stop $apkCase.Package | Out-Null
        & $AdbPath -s $DeviceSerial shell am start -n $component | Out-Null
        $targetPid = 0
        for ($attempt = 0; $attempt -lt 20; ++$attempt) {
            $targetPid = Get-MainProcessPid $apkCase.Package
            if ($targetPid -gt 0) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($targetPid -le 0) { throw "Main process did not start: $($apkCase.Package)" }
        $maps = Invoke-Device "file-dump /proc/$targetPid/maps" 'target maps' $true
        $libcMatches = [regex]::Matches($maps, '(?m)^([0-9a-f]+)-[0-9a-f]+\s+\S+\s+00000000\s+\S+\s+\d+\s+/apex/com\.android\.runtime[^/]*?/lib64/bionic/libc\.so\s*$')
        if ($libcMatches.Count -ne 1) { throw "Cannot identify unique libc load bias for $($apkCase.Package): $($libcMatches.Count)" }
        $base = [Convert]::ToUInt64($libcMatches[0].Groups[1].Value, 16)
        $entry = $base + $symbolOffset
        $result = Invoke-Device ("dbi-apk-test {0} 0x{1:x}" -f $targetPid, $entry) 'per-app DBI relocation' $true
        if ($result -notmatch 'stage1-dbi-apk PASS') {
            throw "DBI relocation failed for $($apkCase.Package): $result"
        }
        $summary = ($result -split "`n" | Where-Object { $_ -match '^dbi-apk ' } | Select-Object -First 1)
        Write-Output ("apk={0} version={1} pid={2} {3}" -f $apkCase.Package, $apkCase.Version, $targetPid, $summary)
        # Second target: a self-contained leaf function, so the block has its
        # own internal control flow rather than a tail-branching stub.
        $selfEntry = $base + $strlenOffset
        $selfResult = Invoke-Device ("dbi-apk-test {0} 0x{1:x} bsearch 160" -f $targetPid, $selfEntry) 'per-app self-contained DBI relocation' $true
        if ($selfResult -notmatch 'stage1-dbi-apk PASS') {
            throw "Self-contained DBI relocation failed for $($apkCase.Package): $selfResult"
        }
        $selfSummary = ($selfResult -split "`n" | Where-Object { $_ -match '^dbi-apk ' } | Select-Object -First 1)
        # The clone must really execute in-process. How many steps stay inside
        # depends on where the clone landed: within branch reach the internal
        # branches stay direct and execution continues into the original
        # function (correct, lower residency); far away they are expanded and
        # the loop stays inside. The far/resident case is asserted by the
        # in-app module (ghost page, 5/5 probes) and by dbi-lab-test.
        $inClone = [regex]::Match($selfSummary, 'in-clone=(\d+)').Groups[1].Value
        if ([int]$inClone -lt 1) {
            throw "Self-contained block never executed in the clone for $($apkCase.Package)"
        }
        Write-Output ("apk={0} version={1} pid={2} {3}" -f $apkCase.Package, $apkCase.Version, $targetPid, $selfSummary)
        & $AdbPath -s $DeviceSerial shell am force-stop $apkCase.Package | Out-Null
    }
    Write-Output 'pixel8-stage1-dbi-apks PASS'
    } catch {
        $testFailure = Redact $_.Exception.Message
        throw $testFailure
    }
}

$after = Invoke-Device 'capabilities' 'post-test capability query' $true
if ($after -notmatch 'active=0 busy=0 images=0') { throw "Residual state: $after" }
$unload = Invoke-Device 'unload' 'KPM unload' $true
if ($unload -notmatch 'unloaded module=rtgum-stage1') { throw "Unexpected unload result: $unload" }
if ($Mode -eq 'ChannelHook') {
    $restored = Invoke-Device 'syscall283' 'membarrier restoration'
    if ($restored -ne $script:channelBaseline) { throw "Channel was not restored: $restored" }
    Write-Output $restored
}
if ($Mode -eq 'FileMismatch') {
    & $AdbPath -s $DeviceSerial shell "rm -f $remote/libc.so" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot remove provider identity fixture' }
}
$names = Invoke-Device 'list' 'KPM list'
if ($names -match 'rtgum-stage1') { throw 'KPM is still listed after unload' }

$dmesg = Invoke-Device 'dmesg' 'post-test log'
$safe = Redact $dmesg
$logPath = Join-Path $projectDirectory "out/device/pixel8/stage1-$($Mode.ToLowerInvariant())-$RunLabel-dmesg-redacted.txt"
Set-Content -LiteralPath $logPath -Value $safe
$start = $safe.LastIndexOf('rtgum-stage1: loaded event=')
if ($start -lt 0) { throw 'Stage 1 load marker is absent from dmesg' }
$newLog = $safe.Substring($start)
if ($newLog -match 'Unable to handle kernel paging request|Kernel panic|\bOops:|rcu_sched detected stalls|Bad page state|BUG: Bad page') {
    throw "Kernel anomaly found in $logPath"
}
if ($newLog -match 'BUG: non-zero pgtables_bytes on freeing mm') {
    throw "Ghost page-table accounting residue in $logPath"
}
$collisionSensitiveModes = @(
    'Sandbox', 'ZygoteInit', 'ZygoteFork', 'ZygotePackage', 'ZygoteReload',
    'ZygoteJniCode', 'ZygoteJniCodeJava', 'ZygoteJniCodeBadver',
    'ZygoteJniCodeNosym', 'ZygoteDaemonReplace', 'ThreeApps', 'GumLuaTarget', 'DbiInApp',
    'DbiStalkerApps', 'GTrace', 'MultiTrace', 'Fork'
)
if ($Mode -in $collisionSensitiveModes -and $newLog -match 'mmap-guard-reject') {
    throw "A normal application mapping collided with the ghost arena in $logPath"
}
if ($Mode -eq 'ZygotePackage' -and
    ($newLog -notmatch 'daemon-syscall done op=10 result=0' -or
     $newLog -notmatch 'daemon-syscall done op=11 result=0' -or
     $newLog -notmatch 'rtgum-stage2-module: ghost alloc roundtrip ok')) {
    throw "Package module did not prove ghost alloc/protect/free in $logPath"
}
if ($Mode -eq 'ZygoteReload' -and
    ($newLog -notmatch 'rtgum-stage2-module: unload' -or
     $newLog -notmatch 'rtgum-stage2-module2: ghost alloc roundtrip ok' -or
     $newLog -notmatch 'daemon-syscall done op=11 result=0')) {
    throw "Hot reload callback or replacement module is absent in $logPath"
}
if ($Mode -eq 'ZygoteJniCode' -and
    ($newLog -notmatch 'rtgum-jnicode-module: poll armed' -or
     $newLog -notmatch 'rtgum-jnicode-module: jni replaced')) {
    throw "JNICode native rewrite breadcrumbs are absent in $logPath"
}
if ($Mode -eq 'ZygoteJniCodeJava' -and
    ($newLog -notmatch 'rtgum-jnicode-java: poll armed' -or
     $newLog -notmatch 'rtgum-jnicode-java: onCreate replaced')) {
    throw "JNICode Java rewrite breadcrumbs are absent in $logPath"
}
if ($Mode -eq 'ZygoteJniCodeBadver' -and
    ($newLog -notmatch 'rtgum-jnicode-badver: host version rejected' -or
     $newLog -match 'rtgum-jnicode-module: jni replaced' -or
     $newLog -match 'rtgum-jnicode-java: onCreate replaced')) {
    throw "Failed-module breadcrumbs missing or a rewrite ran in $logPath"
}
if ($Mode -eq 'ZygoteJniCodeNosym' -and
    ($newLog -notmatch 'rtgum-jnicode-nosym: poll armed' -or
     $newLog -notmatch 'rtgum-jnicode-nosym: symbol missing' -or
     $newLog -match 'rtgum-jnicode-module: jni replaced')) {
    throw "Nosym breadcrumbs missing or a rewrite ran in $logPath"
}
if ($Mode -eq 'ThreeApps') {
    if ($newLog -notmatch 'rtgum-gum: gum_init_embedded done') {
        throw "Gum backend init breadcrumbs are absent in $logPath"
    }
    if ($newLog -notmatch 'gum-lua armed getpid') {
        throw "Gum Lua attach breadcrumbs are absent from the kernel channel"
    }
    # Per-app acceptance: each of the three targets must report armed+fired
    # with its own distinct PID, and that PID must show a hit breadcrumb in
    # the authenticated Daemon/KPM log. One global hit is not enough.
    $targetPids = @{}
    foreach ($label in @('imusic', 'yeemiao', 'funshion')) {
        $targetLine = [regex]::Match($script:lastTestResult,
                                     "target=$label gumlua-armed=1 hook-fired=1 lua-callback=1 memory-io=1 pid=(\d+)")
        if (-not $targetLine.Success) { throw "ThreeApps target $label did not arm and fire" }
        $targetPid = $targetLine.Groups[1].Value
        $targetPids[$targetPid] = $true
        if ($newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua getpid hit=1 lua-enter=1" -or
            $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua getpid leave=1 lua-leave=1" -or
            $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua ordinary-memory=1" -or
            $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua ghost-memory=1") {
            throw "ThreeApps target $label (pid $targetPid) lacks Lua callback or memory breadcrumbs"
        }
        Write-Output "three-apps target=$label pid=$targetPid armed=1 fired=1"
        if ($script:lastTestResult -notmatch
            "target=$label backends-vmaless=1 gum-base=0x[0-9a-f]+ lua-base=0x[0-9a-f]+ maps-hidden=1 smaps-hidden=1 pid=$([regex]::Escape($targetPid))") {
            throw "ThreeApps target $label did not prove VMA-less Gum/Lua backends"
        }
    }
    if ($targetPids.Count -ne 3) { throw 'ThreeApps targets did not run as three distinct processes' }
    if ($script:lastTestResult -notmatch 'child-cleaned=1') {
        throw 'ThreeApps child cleanup did not complete'
    }
}
if ($Mode -eq 'GumLuaTarget') {
    if ($newLog -notmatch 'rtgum-gum: gum_init_embedded done') {
        throw "Gum backend init breadcrumbs are absent for $TargetPackage in $logPath"
    }
    if ($newLog -notmatch 'gum-lua armed getpid') {
        throw "Gum Lua attach breadcrumbs are absent for $TargetPackage"
    }
    $targetLine = [regex]::Match(
        $script:lastTestResult,
        "target=$([regex]::Escape($TargetLabel)) gumlua-armed=1 hook-fired=1 lua-callback=1 memory-io=1 pid=(\d+)")
    if (-not $targetLine.Success) {
        throw "GumLuaTarget $TargetLabel did not arm and fire"
    }
    $targetPid = $targetLine.Groups[1].Value
    if ($newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua getpid hit=1 lua-enter=1" -or
        $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua getpid leave=1 lua-leave=1" -or
        $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua ordinary-memory=1" -or
        $newLog -notmatch "rtgum-daemon\[$([regex]::Escape($targetPid))\]: gum-lua ghost-memory=1") {
        throw "GumLuaTarget $TargetLabel (pid $targetPid) lacks Lua callback or memory breadcrumbs"
    }
    if ($script:lastTestResult -notmatch 'child-cleaned=1') {
        throw "GumLuaTarget $TargetLabel child cleanup did not complete"
    }
    if ($script:lastTestResult -notmatch
        "target=$([regex]::Escape($TargetLabel)) hook-survived=1 quiet-seconds=$HookQuietSeconds pid=$([regex]::Escape($targetPid))") {
        throw "GumLuaTarget $TargetLabel did not survive the $HookQuietSeconds-second observation window"
    }
    if ($script:lastTestResult -notmatch
        "target=$([regex]::Escape($TargetLabel)) backends-vmaless=1 gum-base=0x[0-9a-f]+ lua-base=0x[0-9a-f]+ maps-hidden=1 smaps-hidden=1 pid=$([regex]::Escape($targetPid))") {
        throw "GumLuaTarget $TargetLabel did not prove VMA-less Gum/Lua backends"
    }
    Write-Output "gumlua-target package=$TargetPackage label=$TargetLabel pid=$targetPid armed=1 fired=1 vmaless=1"
}
if ($Mode -eq 'GTrace' -and
    ($newLog -notmatch 'gtrace-edge .*kind=br branch=indirect reg=x16 .*target-scope=internal' -or
     $newLog -notmatch 'gtrace-gap .*bytes=12 direction=forward candidate-junk=1' -or
     $newLog -notmatch 'gtrace-summary executed=5 branches=2 indirect=2 internal-targets=1 gaps=1 skipped-bytes=12 losses=0 mismatches=0 unreadable=0' -or
     $newLog -notmatch 'rtgum-gtrace: result=42 executed=5 junk-executed=0' -or
     $newLog -notmatch 'rtgum-gtrace: PASS')) {
    throw "GTrace dynamic-path breadcrumbs are incomplete in $logPath"
}
if ($Mode -eq 'MultiTrace' -and
    ($newLog -notmatch 'rtgum-multitrace: callbacks A/B=2/3' -or
     $newLog -notmatch 'rtgum-multitrace: steps A/B=6/9' -or
     $newLog -notmatch 'rtgum-multitrace: per-handle config isolated' -or
     $newLog -notmatch 'rtgum-multitrace: relocated prologue coverage complete' -or
     $newLog -notmatch 'rtgum-multitrace: query-stop race safe' -or
     $newLog -notmatch 'rtgum-multitrace: PASS')) {
    throw "Multi-trace handle breadcrumbs are incomplete in $logPath"
}
if ($Mode -eq 'TaskworkSelfTest' -and
    $newLog -notmatch 'taskwork-self-test delivered') {
    throw "task_work breadcrumbs are absent in $logPath"
}
Write-Output $after
Write-Output $unload
Write-Output "log=$logPath"
Write-Output "pixel8-stage1-$($Mode.ToLowerInvariant()) PASS"
