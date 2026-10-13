param(
    [int]$Iterations = 5,
    [switch]$IncludeRealSo,
    [switch]$IncludeZygote,
    [switch]$IncludeInject,
    [string]$InjectPackage = "",
    [string]$AdbPath = "D:\Pixel2_root\platform-tools-latest-windows\platform-tools\adb.exe",
    [string]$SuperKeyPath = ""
)

$ErrorActionPreference = "Stop"
if ($Iterations -lt 1) { throw 'Iterations must be positive' }
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SuperKeyPath)) {
    $SuperKeyPath = Join-Path $projectDirectory "out\device\stage0-superkey.txt"
}
if (-not (Test-Path -LiteralPath $AdbPath)) {
    $adbCommand = Get-Command adb -ErrorAction SilentlyContinue
    if (-not $adbCommand) { throw "ADB not found: $AdbPath" }
    $AdbPath = $adbCommand.Source
}
$device = ((& $AdbPath shell getprop ro.product.device) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $device -ne 'grus') {
    throw "This device test is validated only on Xiaomi grus; detected '$device'"
}
$key = (Get-Content -LiteralPath $SuperKeyPath -Raw).Trim()
if ($key -notmatch '^[A-Za-z0-9._-]+$') { throw 'SuperKey contains unsupported shell characters' }
$client = '/data/local/tmp/rtgum-stage1/rtgum-stage1-ctl'
$sessionPath = Join-Path $projectDirectory 'out\device\stage2-session-key.txt'
if (-not (Test-Path -LiteralPath $sessionPath)) { throw 'Stage-2 session key is missing; deploy first' }
$session = (Get-Content -LiteralPath $sessionPath -Raw).Trim()
if ($session -notmatch '^[0-9a-f]{64}$') { throw 'Stage-2 session key is invalid' }
$run = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session $client"

$before = @(& $AdbPath shell "$run dmesg")
if ($LASTEXITCODE -ne 0) { throw 'Cannot capture the dmesg baseline' }
$baselineTimestamp = 0.0
foreach ($line in $before) {
    if ($line -match '^\[\s*([0-9]+(?:\.[0-9]+)?)\]') {
        $timestamp = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        if ($timestamp -gt $baselineTimestamp) { $baselineTimestamp = $timestamp }
    }
}
$passes = 0
$tests = @('ghost-test', 'fork-test', 'linker-test')
if ($IncludeRealSo) { $tests += 'real-so-test' }
if ($IncludeZygote) { $tests += 'zygote-test' }
foreach ($iteration in 1..$Iterations) {
    foreach ($test in $tests) {
        $output = @(& $AdbPath shell "$run $test")
        if ($LASTEXITCODE -ne 0 -or -not ($output | Select-String -SimpleMatch 'PASS')) {
            throw "iteration=$iteration test=$test failed: $($output -join ' | ')"
        }
        if ($test -eq 'linker-test' -and
            -not ($output | Select-String -SimpleMatch 'arm64-bootstrap=1')) {
            throw "iteration=$iteration linker-test did not exercise the ARM64 bootstrap"
        }
        if ($test -eq 'real-so-test' -and
            (-not ($output | Select-String -SimpleMatch 'dt-needed=1') -or
             -not ($output | Select-String -Pattern 'needed=6\s+imports=13'))) {
            throw "iteration=$iteration real-so-test did not verify 6 NEEDED and 13 imports"
        }
        ++$passes
    }
}

if ($IncludeInject) {
    if ($InjectPackage -notmatch '^[A-Za-z][A-Za-z0-9_.]{2,126}$' -or
        $InjectPackage -notmatch '\.') {
        throw 'IncludeInject requires a valid InjectPackage'
    }
    $output = @(& $AdbPath shell "$run stage2-test $InjectPackage")
    if ($LASTEXITCODE -ne 0 -or -not ($output | Select-String -SimpleMatch 'PASS')) {
        throw "stage2-inject-test failed: $($output -join ' | ')"
    }
    if (-not ($output | Select-String -SimpleMatch 'zygote-hijack=1') -or
        -not ($output | Select-String -SimpleMatch 'fork-inherit=1') -or
        -not ($output | Select-String -SimpleMatch 'hot-reload=1')) {
        throw "stage2-inject-test did not verify the full injection chain"
    }
    ++$passes
}

$caps = (@(& $AdbPath shell "$run capabilities")) -join "`n"
if ($LASTEXITCODE -ne 0 -or $caps -notmatch 'ready=1' -or $caps -notmatch 'hooks=1' -or
    $caps -notmatch 'daemon=0') {
    throw "Final capability state is invalid: $caps"
}
if (-not $IncludeInject -and ($caps -notmatch 'active=0' -or
    $caps -notmatch 'busy=0' -or $caps -notmatch 'images=0')) {
    throw "Final non-injection state is not idle: $caps"
}

$after = @(& $AdbPath shell "$run dmesg")
if ($LASTEXITCODE -ne 0) { throw 'Cannot capture final dmesg' }
$delta = @($after | Where-Object {
    if ($_ -notmatch '^\[\s*([0-9]+(?:\.[0-9]+)?)\]') { return $false }
    [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) -gt
        $baselineTimestamp
})
$anomalies = @($delta | Select-String -Pattern 'BUG:|Oops:|Unable to handle|kernel panic|Kernel panic|Call trace:|Internal error:|use-after-free|double free|Bad page state|rtgum-stage1:.*(failed|missing|occupied|bad pgd|conversion failed|remaining=[1-9])')
if ($anomalies.Count -ne 0) {
    throw "New kernel anomalies detected: $($anomalies -join ' | ')"
}

Write-Output "stage-tests passes=$passes/$($Iterations * $tests.Count + [int]$IncludeInject.IsPresent) dmesg_anomalies=0 real_so=$([int]$IncludeRealSo.IsPresent) zygote=$([int]$IncludeZygote.IsPresent) inject=$([int]$IncludeInject.IsPresent)"
Write-Output $caps
Write-Output 'stage1-device PASS'
