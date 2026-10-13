param(
    [string]$AdbPath = "D:\Pixel2_root\platform-tools-latest-windows\platform-tools\adb.exe",
    [string]$SuperKeyPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SuperKeyPath)) {
    $SuperKeyPath = Join-Path $projectDirectory "out\device\stage0-superkey.txt"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1"
}
if (-not (Test-Path -LiteralPath $AdbPath)) {
    $adbCommand = Get-Command adb -ErrorAction SilentlyContinue
    if (-not $adbCommand) { throw "ADB not found: $AdbPath" }
    $AdbPath = $adbCommand.Source
}

$device = ((& $AdbPath shell getprop ro.product.device) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $device -ne 'grus') {
    throw "This deployment is validated only on Xiaomi grus; detected '$device'"
}

$key = (Get-Content -LiteralPath $SuperKeyPath -Raw).Trim()
if ($key -notmatch '^[A-Za-z0-9._-]+$') { throw 'SuperKey contains unsupported shell characters' }
$kpm = Join-Path $OutputDirectory 'rtgum-stage1.kpm'
$client = Join-Path $OutputDirectory 'rtgum-stage1-ctl'
$payload = Join-Path $OutputDirectory 'rtgum-stage1-payload.so'
$daemon = Join-Path $OutputDirectory 'rtgum-stage2-daemon.so'
$module = Join-Path $OutputDirectory 'rtgum-stage2-module.ghm'
$module2 = Join-Path $OutputDirectory 'rtgum-stage2-module2.ghm'
$zygotePayload = Join-Path $OutputDirectory 'rtgum-stage2-zygote-payload.so'
$sessionPath = Join-Path $projectDirectory 'out\device\stage2-session-key.txt'
foreach ($required in @($kpm, $client, $payload, $daemon, $module, $module2, $zygotePayload)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required artifact not found: $required" }
}

if ((& $AdbPath get-state) -ne 'device') { throw 'ADB device is not online' }
$remote = '/data/local/tmp/rtgum-stage1'
& $AdbPath shell "mkdir -p $remote"
if ($LASTEXITCODE -ne 0) { throw 'Cannot create the remote stage-1 directory' }

# Install the control binary first so an already-loaded current module can be
# checked and safely unloaded before its KPM file is replaced.
& $AdbPath push $client "$remote/rtgum-stage1-ctl"
& $AdbPath shell "chmod 0755 $remote/rtgum-stage1-ctl"
$existingSession = ''
if (Test-Path -LiteralPath $sessionPath) {
    $existingSession = (Get-Content -LiteralPath $sessionPath -Raw).Trim()
}
$existingAuth = if ($existingSession -match '^[0-9a-f]{64}$') {
    "RTGUM_SESSION_KEY=$existingSession "
} else { '' }
$null = & $AdbPath shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl info 2>/dev/null" 2>$null
if ($LASTEXITCODE -eq 0) {
    $caps = (& $AdbPath shell "RTGUM_SUPERKEY=$key $existingAuth$remote/rtgum-stage1-ctl capabilities") -join "`n"
    if ($LASTEXITCODE -ne 0 -or $caps -notmatch 'active=0' -or
        $caps -notmatch 'busy=0' -or $caps -notmatch 'images=0') {
        throw "Refusing to replace a busy or incompatible loaded module: $caps"
    }
    & $AdbPath shell "RTGUM_SUPERKEY=$key $existingAuth$remote/rtgum-stage1-ctl unload"
    if ($LASTEXITCODE -ne 0) { throw 'Existing stage-1 KPM could not be unloaded safely' }
}

& $AdbPath push $kpm "$remote/rtgum-stage1.kpm"
& $AdbPath push $payload "$remote/rtgum-stage1-payload.so"
& $AdbPath push $daemon "$remote/rtgum-stage2-daemon.so"
& $AdbPath push $module "$remote/rtgum-stage2-module.ghm"
& $AdbPath push $module2 "$remote/rtgum-stage2-module2.ghm"
& $AdbPath push $zygotePayload "$remote/rtgum-stage2-zygote-payload.so"
if ($LASTEXITCODE -ne 0) { throw 'Artifact push failed' }
& $AdbPath shell "chmod 0644 $remote/rtgum-stage1.kpm $remote/rtgum-stage1-payload.so $remote/rtgum-stage2-daemon.so $remote/rtgum-stage2-module.ghm $remote/rtgum-stage2-module2.ghm $remote/rtgum-stage2-zygote-payload.so"
& $AdbPath shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl load $remote/rtgum-stage1.kpm"
if ($LASTEXITCODE -ne 0) { throw 'Stage-2 KPM load failed' }
$dmesg = @(& $AdbPath shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl dmesg")
if ($LASTEXITCODE -ne 0) { throw 'Cannot read the stage-2 debug pairing code' }
$pairLine = $dmesg | Select-String -Pattern 'rtgum-stage2-auth: debug-pair-code=([0-9]{6}) one-time=1' | Select-Object -Last 1
if (-not $pairLine) {
    throw 'One-time stage-2 pairing code was not found'
}
$pairMatch = [regex]::Match($pairLine.Line, 'debug-pair-code=([0-9]{6})')
if (-not $pairMatch.Success) { throw 'One-time stage-2 pairing code was malformed' }
$pairCode = $pairMatch.Groups[1].Value
$pairResponse = (@(& $AdbPath shell "RTGUM_SUPERKEY=$key $remote/rtgum-stage1-ctl session-pair $pairCode")) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'One-time stage-2 pairing failed' }
$sessionMatch = [regex]::Match($pairResponse, '^ok session=([0-9a-f]{64}) mode=debug one_time=1$')
if (-not $sessionMatch.Success) {
    throw 'One-time stage-2 pairing failed'
}
$session = $sessionMatch.Groups[1].Value
Set-Content -LiteralPath $sessionPath -Value $session -NoNewline
& $AdbPath shell "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$session $remote/rtgum-stage1-ctl probe $remote/rtgum-stage1.kpm"
if ($LASTEXITCODE -ne 0) { throw 'Stage-1 probe failed' }
Write-Output 'stage1-deploy PASS'
