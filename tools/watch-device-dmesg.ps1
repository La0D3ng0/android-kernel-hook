param(
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = '',
    [string]$SuperKeyFile = '',
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Continue'
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
if (-not $OutputPath) {
    $OutputPath = Join-Path $projectDirectory 'out/device/pixel8/dmesg-watch.txt'
}

$superKey = (Get-Content -Raw -LiteralPath $SuperKeyFile).Trim()
$client = '/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage1-ctl'
Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue

while ($true) {
    $state = (& $AdbPath -s $DeviceSerial get-state 2>$null | Out-String).Trim()
    if ($state -ne 'device') {
        Start-Sleep -Milliseconds 500
        continue
    }
    $bootId = (& $AdbPath -s $DeviceSerial shell cat /proc/sys/kernel/random/boot_id 2>$null |
        Out-String).Trim()
    Add-Content -LiteralPath $OutputPath -Value "=== boot=$bootId ==="
    & $AdbPath -s $DeviceSerial shell `
        "RTGUM_SUPERKEY=$superKey $client dmesg-w" 2>&1 |
        ForEach-Object { Add-Content -LiteralPath $OutputPath -Value $_.ToString() }
    Start-Sleep -Milliseconds 250
}
