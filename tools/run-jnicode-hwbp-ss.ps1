param(
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($AdbPath)) {
    $AdbPath = Join-Path $projectDirectory ".toolchains\platform-tools-37.0.1\platform-tools\adb.exe"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}
$testBinary = Join-Path $OutputDirectory "rtgum-hwbp-ss-test"
if (-not (Test-Path -LiteralPath $testBinary)) { throw "Missing: $testBinary" }
$remote = "/data/local/tmp/rtgum-stage1-pixel8"
& $AdbPath -s $DeviceSerial shell "mkdir -p $remote" | Out-Null
& $AdbPath -s $DeviceSerial push $testBinary "$remote/rtgum-hwbp-ss-test" | Out-Null
& $AdbPath -s $DeviceSerial shell "chmod 0755 $remote/rtgum-hwbp-ss-test" | Out-Null
$result = & $AdbPath -s $DeviceSerial shell "su -c '$remote/rtgum-hwbp-ss-test'" 2>&1 | Out-String
Write-Output $result
if ($result -notmatch 'jnicode-hwbp-ss PASS') { throw "HWBP/SS test failed" }
