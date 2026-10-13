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
$sample = Join-Path $OutputDirectory "librtgum-relr-sample.so"
$testBinary = Join-Path $OutputDirectory "rtgum-relr-test"
foreach ($path in @($AdbPath, $sample, $testBinary)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing: $path" }
}
$remote = "/data/local/tmp/rtgum-stage1-pixel8"
& $AdbPath -s $DeviceSerial shell "mkdir -p $remote" | Out-Null
& $AdbPath -s $DeviceSerial push $sample "$remote/librtgum-relr-sample.so" | Out-Null
& $AdbPath -s $DeviceSerial push $testBinary "$remote/rtgum-relr-test" | Out-Null
& $AdbPath -s $DeviceSerial shell "chmod 0755 $remote/rtgum-relr-test" | Out-Null
$result = & $AdbPath -s $DeviceSerial shell "$remote/rtgum-relr-test $remote/librtgum-relr-sample.so" 2>&1 | Out-String
Write-Output $result
if ($result -notmatch 'jnicode-relr PASS') { throw "RELR test failed" }
