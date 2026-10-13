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
if (-not $AdbPath) {
    $AdbPath = Join-Path $projectDirectory ".toolchains\platform-tools-37.0.1\platform-tools\adb.exe"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$testBinary = Join-Path $OutputDirectory "rtgum-jnicode-native-hook-test"
$library = Join-Path $projectDirectory "out\apk-baseline\lib\arm64-v8a\libjnicode.so"
foreach ($path in @($AdbPath, $testBinary, $library)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $path" }
}

$remote = "/data/local/tmp/rtgum-m2"
& $AdbPath -s $DeviceSerial shell "mkdir -p $remote" | Out-Null
& $AdbPath -s $DeviceSerial push $testBinary "$remote/rtgum-jnicode-native-hook-test" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Cannot push native-hook test" }
& $AdbPath -s $DeviceSerial push $library "$remote/libjnicode.so" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Cannot push libjnicode.so" }
& $AdbPath -s $DeviceSerial shell "chmod 0755 $remote/rtgum-jnicode-native-hook-test" | Out-Null
$result = & $AdbPath -s $DeviceSerial shell "$remote/rtgum-jnicode-native-hook-test $remote/libjnicode.so" 2>&1 | Out-String
Write-Output $result.Trim()
if ($LASTEXITCODE -ne 0 -or $result -notmatch "jnicode-native-hook PASS") {
    throw "Visible native-hook test failed"
}
