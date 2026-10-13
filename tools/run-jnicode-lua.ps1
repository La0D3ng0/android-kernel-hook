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
$helper = Join-Path $OutputDirectory "librtgum-lua-helper.so"
$testBinary = Join-Path $OutputDirectory "rtgum-jnicode-lua-test"
foreach ($path in @($AdbPath, $helper, $testBinary)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing: $path" }
}

function Invoke-AdbChecked {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & $AdbPath -s $DeviceSerial @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed ($LASTEXITCODE): $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return $output
}

function Assert-RemoteSha256 {
    param([string]$LocalPath, [string]$RemotePath)
    $local = (Get-FileHash -Algorithm SHA256 -LiteralPath $LocalPath).Hash.ToLowerInvariant()
    $line = (Invoke-AdbChecked shell "sha256sum '$RemotePath'") -join "`n"
    $remoteHash = ($line -split '\s+')[0].ToLowerInvariant()
    if ($remoteHash -ne $local) {
        throw "SHA256 mismatch for $RemotePath (local=$local remote=$remoteHash)"
    }
}

$remote = "/data/local/tmp/rtgum-stage1-pixel8"
Invoke-AdbChecked shell "mkdir -p $remote" | Out-Null
Invoke-AdbChecked push $helper "$remote/librtgum-lua-helper.so" | Out-Null
Invoke-AdbChecked push $testBinary "$remote/rtgum-jnicode-lua-test" | Out-Null
Assert-RemoteSha256 $helper "$remote/librtgum-lua-helper.so"
Assert-RemoteSha256 $testBinary "$remote/rtgum-jnicode-lua-test"
Invoke-AdbChecked shell "chmod 0755 $remote/rtgum-jnicode-lua-test" | Out-Null
$result = (Invoke-AdbChecked shell "$remote/rtgum-jnicode-lua-test $remote/librtgum-lua-helper.so") -join "`n"
Write-Output $result
if ($result -notmatch 'jnicode-lua PASS') { throw "Lua helper test failed" }
