param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$artHookDirectory = Join-Path $projectDirectory "art-hook"
$buildScript = Join-Path $artHookDirectory "tools\build-android.ps1"
if (-not (Test-Path -LiteralPath $buildScript)) {
    throw "art-hook build script not found: $buildScript"
}

$arguments = @{}
if (-not [string]::IsNullOrWhiteSpace($NdkPath)) { $arguments.NdkPath = $NdkPath }
$arguments.Api = $Api
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $arguments.OutputDirectory = $OutputDirectory
}

& $buildScript @arguments
if ($LASTEXITCODE -ne 0) { throw "art-hook / JNICode Java-hook build failed" }

$artifact = Join-Path $artHookDirectory "out\android-arm64-cxx23\librtgum-jnicode-java-hook.so"
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $artifact = Join-Path $OutputDirectory "librtgum-jnicode-java-hook.so"
}
if (-not (Test-Path -LiteralPath $artifact)) {
    throw "JNICode Java-hook library was not produced: $artifact"
}
Get-FileHash -Algorithm SHA256 -LiteralPath $artifact | Format-List
Write-Output "jnicode-java-hook-build PASS"
