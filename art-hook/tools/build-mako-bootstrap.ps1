param(
    [string]$JavaHomePath = "",
    [string]$AndroidSdkPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($JavaHomePath)) {
    $JavaHomePath = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "D:\jdk" }
}
if ([string]::IsNullOrWhiteSpace($AndroidSdkPath)) {
    $AndroidSdkPath = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "D:\AndroidSDK" }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\mako-bootstrap"
}

$javac = Join-Path $JavaHomePath "bin\javac.exe"
$jar = Join-Path $JavaHomePath "bin\jar.exe"
$d8 = Join-Path $AndroidSdkPath "build-tools\36.0.0\d8.bat"
$source = Join-Path $projectDirectory "bootstrap\com\rtgum\mako\PreForkHost.java"
foreach ($required in @($javac, $jar, $d8, $source)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

$classes = Join-Path $OutputDirectory "classes"
$dex = Join-Path $OutputDirectory "dex"
New-Item -ItemType Directory -Force -Path $classes, $dex | Out-Null
& $javac --release 8 -Xlint:-options -d $classes $source
if ($LASTEXITCODE -ne 0) { throw "Mako bootstrap javac failed: $LASTEXITCODE" }
$classFile = Join-Path $classes "com\rtgum\mako\PreForkHost.class"
& $d8 --min-api 30 --output $dex $classFile
if ($LASTEXITCODE -ne 0) { throw "Mako bootstrap d8 failed: $LASTEXITCODE" }
$output = Join-Path $OutputDirectory "mako-prefork-host.jar"
& $jar cf $output -C $dex classes.dex
if ($LASTEXITCODE -ne 0) { throw "Mako bootstrap jar failed: $LASTEXITCODE" }
Get-Item -LiteralPath $output | Select-Object FullName, Length
