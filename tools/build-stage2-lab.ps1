param(
    [string]$NdkPath = "",
    [int]$Api = 35,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r29"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
$source = Join-Path $projectDirectory "tests\stage2-lab.cpp"
$output = Join-Path $OutputDirectory "librtgum-lab.so"

foreach ($required in @($compiler, $source)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$flags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-fno-exceptions", "-fno-rtti",
    "-static-libstdc++", "-Wall", "-Wextra", "-Wpedantic"
)

& $compiler @flags $source "-o" $output
if ($LASTEXITCODE -ne 0) { throw "Lab library compilation failed with exit code $LASTEXITCODE" }
Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
Write-Output "stage2-lab PASS"
