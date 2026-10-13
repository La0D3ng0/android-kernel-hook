param(
    [string]$NdkPath = "",
    [int]$Api = 35,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r29"
    if (-not (Test-Path -LiteralPath $NdkPath)) {
        $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
        $Api = 30
    }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.exe"
}
$source = Join-Path $projectDirectory "tests\jnicode-module-api-test.cpp"
$output = Join-Path $OutputDirectory "rtgum-jnicode-module-api-test"
$include = Join-Path $projectDirectory "include"
foreach ($required in @($compiler, $source, $include)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$flags = @(
    "-std=c++17", "-O2", "-g", "-fPIE", "-pie", "-static-libstdc++",
    "-Wall", "-Wextra", "-Wpedantic",
    "-I$include"
)
& $compiler @flags $source "-ldl" "-o" $output
if ($LASTEXITCODE -ne 0) { throw "JNICode module-api test compilation failed" }
Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
Write-Output "jnicode-module-api-test PASS"
