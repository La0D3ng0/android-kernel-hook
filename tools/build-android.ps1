param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\android-arm64"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Android compiler not found: $compiler"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$sources = @(
    (Join-Path $projectDirectory "src\core\runtime.cpp"),
    (Join-Path $projectDirectory "src\activation\kpm_dry_run.cpp"),
    (Join-Path $projectDirectory "src\art\art_probe.cpp"),
    (Join-Path $projectDirectory "src\memory\memory_region.cpp"),
    (Join-Path $projectDirectory "src\loader\elf_image.cpp"),
    (Join-Path $projectDirectory "src\loader\module_runtime.cpp"),
    (Join-Path $projectDirectory "src\loader\system_library.cpp")
)
$common = @(
    "-std=c++17",
    "-O2",
    "-g",
    "-fPIE",
    "-pie",
    "-static-libstdc++",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wconversion",
    "-I$projectDirectory\include"
)

$probe = Join-Path $OutputDirectory "rtgum_probe"
$tests = Join-Path $OutputDirectory "rtgum_tests"
$kpmPlan = Join-Path $OutputDirectory "rtgum_kpm_plan"

& $compiler @common @sources (Join-Path $projectDirectory "examples\rtgum_probe.cpp") "-ldl" "-o" $probe
if ($LASTEXITCODE -ne 0) {
    throw "Android probe compilation failed with exit code $LASTEXITCODE"
}

& $compiler @common @sources (Join-Path $projectDirectory "tests\rtgum_tests.cpp") "-ldl" "-o" $tests
if ($LASTEXITCODE -ne 0) {
    throw "Android test compilation failed with exit code $LASTEXITCODE"
}

& $compiler @common @sources (Join-Path $projectDirectory "examples\rtgum_kpm_plan.cpp") "-ldl" "-o" $kpmPlan
if ($LASTEXITCODE -ne 0) {
    throw "Android KPM dry-run planner compilation failed with exit code $LASTEXITCODE"
}

Get-Item -LiteralPath $probe, $tests, $kpmPlan | Select-Object FullName, Length
