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

$clang = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.cmd"
$clangxx = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
if (-not (Test-Path -LiteralPath $clangxx)) {
    $clang = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.exe"
    $clangxx = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.exe"
}
$sample = Join-Path $projectDirectory "tests\relr-sample.c"
$testSource = Join-Path $projectDirectory "tests\rtgum-relr-test.cpp"
$include = Join-Path $projectDirectory "include"
$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
foreach ($required in @($clang, $clangxx, $sample, $testSource, $include)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$so = Join-Path $OutputDirectory "librtgum-relr-sample.so"
$sampleFlags = @(
    "-O2", "-fPIC", "-shared",
    "-Wl,-soname,librtgum-relr-sample.so",
    "-Wl,--pack-dyn-relocs=relr",
    "-Wl,-z,pack-relative-relocs"
)
& $clang @sampleFlags $sample "-o" $so
if ($LASTEXITCODE -ne 0) { throw "RELR sample compilation failed" }

if (Test-Path -LiteralPath $readelf) {
    $dynamic = (& $readelf --dynamic-table $so) -join "`n"
    if ($dynamic -notmatch "RELR") {
        Write-Output $dynamic
        throw "RELR sample did not produce DT_RELR or ANDROID_RELR"
    }
}

$testOut = Join-Path $OutputDirectory "rtgum-relr-test"
$testFlags = @(
    "-std=c++17", "-O2", "-g", "-fPIE", "-pie", "-static-libstdc++",
    "-Wall", "-Wextra",
    "-I$include"
)
& $clangxx @testFlags $testSource "-o" $testOut
if ($LASTEXITCODE -ne 0) { throw "RELR test compilation failed" }

Get-Item -LiteralPath $so, $testOut | Select-Object FullName, Length, LastWriteTime
Write-Output "jnicode-relr-build PASS"
