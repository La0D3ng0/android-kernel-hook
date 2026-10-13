param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$KernelPatchPath = "",
    [string]$KernelPatchVersion = "0.12.2",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($KernelPatchPath)) {
    $KernelPatchPath = Join-Path $projectDirectory "third_party\KernelPatch-$KernelPatchVersion"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage0"
}
if ($KernelPatchVersion -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw "KernelPatchVersion must be major.minor.patch: $KernelPatchVersion"
}
$kpMajor = [int]$Matches[1]
$kpMinor = [int]$Matches[2]
$kpPatch = [int]$Matches[3]
if ($kpMajor -gt 65535 -or $kpMinor -gt 255 -or $kpPatch -gt 255) {
    throw "KernelPatchVersion components exceed the SuperCall version fields: $KernelPatchVersion"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.cmd"
$source = Join-Path $projectDirectory "tools\rtgum-stage0-ctl.c"
$output = Join-Path $OutputDirectory "rtgum-stage0-ctl"

foreach ($required in @(
    $compiler,
    $source,
    (Join-Path $projectDirectory "include\rtgum\kpm_supercall.h"),
    (Join-Path $KernelPatchPath "kernel\include\kpmodule.h")
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required path not found: $required"
    }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$flags = @(
    "-std=c11",
    "-O2",
    "-g",
    "-fPIE",
    "-pie",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-DANDROID",
    "-DRTGUM_KP_VERSION_MAJOR=$kpMajor",
    "-DRTGUM_KP_VERSION_MINOR=$kpMinor",
    "-DRTGUM_KP_VERSION_PATCH=$kpPatch",
    "-I$(Join-Path $projectDirectory 'include')"
)

& $compiler @flags $source "-o" $output
if ($LASTEXITCODE -ne 0) {
    throw "Stage-0 client compilation failed with exit code $LASTEXITCODE"
}

Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
