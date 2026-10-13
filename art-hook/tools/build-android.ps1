param(
    [string]$NdkPath = "",
    [string]$CMakePath = "",
    [string]$NinjaPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = "",
    [ValidateSet("Debug", "Release", "RelWithDebInfo")]
    [string]$BuildType = "RelWithDebInfo"
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$workspaceDirectory = Split-Path -Parent $projectDirectory

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $workspaceDirectory ".toolchains\android-ndk-r29"
}
if ([string]::IsNullOrWhiteSpace($CMakePath)) {
    $CMakePath = Join-Path $workspaceDirectory ".toolchains\cmake-3.31.12-windows-x86_64\bin\cmake.exe"
}
if ([string]::IsNullOrWhiteSpace($NinjaPath)) {
    $NinjaPath = Join-Path $workspaceDirectory ".toolchains\ninja-1.13.2\ninja.exe"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\android-arm64-cxx23"
}

$toolchain = Join-Path $NdkPath "build\cmake\android.toolchain.cmake"
if (-not (Test-Path -LiteralPath $toolchain)) {
    throw "Android NDK r29 toolchain not found: $toolchain"
}
if (-not (Test-Path -LiteralPath $CMakePath)) {
    throw "CMake 3.28+ not found: $CMakePath"
}
if (-not (Test-Path -LiteralPath $NinjaPath)) {
    throw "Ninja not found: $NinjaPath"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$configureArguments = @(
    "-S", $projectDirectory,
    "-B", $OutputDirectory,
    "-G", "Ninja",
    "-DCMAKE_MAKE_PROGRAM=$NinjaPath",
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain",
    "-DANDROID_ABI=arm64-v8a",
    "-DANDROID_PLATFORM=android-$Api",
    "-DANDROID_STL=c++_static",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "-DART_HOOK_BUILD_TESTS=ON",
    "-DART_HOOK_BUILD_SHARED=ON",
    "-DART_HOOK_BUILD_MAKO=ON",
    "-DART_HOOK_WITH_LSPLANT=ON",
    "-DLSPLANT_BUILD_SHARED=OFF",
    "-DDEX_BUILDER_BUILD_SHARED=OFF"
)

& $CMakePath @configureArguments
if ($LASTEXITCODE -ne 0) {
    throw "CMake configuration failed with exit code $LASTEXITCODE"
}

$targets = @(
    "art_hook_tests",
    "art-hook",
    "mako",
    "mako-cache",
    "mako-live-test",
    "art-hook-live-test",
    "art-hook-gum-live-test",
    "art-hook-java-proxy-live-test",
    "rtgum-jnicode-java-hook"
)
& $CMakePath --build $OutputDirectory --target @targets
if ($LASTEXITCODE -ne 0) {
    throw "Android build failed with exit code $LASTEXITCODE"
}

$artifacts = @(
    (Join-Path $OutputDirectory "art_hook_tests"),
    (Join-Path $OutputDirectory "libart-hook.so"),
    (Join-Path $OutputDirectory "libmako.so"),
    (Join-Path $OutputDirectory "libmako-cache.so"),
    (Join-Path $OutputDirectory "libmako-live-test.so"),
    (Join-Path $OutputDirectory "libart-hook-live-test.so"),
    (Join-Path $OutputDirectory "libart-hook-gum-live-test.so"),
    (Join-Path $OutputDirectory "libart-hook-java-proxy-live-test.so"),
    (Join-Path $OutputDirectory "librtgum-jnicode-java-hook.so")
)
Get-Item -LiteralPath $artifacts | Select-Object FullName, Length
