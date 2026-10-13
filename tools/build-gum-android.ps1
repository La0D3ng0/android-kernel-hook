param(
    [string]$NdkPath = "",
    [string]$DevkitPath = "",
    [string]$OutputDirectory = "",
    [int]$Api = 35
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory '.toolchains\android-ndk-r29'
}
if ([string]::IsNullOrWhiteSpace($DevkitPath)) {
    $DevkitPath = Join-Path $projectDirectory `
        '.toolchains\frida-gum-devkit-17.22.2-android-arm64'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory 'out\gum-cmake-arm64'
}

$cmake = Join-Path $projectDirectory `
    '.toolchains\cmake-3.31.12-windows-x86_64\bin\cmake.exe'
$ninja = Join-Path $projectDirectory '.toolchains\ninja-1.13.2\ninja.exe'
$toolchain = Join-Path $NdkPath 'build\cmake\android.toolchain.cmake'
foreach ($required in @($cmake, $ninja, $toolchain,
                       (Join-Path $DevkitPath 'frida-gum.h'),
                       (Join-Path $DevkitPath 'libfrida-gum.a'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required build file is missing: $required"
    }
}

& $cmake -S $projectDirectory -B $OutputDirectory -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain" `
    '-DANDROID_ABI=arm64-v8a' "-DANDROID_PLATFORM=android-$Api" `
    '-DRTGUM_WITH_FRIDA_GUM=ON' "-DRTGUM_FRIDA_GUM_DEVKIT=$DevkitPath" `
    '-DRTGUM_BUILD_TESTS=OFF'
if ($LASTEXITCODE -ne 0) { throw "Gum CMake configuration failed: $LASTEXITCODE" }

& $cmake --build $OutputDirectory --target rtgum_gum_smoke rtgum_gum_lua_smoke -j 4
if ($LASTEXITCODE -ne 0) { throw "Gum examples build failed: $LASTEXITCODE" }

Get-Item -LiteralPath (Join-Path $OutputDirectory 'rtgum_gum_smoke'), `
    (Join-Path $OutputDirectory 'rtgum_gum_lua_smoke') |
    Select-Object FullName, Length
