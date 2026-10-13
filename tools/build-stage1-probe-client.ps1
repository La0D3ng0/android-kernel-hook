param(
    [string]$NdkPath = "",
    [int]$Api = 35,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if (-not $NdkPath) { $NdkPath = Join-Path $projectDirectory '.toolchains/android-ndk-r29' }
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory 'out/kpm-stage1-probe-pixel8'
}
$compiler = Join-Path $NdkPath "toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android$Api-clang.cmd"
$readelf = Join-Path $NdkPath 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
$source = Join-Path $projectDirectory 'tools/rtgum-stage1-probe-ctl.c'
$output = Join-Path $OutputDirectory 'rtgum-stage1-probe-ctl'
foreach ($path in @($compiler, $readelf, $source)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $path" }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
& $compiler -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie -DANDROID `
    -DRTGUM_KP_VERSION_MAJOR=0 -DRTGUM_KP_VERSION_MINOR=13 `
    -DRTGUM_KP_VERSION_PATCH=9 "-I$(Join-Path $projectDirectory 'include')" `
    $source -o $output
if ($LASTEXITCODE -ne 0) { throw 'Pixel 8 Stage 1 probe client compilation failed' }
$header = (& $readelf --file-header $output) -join "`n"
if ($LASTEXITCODE -ne 0 -or $header -notmatch 'Machine:\s+AArch64' -or
    $header -notmatch 'Type:\s+DYN') { throw 'Probe client ELF verification failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath $output | Select-Object Path,Hash
