param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [switch]$ForceRela,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$source = Join-Path $projectDirectory "tests\stage1-linker-payload.cpp"
$output = Join-Path $OutputDirectory "rtgum-stage1-payload.so"
foreach ($required in @($compiler, $readelf, $source)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$flags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fvisibility=hidden", "-Wl,-soname,rtgum-stage1-payload.so", "-Wl,--hash-style=sysv",
    "-Wl,-z,now", "-Wl,-z,relro"
)
if ($ForceRela) { $flags += '-Wl,--pack-dyn-relocs=none' }
& $compiler @flags $source "-o" $output
if ($LASTEXITCODE -ne 0) { throw "Stage-1 payload compilation failed with exit code $LASTEXITCODE" }

$header = (& $readelf --file-header $output) -join "`n"
$dynamic = (& $readelf --dynamic-table $output) -join "`n"
$symbols = (& $readelf --dyn-syms $output) -join "`n"
$relocations = (& $readelf --relocs $output) -join "`n"
if ($header -notmatch "Type:\s+DYN" -or $header -notmatch "Machine:\s+AArch64") {
    throw "Payload is not an AArch64 ET_DYN image"
}
if ($dynamic -notmatch "\(HASH\)" -or $symbols -notmatch "ghost_linker_probe" -or
    $symbols -notmatch "IFUNC\s+GLOBAL.*ghost_ifunc_probe") {
    throw "Payload is missing its SysV hash, normal export, or IFUNC export"
}
if ($relocations -notmatch "R_AARCH64_ABS64.*ghost_ifunc_probe" -or
    $relocations -notmatch "R_AARCH64_IRELATIVE") {
    throw "Payload does not exercise both symbol IFUNC and IRELATIVE repair"
}
Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
Write-Output $relocations
