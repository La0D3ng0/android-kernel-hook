param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$artHookDirectory = Join-Path $projectDirectory "art-hook"
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$include = Join-Path $artHookDirectory "include"
$src = Join-Path $artHookDirectory "src"
$mapFile = Join-Path $artHookDirectory "art-mako-ghost.map.txt"
$output = Join-Path $OutputDirectory "libmako-ghost.so"
foreach ($required in @($compiler, $readelf, $include, $src, $mapFile)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# Mako ghost engine: a standalone SHARED library for the KPM's remote linker.
# Static libc++ keeps DT_NEEDED to libc/libm/libdl, all already loaded in the
# app process, so the in-kernel resolver can repair every import. The jump
# pool is allocated at runtime from ghostMalloc(RWX) - no maps-visible code.
#
# -fno-builtin is retained for the freestanding/remote-linked image policy and
# local byte primitives. It is not a workaround for logging: the previously
# missing diagnostics were in an unreachable block and were correctly removed.
$flags = @(
    "-std=c++17", "-O2", "-fno-builtin", "-fPIC", "-shared", "-static-libstdc++",
    "-fno-stack-protector", "-fvisibility=hidden",
    "-ffunction-sections", "-fdata-sections",
    "-I$include", "-I$src",
    "-Wl,--gc-sections",
    "-Wl,-Bsymbolic-functions",
    "-Wl,--version-script=$mapFile",
    "-Wl,-soname,libmako-ghost.so", "-Wl,--hash-style=gnu",
    "-Wl,-z,now", "-Wl,--no-as-needed",
    "-lc", "-lm", "-ldl"
)
$sources = @(
    (Join-Path $src "mako_ghost.cpp"),
    (Join-Path $src "ghost_jump_pool.cpp"),
    (Join-Path $src "arm64_trampoline.cpp"),
    (Join-Path $src "status.cpp"),
    (Join-Path $src "art_method.cpp"),
    (Join-Path $src "code_allocator.cpp")
)
foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source)) { throw "Required source not found: $source" }
}

& $compiler @flags @sources "-o" $output
if ($LASTEXITCODE -ne 0) { throw "mako-ghost compilation failed with exit code $LASTEXITCODE" }

$header = (& $readelf --file-header $output) -join "`n"
$dynamic = (& $readelf --dynamic-table $output) -join "`n"
$symbols = (& $readelf --wide --dyn-syms $output) -join "`n"
if ($header -notmatch "Type:\s+DYN" -or $header -notmatch "Machine:\s+AArch64") {
    throw "mako-ghost is not an AArch64 ET_DYN image"
}
if ($dynamic -notmatch "\(GNU_HASH\)") { throw "mako-ghost is missing the GNU hash" }
foreach ($symbol in @("rtgum_mako_entry", "ghostModuleUnload")) {
    if ($symbols -notmatch [regex]::Escape($symbol)) {
        throw "mako-ghost is missing required export $symbol"
    }
}
if ($dynamic -notmatch "\(NEEDED\).*libc\.so") { throw "mako-ghost does not declare DT_NEEDED libc.so" }
if ($dynamic -match "libc\+\+_shared") { throw "mako-ghost unexpectedly needs shared libc++" }

Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
Write-Output 'mako-ghost PASS'
