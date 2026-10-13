param(
    [string]$NdkPath = '',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
if (-not $NdkPath) {
    $NdkPath = Join-Path $projectDirectory '.toolchains/android-ndk-r25c'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory 'out/kpm-stage1-pixel8-review'
}
$toolDirectory = Join-Path $NdkPath 'toolchains/llvm/prebuilt/windows-x86_64/bin'
$compiler = Join-Path $toolDirectory 'aarch64-linux-android30-clang++.cmd'
$readelf = Join-Path $toolDirectory 'llvm-readelf.exe'
$source = Join-Path $projectDirectory 'tests/pixel8-needed-ifunc.cpp'
$output = Join-Path $OutputDirectory 'rtgum-pixel8-needed-ifunc.so'
foreach ($path in @($compiler, $readelf, $source)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path" }
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$flags = @(
    '-std=c++17', '-O2', '-fPIC', '-shared', '-nostdlib', '-fno-exceptions',
    '-fno-rtti', '-fno-builtin', '-fvisibility=hidden',
    '-Wl,-soname,rtgum-pixel8-needed-ifunc.so', '-Wl,--hash-style=gnu',
    '-Wl,-z,now', '-Wl,--no-as-needed'
)
& $compiler @flags $source '-lc' '-o' $output
if ($LASTEXITCODE -ne 0) { throw 'NEEDED/IFUNC payload compilation failed' }
$header = (& $readelf --file-header $output) -join "`n"
$dynamic = (& $readelf --dynamic-table $output) -join "`n"
$symbols = (& $readelf --wide --dyn-syms $output) -join "`n"
$relocations = (& $readelf --wide --relocs $output) -join "`n"
if ($header -notmatch 'Type:\s+DYN' -or $header -notmatch 'Machine:\s+AArch64') {
    throw 'Payload is not AArch64 ET_DYN'
}
if ($dynamic -notmatch '\(NEEDED\).*libc\.so' -or $dynamic -notmatch '\(GNU_HASH\)') {
    throw 'Payload lacks libc DT_NEEDED or GNU hash'
}
if ($symbols -notmatch 'UND.*strlen' -or
    $symbols -notmatch 'ghost_needed_ifunc_probe') {
    throw 'Payload lacks import or entry export'
}
if ($relocations -notmatch 'R_AARCH64_IRELATIVE' -or
    $relocations -notmatch 'R_AARCH64_JUMP_SLOT.*strlen') {
    throw 'Payload lacks IRELATIVE or imported strlen relocation'
}
Get-Item -LiteralPath $output | Select-Object FullName,Length
Write-Output 'pixel8-needed-ifunc-build PASS'
