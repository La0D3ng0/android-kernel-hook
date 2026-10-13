param(
    [string]$NdkPath = "",
    [int]$Api = 35,
    [string]$KernelPatchVersion = "0.13.9",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r29"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
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

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
$compiler32 = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi$Api-clang++.cmd"
$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$source = Join-Path $projectDirectory "tools\rtgum-stage1-ctl.cpp"
$personalitySource = Join-Path $projectDirectory "tests\stage2-dbi-personality.cpp"
$output = Join-Path $OutputDirectory "rtgum-stage1-ctl"
$compat32Source = Join-Path $projectDirectory "tests\rtgum-antidbg-compat32.cpp"
$compat32Output = Join-Path $OutputDirectory "rtgum-antidbg-compat32"
$dynamicPhdrSource = Join-Path $projectDirectory "tests\stage2-dbi-dynamic-phdr.cpp"
$dynamicPhdrOutput = Join-Path $OutputDirectory "librtgum-dbi-dynamic-phdr.so"
$dynamicReplacementSource = Join-Path $projectDirectory "tests\stage2-dbi-dynamic-phdr-replacement.cpp"
$dynamicReplacementOutput = Join-Path $OutputDirectory "librtgum-dbi-dynamic-phdr-replacement.so"

foreach ($required in @($compiler, $compiler32, $readelf, $source, $personalitySource, $compat32Source, $dynamicPhdrSource, $dynamicReplacementSource, (Join-Path $projectDirectory "include\rtgum\kpm_supercall.h"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$flags = @(
    "-std=c++17", "-O2", "-g", "-fPIE", "-pie", "-static-libstdc++",
    "-Wall", "-Wextra", "-Wpedantic",
    "-DANDROID", "-DRTGUM_KP_VERSION_MAJOR=$kpMajor", "-DRTGUM_KP_VERSION_MINOR=$kpMinor",
    "-DRTGUM_KP_VERSION_PATCH=$kpPatch", "-I$(Join-Path $projectDirectory 'include')"
)

& $compiler @flags $source $personalitySource "-ldl" "-o" $output
if ($LASTEXITCODE -ne 0) { throw "Stage-1 client compilation failed with exit code $LASTEXITCODE" }
& $compiler32 "-std=c++17" "-O2" "-g" "-fPIE" "-pie" "-static-libstdc++" "-marm" `
    "-Wall" "-Wextra" "-Wpedantic" $compat32Source "-o" $compat32Output
if ($LASTEXITCODE -ne 0) { throw "AArch32 anti-debug probe compilation failed with exit code $LASTEXITCODE" }
& $compiler "-std=c++17" "-O2" "-fPIC" "-shared" "-static-libstdc++" $dynamicPhdrSource "-ldl" "-o" $dynamicPhdrOutput
if ($LASTEXITCODE -ne 0) { throw "Dynamic PLT fixture compilation failed with exit code $LASTEXITCODE" }
& $compiler "-std=c++17" "-O2" "-fPIC" "-shared" "-static-libstdc++" "-mbranch-protection=bti" "-Wl,-z,force-bti" $dynamicReplacementSource "-ldl" "-o" $dynamicReplacementOutput
if ($LASTEXITCODE -ne 0) { throw "Dynamic PLT replacement fixture compilation failed with exit code $LASTEXITCODE" }

function Get-ElfSectionSpan {
    param([string]$Path, [string]$Name)
    $escaped = [regex]::Escape($Name)
    $pattern = "^\s*\[\s*\d+\]\s+$escaped\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)\s"
    foreach ($line in (& $readelf -S $Path)) {
        if ($line -match $pattern) {
            return @{ Address = [Convert]::ToUInt64($Matches[1], 16); Size = [Convert]::ToUInt64($Matches[2], 16) }
        }
    }
    throw "Could not find ELF section $Name in $Path"
}
$originalPlt = Get-ElfSectionSpan $dynamicPhdrOutput '.plt'
$replacementPlt = Get-ElfSectionSpan $dynamicReplacementOutput '.plt'
$replacementText = Get-ElfSectionSpan $dynamicReplacementOutput '.text'
if ($originalPlt.Address -ne $replacementPlt.Address -or
    $replacementText.Address + $replacementText.Size -gt $originalPlt.Address) {
    throw "Dynamic PLT reuse fixture lost its overlap or now masks the replacement function"
}
Get-Item -LiteralPath $output | Select-Object FullName, Length, LastWriteTime
Get-Item -LiteralPath $compat32Output | Select-Object FullName, Length, LastWriteTime
Get-Item -LiteralPath $dynamicPhdrOutput | Select-Object FullName, Length, LastWriteTime
Get-Item -LiteralPath $dynamicReplacementOutput | Select-Object FullName, Length, LastWriteTime
