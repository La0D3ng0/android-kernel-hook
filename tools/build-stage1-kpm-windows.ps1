param(
    [string]$NdkPath = "",
    [string]$KernelPatchDirectory = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r29"
}
if ([string]::IsNullOrWhiteSpace($KernelPatchDirectory)) {
    $KernelPatchDirectory = Join-Path $projectDirectory "third_party\KernelPatch-0.13.9"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$toolDirectory = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin"
$compiler = Join-Path $toolDirectory "clang++.exe"
$linker = Join-Path $toolDirectory "ld.lld.exe"
$strip = Join-Path $toolDirectory "llvm-strip.exe"
$readelf = Join-Path $toolDirectory "llvm-readelf.exe"
$sourceDirectory = Join-Path $projectDirectory "kpm\stage1"
$source = Join-Path $sourceDirectory "stage1.cpp"
$linkerScript = Join-Path $sourceDirectory "stage1.lds"
$object = Join-Path $OutputDirectory "stage1.o"
$output = Join-Path $OutputDirectory "rtgum-stage1.kpm"

$includeDirectories = @(
    (Join-Path $KernelPatchDirectory "kernel"),
    (Join-Path $KernelPatchDirectory "kernel\include"),
    (Join-Path $KernelPatchDirectory "kernel\patch\include"),
    (Join-Path $KernelPatchDirectory "kernel\linux\include"),
    (Join-Path $KernelPatchDirectory "kernel\linux\arch\arm64\include"),
    (Join-Path $KernelPatchDirectory "kernel\linux\tools\arch\arm64\include")
)
foreach ($required in @($compiler, $linker, $strip, $readelf, $source,
                         $linkerScript) + $includeDirectories) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required path not found: $required"
    }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# KernelPatch's KPM loader supports the scalar AArch64 relocation family used
# below. LLVM otherwise vectorizes fixed-size copies at -O2 and emits
# R_AARCH64_LDST128_ABS_LO12_NC, which KernelPatch 0.13.9 rejects with -95.
$compileFlags = @(
    "--target=aarch64-none-elf", "-std=gnu++17", "-O2",
    "-Wall", "-Wextra", "-Werror",
    "-Wno-extern-c-compat", "-Wno-unused-private-field",
    "-Wno-unused-const-variable",
    "-fno-builtin", "-mno-outline-atomics",
    "-fno-exceptions", "-fno-rtti", "-fno-threadsafe-statics",
    "-fno-use-cxa-atexit", "-fno-pic",
    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-fno-stack-protector", "-fno-common", "-nostdinc++",
    "-ffunction-sections", "-fdata-sections",
    "-fno-vectorize", "-fno-slp-vectorize"
)
foreach ($directory in $includeDirectories) { $compileFlags += "-I$directory" }

& $compiler @compileFlags "-c" $source "-o" $object
if ($LASTEXITCODE -ne 0) {
    throw "Stage-1 KPM compilation failed with exit code $LASTEXITCODE"
}
& $linker "-r" "-T" $linkerScript "-o" $output $object
if ($LASTEXITCODE -ne 0) {
    throw "Stage-1 KPM link failed with exit code $LASTEXITCODE"
}
& $strip "--strip-debug" $output
if ($LASTEXITCODE -ne 0) {
    throw "Stage-1 KPM strip failed with exit code $LASTEXITCODE"
}

$header = (& $readelf --file-header $output) -join "`n"
$sections = (& $readelf --sections $output) -join "`n"
$symbols = (& $readelf --wide --symbols $output) -join "`n"
$relocations = (& $readelf --wide --relocs $output) -join "`n"
if ($header -notmatch "Type:\s+REL" -or $header -notmatch "Machine:\s+AArch64") {
    throw "KPM is not an AArch64 ET_REL image"
}
foreach ($section in @(".kpm.info", ".kpm.init", ".kpm.ctl0", ".kpm.exit")) {
    if ($sections -notmatch [regex]::Escape($section)) {
        throw "KPM section missing: $section"
    }
}

$supportedRelocations = @(
    "R_AARCH64_ABS64",
    "R_AARCH64_ADD_ABS_LO12_NC",
    "R_AARCH64_ADR_PREL_PG_HI21",
    "R_AARCH64_CALL26",
    "R_AARCH64_JUMP26",
    "R_AARCH64_LDST8_ABS_LO12_NC",
    "R_AARCH64_LDST16_ABS_LO12_NC",
    "R_AARCH64_LDST32_ABS_LO12_NC",
    "R_AARCH64_LDST64_ABS_LO12_NC"
)
$foundRelocations = @([regex]::Matches($relocations, "R_AARCH64_[A-Z0-9_]+") |
    ForEach-Object { $_.Value } | Sort-Object -Unique)
$unsupported = @($foundRelocations | Where-Object { $_ -notin $supportedRelocations })
if ($unsupported.Count -ne 0) {
    throw "KPM contains loader-unsupported relocations: $($unsupported -join ', ')"
}
if ($relocations -match "R_AARCH64_LDST128_ABS_LO12_NC") {
    throw "KPM contains LDST128 relocations; vectorization must remain disabled"
}

$allowedUndefined = @(
    "_task_pt_reg", "compat_copy_to_user", "compat_strncpy_from_user",
    "fp_unwrap_syscalln", "fp_wrap_syscalln", "hook_wrap",
    "hook_unwrap_remove", "kf_snprintf", "mm_struct_offset",
    "kallsyms_lookup_name", "kver", "printk", "raw_syscall0",
    "task_struct_offset", "thread_size", "linear_voffset",
    "sp_el0_is_current", "sp_el0_is_thread_info",
    "task_in_thread_info_offset", "thread_info_in_task"
)
$undefined = foreach ($line in ($symbols -split "`n")) {
    if ($line -match "\sUND\s+([^\s]+)\s*$") { $Matches[1] }
}
$unexpectedUndefined = @($undefined | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and $_ -notin $allowedUndefined
} | Sort-Object -Unique)
if ($unexpectedUndefined.Count -ne 0) {
    throw "Unexpected KPM undefined symbols: $($unexpectedUndefined -join ', ')"
}

$item = Get-Item -LiteralPath $output
$sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "rtgum-stage1.kpm size=$($item.Length) sha256=$sha256"
Write-Output "relocations=$($foundRelocations -join ',')"
Write-Output "stage1-kpm-windows PASS"
