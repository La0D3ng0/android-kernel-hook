param(
    [string]$NdkPath = "",
    [string]$OutputDirectory = "",
    [string]$RealSoPath = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$assembler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$objcopy = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objcopy.exe"
$trampolineAssembly = Join-Path $projectDirectory 'tools\trampoline-verify.s'
$kpmSource = Join-Path $projectDirectory 'kpm\stage1\stage1.cpp'
$kpm = Join-Path $OutputDirectory "rtgum-stage1.kpm"
$client = Join-Path $OutputDirectory "rtgum-stage1-ctl"
$payload = Join-Path $OutputDirectory "rtgum-stage1-payload.so"
$daemon = Join-Path $OutputDirectory "rtgum-stage2-daemon.so"
foreach ($required in @($readelf, $assembler, $objcopy, $trampolineAssembly,
                        $kpmSource, $kpm, $client, $payload, $daemon)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required artifact not found: $required" }
}

function Get-ReadElfText([string[]]$Arguments) {
    $text = (& $readelf @Arguments) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "llvm-readelf failed: $($Arguments -join ' ')" }
    return $text
}

function ConvertTo-HexString([byte[]]$Bytes) {
    # Convert.ToHexString is unavailable in Windows PowerShell 5.1/.NET
    # Framework, which is still the shell used by the device scripts.
    return [System.BitConverter]::ToString($Bytes).Replace('-', '')
}

# The KPM copies these instruction words into a target process. A mismatch
# between the maintained assembly and C++ array would bypass the compiler.
$temporaryObject = Join-Path ([System.IO.Path]::GetTempPath()) ("rtgum-trampoline-$([guid]::NewGuid().ToString('N')).o")
$temporaryBinary = "$temporaryObject.bin"
try {
    & $assembler --target=aarch64-none-elf -c $trampolineAssembly -o $temporaryObject
    if ($LASTEXITCODE -ne 0) { throw 'ARM64 trampoline assembly failed' }
    & $objcopy -O binary --only-section=.text $temporaryObject $temporaryBinary
    if ($LASTEXITCODE -ne 0) { throw 'ARM64 trampoline extraction failed' }
    $bytes = [System.IO.File]::ReadAllBytes($temporaryBinary)
    $sourceText = Get-Content -LiteralPath $kpmSource -Raw
    $array = [regex]::Match($sourceText,
        'constexpr unsigned int kTrampolineInstructions\[\] = \{(?<body>[\s\S]*?)\};')
    if (-not $array.Success) { throw 'KPM trampoline instruction array not found' }
    $words = [regex]::Matches($array.Groups['body'].Value, '0x([0-9a-fA-F]{8})U,')
    if (-not [System.BitConverter]::IsLittleEndian -or $words.Count * 4 -ne $bytes.Length) {
        throw 'ARM64 trampoline instruction count or host endianness mismatch'
    }
    for ($index = 0; $index -lt $words.Count; $index++) {
        $word = [Convert]::ToUInt32($words[$index].Groups[1].Value, 16)
        $encoded = [System.BitConverter]::GetBytes($word)
        for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex++) {
            if ($encoded[$byteIndex] -ne $bytes[$index * 4 + $byteIndex]) {
                throw "ARM64 trampoline mismatch at instruction $index"
            }
        }
    }
    $kpmHex = ConvertTo-HexString ([System.IO.File]::ReadAllBytes($kpm))
    $trampolineHex = ConvertTo-HexString $bytes
    if ($kpmHex.IndexOf($trampolineHex, [StringComparison]::Ordinal) -lt 0) {
        throw 'Assembled ARM64 trampoline bytes are absent from the KPM artifact'
    }
    Write-Output "arm64-trampoline instructions=$($words.Count) bytes=$($bytes.Length) exact=1"
} finally {
    Remove-Item -LiteralPath $temporaryObject, $temporaryBinary -ErrorAction SilentlyContinue
}

$kpmHeader = Get-ReadElfText @('--file-header', $kpm)
$kpmSections = Get-ReadElfText @('--sections', $kpm)
$kpmSymbols = Get-ReadElfText @('--symbols', $kpm)
if ($kpmHeader -notmatch 'Type:\s+REL' -or $kpmHeader -notmatch 'Machine:\s+AArch64') {
    throw 'KPM must be an AArch64 ET_REL image'
}
foreach ($section in @('.kpm.info', '.kpm.init', '.kpm.ctl0', '.kpm.exit')) {
    if ($kpmSections -notmatch [regex]::Escape($section)) { throw "KPM section missing: $section" }
}

$allowedUndefined = @(
    '_task_pt_reg', 'compat_copy_to_user', 'compat_strncpy_from_user',
    'fp_unwrap_syscalln', 'fp_wrap_syscalln', 'hook_wrap', 'hook_unwrap_remove',
    'kf_snprintf', 'mm_struct_offset', 'kallsyms_lookup_name', 'kver', 'printk',
    'raw_syscall0', 'task_struct_offset', 'thread_size',
    'linear_voffset', 'sp_el0_is_current', 'sp_el0_is_thread_info',
    'task_in_thread_info_offset', 'thread_info_in_task'
)
$undefined = foreach ($line in ($kpmSymbols -split "`n")) {
    if ($line -match '\sUND\s+([^\s]+)\s*$') { $Matches[1] }
}
$unexpected = @($undefined | Where-Object { $_ -notin $allowedUndefined } | Sort-Object -Unique)
if ($unexpected.Count -ne 0) {
    throw "Unexpected KPM undefined symbols: $($unexpected -join ', ')"
}

$clientHeader = Get-ReadElfText @('--file-header', $client)
if ($clientHeader -notmatch 'Machine:\s+AArch64') { throw 'Control client is not AArch64' }

$payloadHeader = Get-ReadElfText @('--file-header', $payload)
$payloadDynamic = Get-ReadElfText @('--dynamic-table', $payload)
$payloadSymbols = Get-ReadElfText @('--dyn-syms', $payload)
$payloadRelocations = Get-ReadElfText @('--relocs', $payload)
if ($payloadHeader -notmatch 'Type:\s+DYN' -or $payloadHeader -notmatch 'Machine:\s+AArch64') {
    throw 'Linker payload must be an AArch64 ET_DYN image'
}
if ($payloadDynamic -notmatch '\(HASH\)' -or $payloadSymbols -notmatch 'ghost_linker_probe' -or
    $payloadSymbols -notmatch 'IFUNC\s+GLOBAL.*ghost_ifunc_probe') {
    throw 'Linker payload is missing its SysV hash, normal export, or IFUNC export'
}
if ($payloadRelocations -notmatch 'R_AARCH64_RELATIVE' -or
    $payloadRelocations -notmatch 'R_AARCH64_ABS64.*ghost_ifunc_probe' -or
    $payloadRelocations -notmatch 'R_AARCH64_IRELATIVE') {
    throw 'Linker payload does not exercise RELATIVE, symbol IFUNC, and IRELATIVE'
}

$daemonHeader = Get-ReadElfText @('--file-header', $daemon)
$daemonDynamic = Get-ReadElfText @('--dynamic-table', $daemon)
$daemonSymbols = Get-ReadElfText @('--wide', '--dyn-syms', $daemon)
$daemonRelocations = Get-ReadElfText @('--wide', '--relocs', $daemon)
if ($daemonHeader -notmatch 'Type:\s+DYN' -or $daemonHeader -notmatch 'Machine:\s+AArch64' -or
    $daemonDynamic -notmatch '\(GNU_HASH\)' -or
    $daemonSymbols -notmatch 'rtgum_stage2_daemon_entry' -or
    $daemonRelocations -notmatch 'R_AARCH64_RELATIVE') {
    throw 'Stage-2 Daemon is missing AArch64 ET_DYN, GNU hash, entry export, or RELATIVE relocation'
}

if (-not [string]::IsNullOrWhiteSpace($RealSoPath)) {
    if (-not (Test-Path -LiteralPath $RealSoPath -PathType Leaf)) {
        throw "Real SO not found: $RealSoPath"
    }
    $realHeader = Get-ReadElfText @('--file-header', $RealSoPath)
    $realDynamic = Get-ReadElfText @('--dynamic-table', $RealSoPath)
    $realSymbols = Get-ReadElfText @('--wide', '--dyn-syms', $RealSoPath)
    $realRelocations = Get-ReadElfText @('--wide', '--relocs', $RealSoPath)
    $neededCount = [regex]::Matches($realDynamic, '\(NEEDED\)').Count
    if ($realHeader -notmatch 'Type:\s+DYN' -or $realHeader -notmatch 'Machine:\s+AArch64' -or
        $realDynamic -notmatch '\(GNU_HASH\)' -or $neededCount -eq 0 -or
        $realSymbols -notmatch 'Unity_AdaptivePerformance_ThermalHeadroom_GetPluginCallback' -or
        $realRelocations -notmatch 'R_AARCH64_JUMP_SLOT') {
        throw 'Real SO is missing AArch64 ET_DYN, GNU hash, the validation export, or JUMP_SLOT imports'
    }
    $realItem = Get-Item -LiteralPath $RealSoPath
    $realHash = (Get-FileHash -LiteralPath $RealSoPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output "$($realItem.Name) size=$($realItem.Length) sha256=$realHash gnu_hash=1 needed=$neededCount"
}

foreach ($artifact in @($kpm, $client, $payload, $daemon)) {
    $item = Get-Item -LiteralPath $artifact
    $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output "$($item.Name) size=$($item.Length) sha256=$hash"
}
Write-Output 'stage1-artifacts PASS'
