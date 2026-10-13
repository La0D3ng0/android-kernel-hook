param(
    [Parameter(Mandatory = $true)][string]$SourceArchive,
    [Parameter(Mandatory = $true)][string]$OutputArchive,
    [Parameter(Mandatory = $true)][string]$NdkPath
)

$ErrorActionPreference = "Stop"
$llvmBin = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin"
$ar = Join-Path $llvmBin "llvm-ar.exe"
$objcopy = Join-Path $llvmBin "llvm-objcopy.exe"
foreach ($required in @($SourceArchive, $ar, $objcopy)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required W^X patch input not found: $required"
    }
}

$outputDirectory = Split-Path -Parent $OutputArchive
$workDirectory = Join-Path $outputDirectory "frida-gum-wx-patch"
New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null
$memberPath = Join-Path $workDirectory "gummemory.c.o"
if (Test-Path -LiteralPath $memberPath) {
    Remove-Item -LiteralPath $memberPath -Force
}

Push-Location $workDirectory
try {
    & $ar x $SourceArchive "gummemory.c.o"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract gummemory.c.o from the pinned Gum archive"
    }
} finally {
    Pop-Location
}
if (-not (Test-Path -LiteralPath $memberPath -PathType Leaf)) {
    throw "Pinned Gum archive has no gummemory.c.o"
}

function Update-SectionBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][byte[]]$Expected,
        [Parameter(Mandatory = $true)][byte[]]$Replacement,
        [Parameter(Mandatory = $true)][string]$Tag
    )
    if ($Expected.Length -ne $Replacement.Length) {
        throw "Internal patch length mismatch for $Tag"
    }
    $dumpPath = Join-Path $workDirectory "$Tag.bin"
    $nextObject = Join-Path $workDirectory "gummemory.next.o"
    if (Test-Path -LiteralPath $dumpPath) { Remove-Item -LiteralPath $dumpPath -Force }
    if (Test-Path -LiteralPath $nextObject) { Remove-Item -LiteralPath $nextObject -Force }
    & $objcopy "--dump-section=$Section=$dumpPath" $memberPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dumpPath -PathType Leaf)) {
        throw "Unable to read Gum section $Section"
    }
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($dumpPath)
    if ($Offset -lt 0 -or $Offset + $Expected.Length -gt $bytes.Length) {
        throw "Patch offset is outside Gum section $Section"
    }
    for ($index = 0; $index -lt $Expected.Length; ++$index) {
        if ($bytes[$Offset + $index] -ne $Expected[$index]) {
            throw ("Unexpected Gum bytes for {0} at +0x{1:x}: got 0x{2:x2}, expected 0x{3:x2}" -f `
                $Tag, ($Offset + $index), $bytes[$Offset + $index], $Expected[$index])
        }
        $bytes[$Offset + $index] = $Replacement[$index]
    }
    [System.IO.File]::WriteAllBytes($dumpPath, $bytes)
    & $objcopy "--update-section=$Section=$dumpPath" $memberPath $nextObject
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $nextObject -PathType Leaf)) {
        throw "Unable to update Gum section $Section"
    }
    Move-Item -LiteralPath $nextObject -Destination $memberPath -Force
}

# The pinned Android build constant-folds RWX support inside gummemory.c.o, so
# ld --wrap cannot reach these same-object paths. Keep the patch deliberately
# narrow and guarded by exact instruction bytes:
#   * public capability queries return NONE/false;
#   * patch_code temporarily uses RW and always restores RX.
Update-SectionBytes ".text.gum_query_is_rwx_supported" 0 `
    ([byte[]](0x20, 0x00, 0x80, 0x52)) ([byte[]](0x00, 0x00, 0x80, 0x52)) `
    "query-is-rwx"
Update-SectionBytes ".text.gum_query_rwx_support" 0 `
    ([byte[]](0x40, 0x00, 0x80, 0x52)) ([byte[]](0x00, 0x00, 0x80, 0x52)) `
    "query-rwx"
Update-SectionBytes ".text.gum_memory_patch_code_pages_via_mprotect" 0x64 `
    ([byte[]](0xe2, 0x00, 0x80, 0x52)) ([byte[]](0x62, 0x00, 0x80, 0x52)) `
    "patch-rw"
Update-SectionBytes ".text.gum_memory_patch_code_pages_via_mprotect" 0x12c `
    ([byte[]](0x02, 0x01, 0x16, 0x2a)) ([byte[]](0xe2, 0x03, 0x16, 0x2a)) `
    "restore-rx"

Copy-Item -LiteralPath $SourceArchive -Destination $OutputArchive -Force
Push-Location $workDirectory
try {
    & $ar r $OutputArchive "gummemory.c.o"
    if ($LASTEXITCODE -ne 0) { throw "Failed to replace patched Gum archive member" }
    & $ar s $OutputArchive
    if ($LASTEXITCODE -ne 0) { throw "Failed to rebuild patched Gum archive index" }
} finally {
    Pop-Location
}

$sourceHash = (Get-FileHash -LiteralPath $SourceArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$outputHash = (Get-FileHash -LiteralPath $OutputArchive -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "frida-gum-wx source=$sourceHash patched=$outputHash"
