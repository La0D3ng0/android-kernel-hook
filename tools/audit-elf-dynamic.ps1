param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,
    [string]$NdkPath = ""
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory '.toolchains\android-ndk-r29'
}
$readelf = Join-Path $NdkPath 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
if (-not (Test-Path -LiteralPath $readelf -PathType Leaf)) {
    throw "llvm-readelf is absent: $readelf"
}

foreach ($candidate in $Paths) {
    $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Expected an ELF file: $candidate" }

    $header = (& $readelf --file-header $item.FullName) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Cannot read ELF header: $($item.FullName)" }
    $dynamic = (& $readelf --wide --dynamic-table $item.FullName) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "Cannot read ELF dynamic table: $($item.FullName)" }

    $machine = [regex]::Match($header, '(?m)^\s*Machine:\s*(.+)$')
    $type = [regex]::Match($header, '(?m)^\s*Type:\s*(\S+)')
    $tagMatches = [regex]::Matches($dynamic, '\(([A-Z][A-Z0-9_]*)\)')
    $tags = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($match in $tagMatches) { [void]$tags.Add($match.Groups[1].Value) }
    $neededMatches = [regex]::Matches(
        $dynamic, '(?m)\(NEEDED\)[^\r\n]*\[([^\]]+)\]')
    $needed = foreach ($match in $neededMatches) { $match.Groups[1].Value }

    $hasRelr = $tags.Contains('RELR') -or $tags.Contains('ANDROID_RELR')
    $hasAndroidPacked = $tags.Contains('ANDROID_REL') -or
        $tags.Contains('ANDROID_RELA')
    $hasRela = $tags.Contains('RELA') -or
        $dynamic -match '(?m)\(PLTREL\)\s+RELA\b'
    $hasVersions = $tags.Contains('VERSYM') -or
        $tags.Contains('VERNEED') -or $tags.Contains('VERDEF')

    [pscustomobject]@{
        File = $item.FullName
        Size = $item.Length
        Sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        ElfType = if ($type.Success) { $type.Groups[1].Value } else { 'unknown' }
        Machine = if ($machine.Success) { $machine.Groups[1].Value.Trim() } else { 'unknown' }
        Needed = @($needed)
        HasRela = $hasRela
        HasRelr = $hasRelr
        HasAndroidPacked = $hasAndroidPacked
        HasGnuVersions = $hasVersions
        Note = 'ELF tags alone do not identify the process linker namespace or prove loadability.'
    }
}
