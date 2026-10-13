param(
    [string]$NdkPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage0"
}

$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$kpm = Join-Path $OutputDirectory "rtgum-stage0.kpm"
$client = Join-Path $OutputDirectory "rtgum-stage0-ctl"

foreach ($required in @($readelf, $kpm, $client)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required artifact not found: $required"
    }
}

$header = & $readelf "--file-header" $kpm
$sections = & $readelf "--sections" $kpm
$clientHeader = & $readelf "--file-header" $client
$headerText = $header -join "`n"
$sectionsText = $sections -join "`n"
$clientHeaderText = $clientHeader -join "`n"

if ($headerText -notmatch "Type:\s+REL") { throw "KPM is not an ELF relocatable object" }
if ($headerText -notmatch "Machine:\s+AArch64") { throw "KPM is not AArch64" }
foreach ($section in @(".kpm.info", ".kpm.init", ".kpm.ctl0", ".kpm.exit")) {
    if ($sectionsText -notmatch [regex]::Escape($section)) { throw "KPM section missing: $section" }
}
if ($clientHeaderText -notmatch "Type:\s+DYN" -or $clientHeaderText -notmatch "Machine:\s+AArch64") {
    throw "Stage-0 client is not an AArch64 PIE executable"
}

Get-FileHash -Algorithm SHA256 -LiteralPath $kpm, $client | Format-Table Path, Hash -AutoSize
Write-Output "stage0-artifacts PASS"
