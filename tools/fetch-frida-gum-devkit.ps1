param(
    [string]$OutputDirectory = "",
    [string]$ArchivePath = ""
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
$version = '17.22.2'
$archiveName = "frida-gum-devkit-$version-android-arm64.tar.xz"
$expectedSha256 = 'ca274f586672a6bdda0a08278e0217a0ffa0c4611f819d1b00a37e5e53583a80'
$assetUrl = "https://github.com/frida/frida/releases/download/$version/$archiveName"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory `
        ".toolchains\frida-gum-devkit-$version-android-arm64"
}
if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
    $ArchivePath = Join-Path $projectDirectory ".toolchains\downloads\$archiveName"
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ArchivePath) | Out-Null
if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
    Invoke-WebRequest -Uri $assetUrl -OutFile $ArchivePath
}
$actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "Frida Gum devkit SHA-256 mismatch: $actualSha256"
}

$entries = @(& tar -tf $ArchivePath)
if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0) {
    throw 'Cannot read Frida Gum devkit archive'
}
if ($entries | Where-Object { $_ -match '(^/|^[A-Za-z]:|(^|/)\.\.(/|$))' }) {
    throw 'Frida Gum devkit archive contains an unsafe path'
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
& tar -xf $ArchivePath -C $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw 'Frida Gum devkit extraction failed' }
$header = Join-Path $OutputDirectory 'frida-gum.h'
$library = Join-Path $OutputDirectory 'libfrida-gum.a'
foreach ($required in @($header, $library)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Frida Gum devkit is incomplete: $required"
    }
}
Get-Item -LiteralPath $header, $library | Select-Object FullName, Length
Write-Output "Verified SHA-256 $actualSha256"
