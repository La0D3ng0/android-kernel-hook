param(
    [string]$ManagerApk = "",
    [string]$KernelPatchDirectory = "",
    [string]$SdkPath = ""
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ManagerApk)) {
    $ManagerApk = Join-Path $projectDirectory 'out\manager-build\rtgum-manager-debug.apk'
}
if ([string]::IsNullOrWhiteSpace($KernelPatchDirectory)) {
    $KernelPatchDirectory = Join-Path $projectDirectory 'third_party\KernelPatch-0.13.9'
}
if ([string]::IsNullOrWhiteSpace($SdkPath)) {
    foreach ($candidate in @($env:ANDROID_HOME,
                              $env:ANDROID_SDK_ROOT,
                              (Join-Path $env:LOCALAPPDATA 'Android\Sdk'),
                              'E:\AndroidSDK')) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'build-tools'))) {
            $SdkPath = $candidate
            break
        }
    }
}

$ManagerApk = [IO.Path]::GetFullPath($ManagerApk)
$KernelPatchDirectory = [IO.Path]::GetFullPath($KernelPatchDirectory)
if (-not (Test-Path -LiteralPath $ManagerApk -PathType Leaf)) {
    throw "Manager APK was not found: $ManagerApk"
}
$userdSource = Join-Path $KernelPatchDirectory 'kernel\patch\android\userd.c'
if (-not (Test-Path -LiteralPath $userdSource -PathType Leaf)) {
    throw "KernelPatch manager trust source was not found: $userdSource"
}

$apksigner = $null
if ($SdkPath) {
    $buildToolsRoot = Join-Path $SdkPath 'build-tools'
    if (Test-Path -LiteralPath $buildToolsRoot -PathType Container) {
        $apksigner = Get-ChildItem -LiteralPath $buildToolsRoot -Directory |
            Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'apksigner.bat' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
}
if (-not $apksigner) {
    throw 'Android SDK apksigner was not found. Pass -SdkPath.'
}

$certificateOutput = (& $apksigner verify --print-certs $ManagerApk 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "APK signature verification failed: $certificateOutput"
}
$digestMatch = [regex]::Match(
    $certificateOutput,
    '(?im)^Signer #1 certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$')
if (-not $digestMatch.Success) {
    throw 'Could not read the signer SHA-256 digest from apksigner output.'
}
$digest = $digestMatch.Groups[1].Value.ToLowerInvariant()
$bytes = for ($i = 0; $i -lt $digest.Length; $i += 2) {
    '0x' + $digest.Substring($i, 2)
}
$rows = for ($row = 0; $row -lt 4; ++$row) {
    '            ' + (($bytes[($row * 8)..($row * 8 + 7)] -join ', ')) +
        $(if ($row -lt 3) { ',' } else { '' })
}

$source = [IO.File]::ReadAllText($userdSource)
$newline = if ($source.Contains("`r`n")) { "`r`n" } else { "`n" }
$entryLines = @(
    '    {'
    '        "dev.rtgum.manager",'
    '        {'
) + $rows + @(
    '        }'
    '    },'
)
$entry = $entryLines -join $newline

$existingPattern = '(?s)\s*\{\s*"dev\.rtgum\.manager"\s*,\s*\{\s*' +
    '(?:0x[0-9a-fA-F]{2}\s*,?\s*){32}\}\s*\}\s*,?'
$existingMatches = [regex]::Matches($source, $existingPattern)
if ($existingMatches.Count -gt 1) {
    throw 'KernelPatch source contains more than one dev.rtgum.manager trust entry.'
}
if ($existingMatches.Count -eq 1) {
    $source = [regex]::Replace(
        $source,
        $existingPattern,
        $newline + $entry,
        1)
} else {
    $sentinelPattern = '(?m)^(?<indent>\s*)\{\s*""\s*,\s*\{\s*0\s*\}\s*\}\s*$'
    $sentinels = [regex]::Matches($source, $sentinelPattern)
    if ($sentinels.Count -ne 1) {
        throw 'Could not identify the trusted_managers sentinel in KernelPatch userd.c.'
    }
    $source = [regex]::Replace(
        $source,
        $sentinelPattern,
        $entry + $newline + '${indent}{ "", { 0 } }',
        1)
}

[IO.File]::WriteAllText($userdSource, $source, [Text.UTF8Encoding]::new($false))
Write-Output "manager-trust package=dev.rtgum.manager sha256=$digest"
Write-Output "manager-trust-source $userdSource"
