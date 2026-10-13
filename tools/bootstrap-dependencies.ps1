param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is required. Install Git 2.35 or newer and run this script again.'
}

function Invoke-Git {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    & git -c core.longpaths=true @Arguments
    $exitCode = $LASTEXITCODE
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $exitCode"
    }
    return $exitCode
}

function Remove-DependencyDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $root = [IO.Path]::GetFullPath($projectDirectory).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if (-not $target.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
                               [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a dependency outside the project: $target"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

function Test-GitCommand {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & git -c core.longpaths=true @Arguments *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-Dependency {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Commit,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Patch = '',
        [string[]]$Submodules = @()
    )

    $destinationPath = Join-Path $projectDirectory $Destination
    if ($Force) {
        Remove-DependencyDirectory -Path $destinationPath
    }

    if (-not (Test-Path -LiteralPath (Join-Path $destinationPath '.git'))) {
        if (Test-Path -LiteralPath $destinationPath) {
            throw "$Name exists but is not a Git checkout: $destinationPath. Use -Force to replace it."
        }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destinationPath) |
            Out-Null
        Invoke-Git -Arguments @('clone', '--filter=blob:none', $Url,
                                $destinationPath) | Out-Null
    }

    $head = (& git -C $destinationPath rev-parse HEAD 2>$null | Out-String).Trim()
    if ($head -ne $Commit) {
        $dirty = (& git -C $destinationPath status --porcelain | Out-String).Trim()
        if ($dirty) {
            throw "$Name has local changes and is not at the pinned revision. Move the changes or use -Force."
        }
        Invoke-Git -Arguments @('-C', $destinationPath, 'fetch', '--depth=1',
                                'origin', $Commit) | Out-Null
        Invoke-Git -Arguments @('-C', $destinationPath, 'checkout', '--detach',
                                $Commit) | Out-Null
    }

    foreach ($submodule in $Submodules) {
        Invoke-Git -Arguments @('-C', $destinationPath, 'submodule', 'update',
                                '--init', '--recursive', '--', $submodule) | Out-Null
    }

    if ($Patch) {
        $patchPath = Join-Path $projectDirectory $Patch
        if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
            throw "$Name patch is missing: $patchPath"
        }
        if (Test-GitCommand -Arguments @('-C', $destinationPath, 'apply',
                                         '--reverse', '--check', $patchPath)) {
            Write-Host "${Name}: pinned revision and project patch already present"
        } elseif (Test-GitCommand -Arguments @('-C', $destinationPath, 'apply',
                                                '--check', $patchPath)) {
            Invoke-Git -Arguments @('-C', $destinationPath, 'apply', $patchPath) |
                Out-Null
            Write-Host "${Name}: applied project patch"
        } else {
            throw "$Name does not match its pinned patch. Use -Force to recreate the checkout."
        }
    } else {
        Write-Host "${Name}: ready"
    }
}

Ensure-Dependency `
    -Name 'LSPlant' `
    -Url 'https://github.com/LSPosed/LSPlant.git' `
    -Commit 'bd67b61077e4889de02af81a66913b55b7b01a8b' `
    -Destination 'art-hook/third_party/lsplant' `
    -Patch 'patches/vendor/lsplant-rtgum.patch' `
    -Submodules @('lsplant/src/main/jni/external/dex_builder')

Ensure-Dependency `
    -Name 'frida-java-bridge' `
    -Url 'https://github.com/frida/frida-java-bridge.git' `
    -Commit 'b38a5b647d3e6b72aa19bcf8eb5e41c550a0e622' `
    -Destination 'frida-java-bridge' `
    -Patch 'patches/vendor/frida-java-bridge-rtgum.patch'

Ensure-Dependency `
    -Name 'KernelPatch 0.12.2 base' `
    -Url 'https://github.com/bmax121/KernelPatch.git' `
    -Commit '8eebc2e00235e64e3cd56b4918287415188cc752' `
    -Destination 'third_party/KernelPatch-0.12.2'

Ensure-Dependency `
    -Name 'KernelPatch 0.13.9 base' `
    -Url 'https://github.com/bmax121/KernelPatch.git' `
    -Commit 'b51197aaba8f2272dd8a3e30c85698a29aa928c9' `
    -Destination 'third_party/KernelPatch-0.13.9' `
    -Patch 'patches/kernelpatch-0.13.9-pixel8-stage1.patch'

Write-Host 'android-kernel-hook source dependencies are ready.'
Write-Host 'Run tools/fetch-frida-gum-devkit.ps1 before building the Android Gum backend.'
