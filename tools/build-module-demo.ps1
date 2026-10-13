param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory '.toolchains\android-ndk-r25c'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory 'out\module-demo'
}
$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw "Android compiler not found: $compiler"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$module = Join-Path $OutputDirectory 'rtgum-sample.ghm'
$hostProgram = Join-Path $OutputDirectory 'rtgum-module-host'
$include = "-I$(Join-Path $projectDirectory 'include')"

& $compiler -std=c++17 -O2 -fPIC -shared -nostdlib '-Wl,--no-undefined' `
    '-Wl,-soname,rtgum-sample.ghm' $include `
    (Join-Path $projectDirectory 'examples\rtgum_sample_module.cpp') -o $module
if ($LASTEXITCODE -ne 0) { throw "Sample module build failed: $LASTEXITCODE" }

& $compiler -std=c++17 -O2 -fPIE -pie -static-libstdc++ $include `
    (Join-Path $projectDirectory 'src\loader\system_library.cpp') `
    (Join-Path $projectDirectory 'src\loader\module_runtime.cpp') `
    (Join-Path $projectDirectory 'examples\rtgum_module_host.cpp') `
    -ldl -o $hostProgram
if ($LASTEXITCODE -ne 0) { throw "Module host build failed: $LASTEXITCODE" }
Get-Item -LiteralPath $module, $hostProgram | Select-Object FullName, Length
