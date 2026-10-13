param(
    [string]$NdkPath = "",
    [int]$Api = 35,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r29"
    if (-not (Test-Path -LiteralPath $NdkPath)) {
        $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
        $Api = 30
    }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$clang = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.cmd"
$clangxx = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
if (-not (Test-Path -LiteralPath $clangxx)) {
    $clang = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.exe"
    $clangxx = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.exe"
}
$luaSrc = Join-Path $projectDirectory "third_party\lua-5.4.7\src"
$helper = Join-Path $projectDirectory "tests\lua-helper.cpp"
$map = Join-Path $projectDirectory "tests\lua-helper.map.txt"
$include = Join-Path $projectDirectory "include"
$luaTest = Join-Path $projectDirectory "tests\jnicode-lua-test.cpp"
foreach ($required in @($clangxx, $luaSrc, $helper, $map, $include, $luaTest)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$objDir = Join-Path $OutputDirectory "lua-obj"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
$luaC = Get-ChildItem -LiteralPath $luaSrc -Filter *.c |
    Where-Object { $_.Name -ne "lua.c" -and $_.Name -ne "luac.c" }

$cFlags = @(
    "-O2", "-fPIC", "-c",
    "-std=c99",
    "-fvisibility=hidden",
    "-DLUA_USE_POSIX",
    "-I$luaSrc"
)
$luaObjects = @()
foreach ($source in $luaC) {
    $object = Join-Path $objDir ($source.BaseName + ".o")
    & $clang @cFlags $source.FullName "-o" $object
    if ($LASTEXITCODE -ne 0) { throw "Lua C compilation failed: $($source.Name)" }
    $luaObjects += $object
}

$helperObject = Join-Path $objDir "lua-helper.o"
$cxxFlags = @(
    "-O2", "-fPIC", "-c",
    "-std=c++17",
    "-Wall", "-Wextra", "-Werror",
    "-fvisibility=hidden",
    "-I$include",
    "-I$luaSrc"
)
& $clangxx @cxxFlags $helper "-o" $helperObject
if ($LASTEXITCODE -ne 0) { throw "Lua helper C++ compilation failed" }

$so = Join-Path $OutputDirectory "librtgum-lua-helper.so"
$linkFlags = @(
    "-O2", "-fPIC", "-shared",
    "-static-libstdc++",
    "-fvisibility=hidden",
    "-Wl,--version-script=$map",
    "-Wl,-soname,librtgum-lua-helper.so",
    "-llog", "-ldl", "-lm"
)
& $clangxx @linkFlags $helperObject @luaObjects "-o" $so
if ($LASTEXITCODE -ne 0) { throw "Lua helper compilation failed" }

$testOut = Join-Path $OutputDirectory "rtgum-jnicode-lua-test"
$testFlags = @(
    "-std=c++17", "-O2", "-g", "-fPIE", "-pie", "-static-libstdc++",
    "-Wall", "-Wextra",
    "-I$include",
    "-ldl"
)
& $clangxx @testFlags $luaTest "-o" $testOut
if ($LASTEXITCODE -ne 0) { throw "Lua test compilation failed" }

Get-Item -LiteralPath $so, $testOut | Select-Object FullName, Length, LastWriteTime
Write-Output "jnicode-lua-helper-build PASS"
