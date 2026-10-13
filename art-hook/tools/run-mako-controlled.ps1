param(
    [string]$DeviceSerial = "",
    [string]$NdkPath = "",
    [string]$CMakePath = "",
    [string]$NinjaPath = "",
    [string]$JavaHomePath = "",
    [string]$AndroidSdkPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$workspaceDirectory = Split-Path -Parent $projectDirectory
if (-not $NdkPath) { $NdkPath = Join-Path $workspaceDirectory ".toolchains\android-ndk-r29" }
if (-not $CMakePath) { $CMakePath = Join-Path $workspaceDirectory ".toolchains\cmake-3.31.12-windows-x86_64\bin\cmake.exe" }
if (-not $NinjaPath) { $NinjaPath = Join-Path $workspaceDirectory ".toolchains\ninja-1.13.2\ninja.exe" }
if (-not $JavaHomePath) { $JavaHomePath = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "D:\jdk" } }
if (-not $AndroidSdkPath) { $AndroidSdkPath = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "D:\AndroidSDK" } }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectDirectory "out\mako-controlled" }

$toolchain = Join-Path $NdkPath "build\cmake\android.toolchain.cmake"
$javac = Join-Path $JavaHomePath "bin\javac.exe"
$jar = Join-Path $JavaHomePath "bin\jar.exe"
$d8 = Join-Path $AndroidSdkPath "build-tools\36.0.0\d8.bat"
$adb = Join-Path $AndroidSdkPath "platform-tools\adb.exe"
$bootstrapSource = Join-Path $projectDirectory "bootstrap\com\rtgum\mako\PreForkHost.java"
$probeSource = Join-Path $projectDirectory "tests\MakoProbe.java"
$bootstrapBuilder = Join-Path $PSScriptRoot "build-mako-bootstrap.ps1"
foreach ($required in @($toolchain, $CMakePath, $NinjaPath, $javac, $jar,
                         $d8, $adb, $bootstrapSource, $probeSource,
                         $bootstrapBuilder)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

$nativeOutput = Join-Path $OutputDirectory "native"
$classesOutput = Join-Path $OutputDirectory "classes"
$dexOutput = Join-Path $OutputDirectory "dex"
$bootstrapOutput = Join-Path $OutputDirectory "bootstrap"
New-Item -ItemType Directory -Force -Path $nativeOutput, $classesOutput,
    $dexOutput, $bootstrapOutput | Out-Null

& $CMakePath -S $projectDirectory -B $nativeOutput -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$NinjaPath" `
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain" `
    "-DANDROID_ABI=arm64-v8a" "-DANDROID_PLATFORM=android-30" `
    "-DANDROID_STL=c++_static" "-DCMAKE_BUILD_TYPE=RelWithDebInfo" `
    "-DART_HOOK_BUILD_SHARED=OFF" "-DART_HOOK_WITH_LSPLANT=OFF" `
    "-DART_HOOK_BUILD_MAKO=ON" "-DART_HOOK_BUILD_TESTS=ON"
if ($LASTEXITCODE -ne 0) { throw "Mako CMake configuration failed: $LASTEXITCODE" }
& $CMakePath --build $nativeOutput --target mako-cache mako mako-live-test
if ($LASTEXITCODE -ne 0) { throw "Mako native build failed: $LASTEXITCODE" }

& $bootstrapBuilder -JavaHomePath $JavaHomePath -AndroidSdkPath $AndroidSdkPath `
    -OutputDirectory $bootstrapOutput | Out-Null
& $javac --release 8 -Xlint:-options -d $classesOutput $bootstrapSource $probeSource
if ($LASTEXITCODE -ne 0) { throw "Mako probe javac failed: $LASTEXITCODE" }
$bootstrapClass = Join-Path $classesOutput "com\rtgum\mako\PreForkHost.class"
$probeClass = Join-Path $classesOutput "MakoProbe.class"
& $d8 --min-api 30 --output $dexOutput $bootstrapClass $probeClass
if ($LASTEXITCODE -ne 0) { throw "Mako probe d8 failed: $LASTEXITCODE" }
$probeJar = Join-Path $OutputDirectory "mako-probe.jar"
& $jar cf $probeJar -C $dexOutput classes.dex
if ($LASTEXITCODE -ne 0) { throw "Mako probe jar failed: $LASTEXITCODE" }

$adbArgs = @()
if ($DeviceSerial) { $adbArgs = @("-s", $DeviceSerial) }
$deviceState = (& $adb @adbArgs get-state 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $deviceState -ne "device") {
    throw "ADB device unavailable: $deviceState"
}

function Confirm-DeviceSha256([string]$LocalPath, [string]$RemotePath) {
    $localHash = (Get-FileHash -LiteralPath $LocalPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $deviceLine = (& $adb @adbArgs shell "toybox sha256sum '$RemotePath'" 2>&1 |
        Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $deviceLine -notmatch '^([0-9a-fA-F]{64})\s+') {
        throw "Cannot read device SHA256 for ${RemotePath}: $deviceLine"
    }
    $deviceHash = $Matches[1].ToLowerInvariant()
    if ($deviceHash -ne $localHash) {
        throw "Device SHA256 mismatch for $RemotePath"
    }
    Write-Output "sha256-ok local=$localHash device=$deviceHash remote=$RemotePath"
}

$zygoteBefore = (& $adb @adbArgs shell "pidof zygote64" 2>$null | Out-String).Trim()
$artifacts = @(
    (Join-Path $nativeOutput "libmako-cache.so"),
    (Join-Path $nativeOutput "libmako.so"),
    (Join-Path $nativeOutput "libmako-live-test.so"),
    $probeJar
)
foreach ($artifact in $artifacts) {
    $remoteArtifact = "/data/local/tmp/" + [IO.Path]::GetFileName($artifact)
    & $adb @adbArgs push $artifact $remoteArtifact | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ADB push failed: $artifact" }
    Confirm-DeviceSha256 $artifact $remoteArtifact
}

$inherited = (& $adb @adbArgs shell `
    "CLASSPATH=/data/local/tmp/mako-probe.jar app_process /system/bin MakoProbe" 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $inherited -notmatch "(?m)^mako inherited cache: PASS$") {
    throw "Inherited-cache run failed: $inherited"
}
$fallback = (& $adb @adbArgs shell `
    "CLASSPATH=/data/local/tmp/mako-probe.jar app_process /system/bin MakoProbe fallback" 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $fallback -notmatch "(?m)^mako fallback: PASS$") {
    throw "Fallback run failed: $fallback"
}
$zygoteAfter = (& $adb @adbArgs shell "pidof zygote64" 2>$null | Out-String).Trim()
if ($zygoteBefore -and $zygoteAfter -and $zygoteBefore -ne $zygoteAfter) {
    throw "Zygote PID changed during the isolated test: $zygoteBefore -> $zygoteAfter"
}

$result = [ordered]@{
    deviceSerial = $DeviceSerial
    inherited = $inherited
    fallback = $fallback
    zygotePidBefore = $zygoteBefore
    zygotePidAfter = $zygoteAfter
    artifacts = @($artifacts | ForEach-Object {
        [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash }
    })
}
$resultPath = Join-Path $OutputDirectory "result.json"
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding utf8
Write-Output $inherited
Write-Output $fallback
Write-Output "Controlled Mako result: $resultPath"
