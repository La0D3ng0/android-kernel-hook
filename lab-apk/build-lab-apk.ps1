# Build the ART hook acceptance APK (dev.rtgum.lab).
#
# Uses the platform build-tools directly (aapt2 / d8 / zipalign / apksigner)
# rather than Gradle: the lab is a single activity with no dependencies, and a
# direct build keeps the artifact reproducible from this script alone.
#
# The APK is self-signed with a generated lab keystore. It is a test fixture,
# never shipped, and never installed anywhere but the lab device.

param(
    [string]$SdkPath = "",
    [int]$Api = 35,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($SdkPath)) {
    if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
        $SdkPath = $env:ANDROID_HOME
    } elseif (-not [string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT)) {
        $SdkPath = $env:ANDROID_SDK_ROOT
    } else {
        $SdkPath = Join-Path $env:LOCALAPPDATA "Android\Sdk"
    }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\lab-apk"
}

$buildTools = Get-ChildItem (Join-Path $SdkPath "build-tools") -Directory |
    Sort-Object { [int]($_.Name -replace '\..*$', '') } -Descending |
    Select-Object -First 1
if ($null -eq $buildTools) { throw "no build-tools under $SdkPath" }
$platform = Join-Path $SdkPath "platforms\android-$Api"
$androidJar = Join-Path $platform "android.jar"

$aapt2 = Join-Path $buildTools.FullName "aapt2.exe"
$d8 = Join-Path $buildTools.FullName "d8.bat"
$zipalign = Join-Path $buildTools.FullName "zipalign.exe"
$apksigner = Join-Path $buildTools.FullName "apksigner.bat"
$javac = (Get-Command javac.exe -ErrorAction SilentlyContinue).Source
$keytool = (Get-Command keytool.exe -ErrorAction SilentlyContinue).Source

foreach ($required in @($aapt2, $d8, $zipalign, $apksigner, $androidJar)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "required tool missing: $required" }
}
if ([string]::IsNullOrWhiteSpace($javac)) { throw "javac.exe not found on PATH" }
if ([string]::IsNullOrWhiteSpace($keytool)) { throw "keytool.exe not found on PATH" }

$sourceRoot = Join-Path $PSScriptRoot "src"
$manifest = Join-Path $PSScriptRoot "AndroidManifest.xml"
$work = Join-Path $OutputDirectory "work"
$classes = Join-Path $work "classes"
$dex = Join-Path $work "dex"
foreach ($directory in @($OutputDirectory, $work, $classes, $dex)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

# ---- 1. resources -----------------------------------------------------------
# aapt2 link accepts a resource directory; an empty one keeps the lab free of
# resource ids so the manifest is the whole resource story.
$res = Join-Path $PSScriptRoot "res"
New-Item -ItemType Directory -Force -Path $res | Out-Null
$flat = Join-Path $work "res.zip"
& $aapt2 compile --dir $res -o $flat 2>&1 | Out-Null

$unsigned = Join-Path $work "lab-unsigned.apk"
& $aapt2 link -o $unsigned -I $androidJar --manifest $manifest `
    --min-sdk-version $Api --target-sdk-version $Api $flat
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed ($LASTEXITCODE)" }

# ---- 2. java -> dex --------------------------------------------------------
$sources = Get-ChildItem -Path $sourceRoot -Recurse -Filter "*.java" | ForEach-Object { $_.FullName }
if ($sources.Count -eq 0) { throw "no java sources under $sourceRoot" }
# -source/-target 8 with the platform bootclasspath: --release cannot be
# combined with an explicit bootclasspath, and the deprecation notice it
# replaces is already silenced by -Xlint:-options. PowerShell treats any
# compiler message on stderr as an error record, so the preference is relaxed
# for this one invocation and the exit code is checked directly.
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $javac -source 8 -target 8 -Xlint:-options -bootclasspath $androidJar `
    -classpath $androidJar -nowarn -d $classes $sources 2>$null
$javacExit = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($javacExit -ne 0) { throw "javac failed ($javacExit)" }

$classFiles = Get-ChildItem -Path $classes -Recurse -Filter "*.class" | ForEach-Object { $_.FullName }
# d8 in these build-tools tops out at API 34; the lab uses no API-35 surface, so
# the lower min-api is the correct target rather than a compromise.
$d8Api = [Math]::Min($Api, 34)
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $d8 --release --min-api $d8Api --lib $androidJar --output $dex $classFiles 2>$null
$d8Exit = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($d8Exit -ne 0) { throw "d8 failed ($d8Exit)" }

# ---- 2b. native ArtMethod reader ------------------------------------------
# FromReflectedMethod is the only route to an ArtMethod address that survives
# the hidden-API filter on API 34, and it needs JNI, so the lab ships one small
# .so. It is a test fixture: the framework itself never uses it.
$abi = "arm64-v8a"
$jniLibs = Join-Path $work "jni\$abi"
New-Item -ItemType Directory -Force -Path $jniLibs | Out-Null
$labscanSource = Join-Path $PSScriptRoot "jni\labscan.cpp"
$gtraceSource = Join-Path $PSScriptRoot "jni\gtrace_flower.S"
$labscanOutput = Join-Path $jniLibs "libghostlab.so"
$clang = Get-ChildItem (Join-Path $projectDirectory ".toolchains\android-ndk-r29\toolchains\llvm\prebuilt\windows-x86_64\bin") `
    -Filter "aarch64-linux-android$Api-clang.cmd" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $clang) {
    $clang = Get-ChildItem (Join-Path $projectDirectory ".toolchains\android-ndk-r29\toolchains\llvm\prebuilt\windows-x86_64\bin") `
        -Filter "aarch64-linux-android*-clang.cmd" | Sort-Object Name -Descending |
        Select-Object -First 1
}
if ($null -eq $clang) { throw "no aarch64 clang wrapper found in the NDK" }
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
# Splatted array rather than a single line: PowerShell parses an unquoted
# -Wl,-soname,... as a parameter list and chokes on it. -llog is required for
# android_log_print and -ldl are required for diagnostics and the runtime's
# exported jmethodID decoder. -fno-builtin remains part of the freestanding
# fixture policy; it is not a workaround for the earlier unreachable logging
# block (the optimizer correctly removed that dead code).
$clangFlags = @(
    "-std=c++17", "-O2", "-fno-builtin", "-fPIC", "-shared", "-Wall", "-Wextra",
    "-Wl,-soname,libghostlab.so", $labscanSource, $gtraceSource,
    "-o", $labscanOutput,
    "-llog", "-ldl"
)
& $clang.FullName @clangFlags 2>$null
$clangExit = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($clangExit -ne 0) { throw "labscan build failed ($clangExit)" }

# ---- 3. package ------------------------------------------------------------
$dexFile = Join-Path $dex "classes.dex"
if (-not (Test-Path -LiteralPath $dexFile)) { throw "d8 produced no classes.dex" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$withDex = Join-Path $work "lab-with-dex.apk"
Copy-Item -LiteralPath $unsigned -Destination $withDex -Force
$archive = [System.IO.Compression.ZipFile]::Open($withDex, "Update")
try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $archive, $dexFile, "classes.dex") | Out-Null
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $archive, $labscanOutput, "lib/$abi/libghostlab.so") | Out-Null
} finally {
    $archive.Dispose()
}

$aligned = Join-Path $work "lab-aligned.apk"
& $zipalign -f 4 $withDex $aligned
if ($LASTEXITCODE -ne 0) { throw "zipalign failed ($LASTEXITCODE)" }

# ---- 4. sign ---------------------------------------------------------------
$keystore = Join-Path $OutputDirectory "lab-debug.keystore"
if (-not (Test-Path -LiteralPath $keystore)) {
    # keytool prints its progress to stderr, which PowerShell would otherwise
    # turn into a terminating error under $ErrorActionPreference = Stop.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $keytool -genkeypair -keystore $keystore -storepass android -keypass android `
        -alias labdebug -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=RTGUM Lab, OU=Test, O=RTGUM, L=Lab, S=Lab, C=CN" 2>$null
    $keytoolExit = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($keytoolExit -ne 0) { throw "keytool failed ($keytoolExit)" }
}

$signed = Join-Path $OutputDirectory "rtgum-art-lab.apk"
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $apksigner sign --ks $keystore --ks-pass pass:android --key-pass pass:android `
    --out $signed $aligned 2>$null
$signExit = $LASTEXITCODE
if ($signExit -eq 0) {
    & $apksigner verify $signed 2>$null
    $signExit = $LASTEXITCODE
}
$ErrorActionPreference = $previousPreference
if ($signExit -ne 0) { throw "apksigner failed ($signExit)" }

$item = Get-Item -LiteralPath $signed
$hash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLower()
[pscustomobject]@{
    Path = $item.FullName
    Length = $item.Length
    Sha256 = $hash
} | Format-List
