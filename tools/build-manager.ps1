param(
    [string]$SdkPath = "",
    [string]$NdkPath = "",
    [string]$OutputDirectory = "",
    [string]$KeystorePath = "",
    [string]$KeystorePasswordFile = "",
    [string]$KeystoreAlias = "rtgum-manager",
    [ValidateRange(1, 2100000000)]
    [int]$VersionCode = 13,
    [ValidatePattern('^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$')]
    [string]$VersionName = "0.2.11",
    [ValidatePattern('^[A-Za-z0-9._-]+\.apk$')]
    [string]$OutputApkName = "rtgum-manager-debug.apk"
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
$sourceDirectory = Join-Path $projectDirectory 'manager-app\app\src\main'

if ([string]::IsNullOrWhiteSpace($SdkPath)) {
    $candidates = @($env:ANDROID_HOME,
                    (Join-Path $env:LOCALAPPDATA 'Android\Sdk'),
                    'E:\AndroidSDK')
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'platforms\android-35\android.jar'))) {
            $SdkPath = $candidate
            break
        }
    }
}
if ([string]::IsNullOrWhiteSpace($SdkPath)) {
    throw 'Android SDK platform android-35 was not found.'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory 'out\manager-build'
}
if ([string]::IsNullOrWhiteSpace($KeystorePath)) {
    $KeystorePath = Join-Path $projectDirectory 'out\device\pixel8\rtgum-manager-release.p12'
}
if ([string]::IsNullOrWhiteSpace($KeystorePasswordFile)) {
    $KeystorePasswordFile = Join-Path $projectDirectory `
        'out\device\pixel8\rtgum-manager-keystore.password'
}

$androidJar = Join-Path $SdkPath 'platforms\android-35\android.jar'
$buildTools = Join-Path $SdkPath 'build-tools\35.0.0'
$aapt2 = Join-Path $buildTools 'aapt2.exe'
$d8 = Join-Path $buildTools 'd8.bat'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$apksigner = Join-Path $buildTools 'apksigner.bat'
foreach ($required in @($androidJar, $aapt2, $d8, $zipalign, $apksigner)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required Android SDK file is missing: $required"
    }
}
foreach ($command in @('javac', 'jar', 'keytool')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "JDK command is missing: $command"
    }
}
$ndkCandidates = @($NdkPath,
                   $env:ANDROID_NDK_HOME,
                   (Join-Path $SdkPath 'ndk\25.2.9519653'),
                   (Join-Path $projectDirectory '.toolchains\android-ndk-r25c'))
foreach ($candidate in $ndkCandidates) {
    if ($candidate -and
        (Test-Path -LiteralPath (Join-Path $candidate `
            'toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe'))) {
        $NdkPath = $candidate
        break
    }
}
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory '.toolchains\android-ndk-r25c'
}
$clang = Join-Path $NdkPath 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe'
if (-not (Test-Path -LiteralPath $clang -PathType Leaf)) {
    throw 'Android NDK r25c compiler was not found. Pass -NdkPath or set ANDROID_NDK_HOME.'
}

if (-not (Test-Path -LiteralPath $KeystorePasswordFile -PathType Leaf)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $KeystorePasswordFile) | Out-Null
    $randomBytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
    $generatedPassword = ([Convert]::ToHexString($randomBytes)).ToLowerInvariant()
    [IO.File]::WriteAllText($KeystorePasswordFile, $generatedPassword,
                            [Text.Encoding]::ASCII)
}
$keystorePassword = (Get-Content -LiteralPath $KeystorePasswordFile -Raw).Trim()
if ($keystorePassword.Length -lt 12) { throw 'Manager keystore password is too short' }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$temporary = Join-Path $outputRoot ('tmp-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temporary | Out-Null
$temporaryAbsolute = [IO.Path]::GetFullPath($temporary)
if (-not $temporaryAbsolute.StartsWith($outputRoot + [IO.Path]::DirectorySeparatorChar,
                                      [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary build directory is outside the requested output directory.'
}

try {
    $classes = Join-Path $temporary 'classes'
    $dex = Join-Path $temporary 'dex'
    $nativeRoot = Join-Path $temporary 'native\lib\arm64-v8a'
    New-Item -ItemType Directory -Force -Path $classes, $dex, $nativeRoot | Out-Null
    $source = Join-Path $sourceDirectory 'java\dev\rtgum\manager\MainActivity.java'
    $bundleSource = Join-Path $projectDirectory `
        'manager-app\host\src\main\java\dev\rtgum\host\ModuleBundle.java'
    & javac -encoding UTF-8 -source 8 -target 8 -Xlint:-options `
        -cp $androidJar -d $classes $bundleSource $source
    if ($LASTEXITCODE -ne 0) { throw "javac failed: $LASTEXITCODE" }

    $classFiles = @(Get-ChildItem -LiteralPath $classes -Recurse -Filter '*.class' -File |
                        ForEach-Object FullName)
    & $d8 --lib $androidJar --min-api 26 --output $dex @classFiles
    if ($LASTEXITCODE -ne 0) { throw "d8 failed: $LASTEXITCODE" }

    $base = Join-Path $temporary 'base.apk'
    $manifest = Join-Path $sourceDirectory 'AndroidManifest.xml'
    & $aapt2 link -o $base -I $androidJar --manifest $manifest `
        --min-sdk-version 26 --target-sdk-version 35 `
        --version-code $VersionCode --version-name $VersionName --replace-version
    if ($LASTEXITCODE -ne 0) { throw "aapt2 failed: $LASTEXITCODE" }
    & jar uf $base -C $dex 'classes.dex'
    if ($LASTEXITCODE -ne 0) { throw "jar failed: $LASTEXITCODE" }

    $bridgeSource = Join-Path $projectDirectory `
        'manager-app\app\src\main\cpp\manager_bridge.cpp'
    $bridge = Join-Path $nativeRoot 'librtgum_manager.so'
    # The bridge uses only JNI's C ABI and bionic.  clang++ otherwise adds a
    # DT_NEEDED for libc++_shared.so even though no libc++ symbol is used,
    # which makes System.loadLibrary fail unless that runtime is packaged.
    & $clang --target=aarch64-linux-android26 -std=c++17 -O2 -fPIC -shared `
        -nostdlib++ `
        -fvisibility=hidden '-Wl,--build-id=sha1' '-Wl,-z,relro,-z,now' `
        -I (Join-Path $projectDirectory 'include') `
        -o $bridge $bridgeSource
    if ($LASTEXITCODE -ne 0) { throw "Manager native bridge build failed: $LASTEXITCODE" }
    $mako = Join-Path $projectDirectory 'out\kpm-stage1-pixel8-review\libmako-ghost.so'
    if (-not (Test-Path -LiteralPath $mako -PathType Leaf)) {
        throw "Mako runtime is missing: $mako"
    }
    Copy-Item -LiteralPath $mako -Destination (Join-Path $nativeRoot 'libmako-ghost.so')
    & jar uf $base -C (Join-Path $temporary 'native') 'lib'
    if ($LASTEXITCODE -ne 0) { throw "native library packaging failed: $LASTEXITCODE" }

    $aligned = Join-Path $temporary 'aligned.apk'
    & $zipalign -f 4 $base $aligned
    if ($LASTEXITCODE -ne 0) { throw "zipalign failed: $LASTEXITCODE" }

    if (-not (Test-Path -LiteralPath $KeystorePath -PathType Leaf)) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $KeystorePath) | Out-Null
        & keytool -genkeypair -storetype PKCS12 -keystore $KeystorePath `
            -storepass $keystorePassword -alias $KeystoreAlias `
            -keypass $keystorePassword -keyalg RSA -keysize 3072 `
            -validity 36500 -dname 'CN=android-kernel-hook Manager,O=android-kernel-hook,C=CN'
        if ($LASTEXITCODE -ne 0) { throw "keytool failed: $LASTEXITCODE" }
    }
    $outputApk = Join-Path $outputRoot $OutputApkName
    & $apksigner sign --ks $KeystorePath --ks-key-alias $KeystoreAlias `
        --ks-pass "pass:$keystorePassword" --key-pass "pass:$keystorePassword" `
        --v1-signing-enabled false --v2-signing-enabled true `
        --v3-signing-enabled false --v4-signing-enabled false `
        --out $outputApk $aligned
    if ($LASTEXITCODE -ne 0) { throw "apksigner failed: $LASTEXITCODE" }
    & $apksigner verify $outputApk
    if ($LASTEXITCODE -ne 0) { throw "APK signature verification failed: $LASTEXITCODE" }
    $badging = (& $aapt2 dump badging $outputApk 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect built APK metadata: $LASTEXITCODE" }
    $escapedName = [regex]::Escape($VersionName)
    if ($badging -notmatch "(?m)^package: .*versionCode='$VersionCode' versionName='$escapedName'") {
        $packageLine = ($badging -split "`r?`n" | Select-Object -First 1)
        throw "Built APK version does not match request: $packageLine"
    }
    $outputHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk).Hash.ToLowerInvariant()
    Get-Item -LiteralPath $outputApk | Select-Object FullName, Length
    Write-Output "manager-apk versionCode=$VersionCode versionName=$VersionName sha256=$outputHash"
} finally {
    if (Test-Path -LiteralPath $temporaryAbsolute) {
        Remove-Item -LiteralPath $temporaryAbsolute -Recurse -Force
    }
}
