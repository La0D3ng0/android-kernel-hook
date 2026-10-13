param(
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [switch]$FreshBoot,
    [string]$BootImage = "",
    [string]$OutputDirectory = "",
    [string]$LabApk = "",
    [string]$LabElf = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
$projectDirectory = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $projectDirectory ".toolchains\platform-tools-37.0.1\platform-tools\adb.exe"
$fastboot = Join-Path $projectDirectory ".toolchains\platform-tools-37.0.1\platform-tools\fastboot.exe"
if ([string]::IsNullOrWhiteSpace($BootImage)) {
    $BootImage = Join-Path $projectDirectory "out\device\pixel8\boot-kp0139-manager-v1-cp1a.260405.005.img"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}
if ([string]::IsNullOrWhiteSpace($LabApk)) {
    $LabApk = Join-Path $projectDirectory "out\lab-apk\rtgum-art-lab.apk"
}
if ([string]::IsNullOrWhiteSpace($LabElf)) {
    $LabElf = Join-Path $projectDirectory "out\lab-apk\work\jni\arm64-v8a\libghostlab.so"
}
$superkeyPath = Join-Path $projectDirectory "out\device\pixel8\stage1-superkey-v3.txt"
$kpm = Join-Path $OutputDirectory "rtgum-stage1.kpm"
$ctl = Join-Path $OutputDirectory "rtgum-stage1-ctl"
$daemon = Join-Path $OutputDirectory "rtgum-stage2-daemon.so"
$module = Join-Path $OutputDirectory "rtgum-stage2-symbol.ghm"
foreach ($path in @($adb, $fastboot, $BootImage, $superkeyPath, $kpm, $ctl,
                    $daemon, $module, $LabApk, $LabElf)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file is missing: $path"
    }
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & $adb -s $DeviceSerial @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed ($($Arguments -join ' ')): $($output -join ' ')"
    }
    return @($output)
}

$bootBefore = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($FreshBoot) {
    Invoke-Adb reboot bootloader | Out-Null
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        Start-Sleep -Seconds 1
        if ((& $fastboot devices) -match [regex]::Escape($DeviceSerial)) { break }
    }
    if ($attempt -ge 60) { throw "fastboot device timeout" }
    & $fastboot -s $DeviceSerial boot $BootImage
    if ($LASTEXITCODE -ne 0) { throw "fastboot boot failed" }
    & $adb -s $DeviceSerial wait-for-device
    for ($attempt = 0; $attempt -lt 120; ++$attempt) {
        if (((& $adb -s $DeviceSerial shell getprop sys.boot_completed 2>$null) -join "").Trim() -eq "1") {
            break
        }
        Start-Sleep -Seconds 1
    }
    if ($attempt -ge 120) { throw "Android boot timeout" }
}

$bootId = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($FreshBoot -and $bootId -eq $bootBefore) { throw "fresh boot did not change boot_id" }
$remote = "/data/local/tmp/rtgum-stage1-pixel8"
$artifacts = @(
    @($ctl, "$remote/rtgum-stage1-ctl"),
    @($kpm, "$remote/rtgum-stage1.kpm"),
    @($daemon, "$remote/rtgum-stage2-daemon.so"),
    @($module, "$remote/rtgum-stage2-symbol.ghm"),
    @($LabElf, "$remote/libghostlab.so")
)
Invoke-Adb shell "mkdir -p $remote" | Out-Null
foreach ($pair in $artifacts) { Invoke-Adb push $pair[0] $pair[1] | Out-Null }
Invoke-Adb shell chmod 755 "$remote/rtgum-stage1-ctl" | Out-Null
Invoke-Adb shell sync | Out-Null
foreach ($pair in $artifacts) {
    $localSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteSha = ((((Invoke-Adb shell sha256sum $pair[1]) -join " ") -split "\s+")[0]).ToLowerInvariant()
    $localMd5 = (Get-FileHash -Algorithm MD5 -LiteralPath $pair[0]).Hash.ToLowerInvariant()
    $remoteMd5 = ((((Invoke-Adb shell md5sum $pair[1]) -join " ") -split "\s+")[0]).ToLowerInvariant()
    if ($localSha -ne $remoteSha -or $localMd5 -ne $remoteMd5) {
        throw "push hash mismatch: $($pair[1])"
    }
    Write-Host "hash-ok sha256=$localSha md5=$localMd5 file=$($pair[1])"
}

Invoke-Adb install -r -t $LabApk | Out-Null
$superkey = [IO.File]::ReadAllText($superkeyPath).Trim()
$remoteCtl = "$remote/rtgum-stage1-ctl"
$ready = (& $adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl ready 2>&1) -join " "
if ($LASTEXITCODE -ne 0 -or $ready -notmatch "kpver=0xd09") {
    throw "KernelPatch readiness failed: $ready"
}
Write-Host $ready
$info = (& $adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl info 2>&1) -join " "
if ($LASTEXITCODE -ne 0) {
    $loaded = (& $adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl load "$remote/rtgum-stage1.kpm" 2>&1) -join " "
    if ($LASTEXITCODE -ne 0) { throw "KPM load failed: $loaded" }
    Write-Host $loaded
} elseif ($info -notmatch "0\.12\.0") {
    throw "another rtgum-stage1 version is already loaded; rerun with -FreshBoot: $info"
}

$sessionReply = (& $adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" $remoteCtl session-manager 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "session-manager failed: $sessionReply" }
$sessionMatch = [regex]::Match($sessionReply, "(?:session(?:-key)?|key)=([0-9A-Fa-f]+)")
if (-not $sessionMatch.Success) { $sessionMatch = [regex]::Match($sessionReply, "([0-9A-Fa-f]{32,})") }
if (-not $sessionMatch.Success) { throw "session key missing" }
$session = $sessionMatch.Groups[1].Value

Invoke-Adb shell am force-stop dev.rtgum.lab | Out-Null
$result = (& $adb -s $DeviceSerial shell env "RTGUM_SUPERKEY=$superkey" `
    "RTGUM_SESSION_KEY=$session" $remoteCtl symbol-target-test `
    dev.rtgum.lab dev.rtgum.lab/.MainActivity 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0 -or $result -notmatch "stage2-symbol-resolver PASS") {
    throw "symbol resolver smoke failed: $result"
}
Write-Host $result

$logs = (Invoke-Adb shell cat "$remote/rtgum-symbol-dmesg.log") -join "`n"
foreach ($evidence in @(
    "rtgum-symbol: libc.so!open resolved",
    "rtgum-symbol: ghost .symtab resolved",
    "rtgum-symbol: disk .symtab fallback resolved",
    "libghostlab.so!lab_add+0x0",
    "rtgum-symbol: symbol not found",
    "rtgum-symbol: PASS"
)) {
    if ($logs -notlike "*$evidence*") { throw "missing device evidence: $evidence" }
}
$bootAfter = ((Invoke-Adb shell cat /proc/sys/kernel/random/boot_id) -join "").Trim()
if ($bootAfter -ne $bootId) { throw "device rebooted during symbol resolver smoke" }
Write-Host "symbol-smoke PASS"
Write-Host "hook=libc.so!open trace=libghostlab.so!lab_add+0x0 ghost-full-symtab=1 disk-full-symtab=1 missing=ENOENT reboot=0"
