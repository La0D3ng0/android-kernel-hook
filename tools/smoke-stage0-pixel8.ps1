param(
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = "",
    [string]$SuperKeyFile = "",
    [int]$Rounds = 5
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
$projectDirectory = Split-Path -Parent $PSScriptRoot
if (-not $AdbPath) {
    $AdbPath = Join-Path $projectDirectory ".toolchains/platform-tools-37.0.1/platform-tools/adb.exe"
}
if (-not $SuperKeyFile) {
    $SuperKeyFile = Join-Path $projectDirectory "out/device/pixel8/stage1-superkey-v3.txt"
}
if (-not (Test-Path -LiteralPath $AdbPath -PathType Leaf)) { throw "ADB executable is missing" }
if (-not (Test-Path -LiteralPath $SuperKeyFile -PathType Leaf)) { throw "SuperKey file is missing" }
if ($Rounds -lt 1 -or $Rounds -gt 25) { throw "Rounds must be between 1 and 25" }

$superKey = (Get-Content -Raw -LiteralPath $SuperKeyFile).Trim()
if ($superKey -cnotmatch '^[A-Za-z0-9]{8,63}$') { throw "Invalid SuperKey format" }
$deviceDirectory = "/data/local/tmp/rtgum-stage0-pixel8"
$client = "$deviceDirectory/rtgum-stage0-ctl"
$module = "$deviceDirectory/rtgum-stage0.kpm"

function Invoke-Device {
    param([string]$Command)
    $output = & $AdbPath -s $DeviceSerial shell "RTGUM_SUPERKEY=$superKey $client $Command" 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output -join "`n").Replace($superKey, "<redacted>").TrimEnd()
    if ($exitCode -ne 0) { throw "Device command failed with exit code ${exitCode}: $text" }
    return $text
}

function Read-Property {
    param([string]$Name)
    $value = & $AdbPath -s $DeviceSerial shell getprop $Name 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Unable to read device property $Name" }
    return ($value -join "`n").Trim()
}

$state = (& $AdbPath -s $DeviceSerial get-state 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne "device") {
    throw "ADB state is '$state'; authorize USB debugging on the phone first"
}

$product = Read-Property "ro.product.device"
$fingerprint = Read-Property "ro.build.fingerprint"
$locked = Read-Property "ro.boot.flash.locked"
$bootComplete = Read-Property "sys.boot_completed"
if ($product -ne "shiba") { throw "Unexpected device: $product" }
if ($fingerprint -ne "google/shiba/shiba:16/CP1A.260405.005/15001963:user/release-keys") {
    throw "Unexpected build fingerprint: $fingerprint"
}
if ($locked -ne "0") { throw "Bootloader is not unlocked" }
if ($bootComplete -ne "1") { throw "Android boot is incomplete" }
Write-Output "device=$product locked=$locked boot_completed=$bootComplete"
Write-Output "fingerprint=$fingerprint"

$ready = Invoke-Device "ready"
Write-Output $ready
if ($ready -notmatch 'ready hello=0x11581158 kpver=0xd09\b') {
    throw "KernelPatch 0.13.9 SuperCall did not pass"
}

for ($round = 1; $round -le $Rounds; $round++) {
    $smoke = Invoke-Device "smoke $module"
    Write-Output "round=$round"
    Write-Output $smoke
    if ($smoke -notmatch 'stage0-smoke PASS' -or
        $smoke -notmatch 'anonymous-allocation unmapped=1') {
        throw "Stage-0 smoke failed in round $round"
    }
}

$list = Invoke-Device "list"
$info = Invoke-Device "info"
Write-Output $list
Write-Output $info
if ($list -notmatch 'rtgum-stage0') { throw "Loaded KPM is absent from list" }
if ($info -notmatch 'rtgum-stage0') { throw "Loaded KPM has no metadata" }

$unload = Invoke-Device "unload"
Write-Output $unload
if ($unload -notmatch 'unloaded module=rtgum-stage0') { throw "KPM unload was not confirmed" }
Write-Output "pixel8-stage0-smoke PASS"
