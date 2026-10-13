param(
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = '',
    [string]$FastbootPath = '',
    [string]$BootImagePath = '',
    [string]$KpmPath = '',
    [string]$CtlPath = '',
    [string]$ModulePath = '',
    [string]$OutputDirectory = '',
    [switch]$FreshBoot,
    [switch]$KeepFixture
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
$projectDirectory = Split-Path -Parent $PSScriptRoot
$managerPackage = 'dev.rtgum.manager'
$managerComponent = 'dev.rtgum.manager/dev.rtgum.manager.MainActivity'
$fixturePackage = 'dev.rtgum.manager.ui.fixture'
$fixtureName = 'rtgum-manager-ui-test.ghm'
$remoteRoot = '/data/local/tmp/rtgum-manager-ui'
$remoteCtl = "$remoteRoot/rtgum-stage1-ctl"
$remoteKpm = "$remoteRoot/rtgum-stage1.kpm"
$remoteFixture = "/sdcard/Download/$fixtureName"

if (-not $AdbPath) {
    $bundled = Join-Path $projectDirectory '.toolchains\platform-tools-37.0.1\platform-tools\adb.exe'
    $AdbPath = if (Test-Path -LiteralPath $bundled) { $bundled } else { 'adb' }
}
if (-not $FastbootPath) {
    $bundled = Join-Path $projectDirectory '.toolchains\platform-tools-37.0.1\platform-tools\fastboot.exe'
    $FastbootPath = if (Test-Path -LiteralPath $bundled) { $bundled } else { 'fastboot' }
}
if (-not $BootImagePath) {
    $BootImagePath = Join-Path $projectDirectory `
        'out\device\pixel8\boot-kp0139-manager-v1-cp1a.260405.005.img'
}
if (-not $KpmPath) {
    $KpmPath = Join-Path $projectDirectory 'out\kpm-stage1-pixel8-review\rtgum-stage1.kpm'
}
if (-not $CtlPath) {
    $CtlPath = Join-Path $projectDirectory 'out\kpm-stage1-pixel8-review\rtgum-stage1-ctl'
}
if (-not $ModulePath) {
    $ModulePath = Join-Path $projectDirectory 'out\kpm-stage1-pixel8-review\rtgum-stage2-gumlua.ghm'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $projectDirectory 'out\manager-ui-automation'
}
$superKeyFile = Join-Path $projectDirectory 'out\device\pixel8\stage1-superkey-v3.txt'
$builder = Join-Path $projectDirectory 'tools\build-manager.ps1'
$keystore = Join-Path $projectDirectory 'out\device\pixel8\rtgum-manager-release.p12'

foreach ($path in @($BootImagePath, $KpmPath, $CtlPath, $ModulePath,
                     $superKeyFile, $builder, $keystore)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file is missing: $path"
    }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

function Invoke-Adb {
    # Keep this a simple function with no declared parameters.  Advanced
    # PowerShell functions consume adb switches such as -W/-d as abbreviated
    # common parameters instead of forwarding them to adb.
    $allowFailure = $false
    $arguments = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $args.Count; ++$index) {
        if ([string]$args[$index] -eq '-AllowFailure') {
            $allowFailure = $true
            continue
        }
        if ([string]$args[$index] -eq '-AllowFailure:' -and $index + 1 -lt $args.Count) {
            $allowFailure = [bool]$args[++$index]
            continue
        }
        $arguments.Add($args[$index])
    }
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    throw 'Pass -DeviceSerial or set ANDROID_SERIAL.'
}
        $output = (& $AdbPath -s $DeviceSerial @arguments 2>&1 |
            ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $text = ($output -join "`n").Trim()
    if (-not $allowFailure -and $exitCode -ne 0) {
        throw "adb failed ($($arguments -join ' ')): $text"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

function Wait-ForAndroid {
    & $AdbPath -s $DeviceSerial wait-for-device | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'adb wait-for-device failed' }
    for ($attempt = 0; $attempt -lt 120; ++$attempt) {
        $booted = (Invoke-Adb shell getprop sys.boot_completed -AllowFailure).Text
        if ($booted -eq '1') { return }
        Start-Sleep -Seconds 1
    }
    throw 'Android boot timeout'
}

function Dismiss-Keyguard {
    # A freshly booted Pixel can report sys.boot_completed=1 while the
    # unlocked keyguard/notification shade still owns the accessibility
    # window.  UIAutomator would then inspect SystemUI instead of Manager.
    Invoke-Adb shell input keyevent KEYCODE_WAKEUP -AllowFailure | Out-Null
    Invoke-Adb shell wm dismiss-keyguard -AllowFailure | Out-Null
    Start-Sleep -Milliseconds 200
    $focus = (Invoke-Adb shell dumpsys window -AllowFailure).Text
    if ($focus -match 'mCurrentFocus=.*(?:NotificationShade|Keyguard)') {
        Invoke-Adb shell input keyevent 82 -AllowFailure | Out-Null
        Invoke-Adb shell input swipe 540 1850 540 350 250 -AllowFailure | Out-Null
        Start-Sleep -Milliseconds 400
    }
}

function Start-FreshBoot {
    Invoke-Adb reboot bootloader | Out-Null
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        Start-Sleep -Seconds 1
        $devices = (& $FastbootPath devices 2>$null | Out-String)
        if ($devices -match [regex]::Escape($DeviceSerial)) { break }
    }
    if ($attempt -ge 60) { throw 'fastboot device timeout' }
    $boot = (& $FastbootPath -s $DeviceSerial boot $BootImagePath 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "fastboot boot failed: $boot" }
    Wait-ForAndroid
}

function Get-PackageVersion {
    $dump = (Invoke-Adb shell dumpsys package $managerPackage).Text
    $code = [regex]::Match($dump, '(?m)^\s*versionCode=(\d+)\b')
    $name = [regex]::Match($dump, '(?m)^\s*versionName=([^\r\n]+)')
    if (-not $code.Success -or -not $name.Success) {
        throw "$managerPackage is not installed or has no readable version"
    }
    return [pscustomobject]@{
        Code = [int]$code.Groups[1].Value
        Name = $name.Groups[1].Value.Trim()
    }
}

function Get-ApkSigner {
    $candidates = @($env:ANDROID_HOME,
                    (Join-Path $env:LOCALAPPDATA 'Android\Sdk'),
                    'E:\AndroidSDK') | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    foreach ($sdk in $candidates) {
        $candidate = Get-ChildItem -LiteralPath (Join-Path $sdk 'build-tools') `
            -Recurse -Filter 'apksigner.bat' -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
        if ($candidate) { return $candidate }
    }
    throw 'apksigner.bat was not found'
}

function Get-CertificateDigest([string]$apk, [string]$apksigner) {
    $result = (& $apksigner verify --print-certs $apk 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "APK signature verification failed: $apk" }
    $match = [regex]::Match($result, 'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})')
    if (-not $match.Success) { throw "Cannot read signer digest from $apk" }
    return $match.Groups[1].Value.ToLowerInvariant()
}

function Backup-ManagerData([string]$label) {
    Invoke-Adb shell am force-stop $managerPackage | Out-Null
    $remote = "$remoteRoot/manager-data-$label.tar"
    Invoke-Adb shell "mkdir -p $remoteRoot" | Out-Null
    $command = "su -c 'tar -cpf $remote -C /data/user/0 $managerPackage && chmod 0644 $remote'"
    Invoke-Adb shell $command | Out-Null
    $local = Join-Path $OutputDirectory "manager-data-$label.tar"
    Invoke-Adb pull $remote $local | Out-Null
    Invoke-Adb shell rm -f $remote | Out-Null
    if (-not (Test-Path -LiteralPath $local) -or (Get-Item $local).Length -eq 0) {
        throw 'Manager data backup is empty'
    }
    return $local
}

function Read-PrivateFile([string]$relativePath, [switch]$Optional) {
    $path = "/data/user/0/$managerPackage/$relativePath"
    $result = Invoke-Adb shell "su -c 'cat $path 2>/dev/null'" -AllowFailure
    if ($result.ExitCode -ne 0 -and -not $Optional) {
        throw "Cannot read Manager private file: $relativePath"
    }
    return $result.Text
}

function Read-RecordsFromPreferences([string]$xmlText) {
    if ([string]::IsNullOrWhiteSpace($xmlText)) { return @() }
    [xml]$document = $xmlText
    $node = $document.SelectSingleNode('/map/string[@name="records"]')
    if ($null -eq $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) { return @() }
    return @($node.InnerText | ConvertFrom-Json)
}

function Assert-RecordEquivalent($expected, [object[]]$actualRecords, [string]$label) {
    $matches = @($actualRecords | Where-Object {
        $_.id -eq $expected.id -and $_.package -eq $expected.package
    })
    if ($matches.Count -ne 1) {
        throw "$label record is missing or duplicated: $($expected.package)"
    }
    $actual = $matches[0]
    if ([string]$actual.sha256 -cne [string]$expected.sha256 -or
        [bool]$actual.enabled -ne [bool]$expected.enabled -or
        [bool]$actual.art_hook -ne [bool]$expected.art_hook -or
        [bool]$actual.memory_access -ne [bool]$expected.memory_access -or
        [bool]$actual.anti_debug -ne [bool]$expected.anti_debug) {
        throw "$label record changed during upgrade/restart: $($expected.package)"
    }
}

function Get-UiDocument {
    $dump = Invoke-Adb shell uiautomator dump /sdcard/rtgum-manager-ui.xml -AllowFailure
    if ($dump.ExitCode -ne 0 -or $dump.Text -match 'ERROR') {
        Start-Sleep -Milliseconds 250
        $dump = Invoke-Adb shell uiautomator dump /sdcard/rtgum-manager-ui.xml
    }
    $raw = (Invoke-Adb exec-out cat /sdcard/rtgum-manager-ui.xml).Text
    try { return [xml]$raw } catch { throw "Invalid UIAutomator XML: $($_.Exception.Message)" }
}

function Find-UiNode {
    param(
        [string]$Description = '',
        [string]$Text = '',
        [int]$TimeoutSeconds = 0,
        [switch]$Scroll
    )
    # A Pixel UIAutomator dump commonly takes 1-2 seconds.  A scroll search
    # needs enough time for several dumps; otherwise a valid off-screen node
    # is rejected after only one or two swipes.
    $effectiveTimeout = if ($Scroll) { [Math]::Max($TimeoutSeconds, 20) } else { $TimeoutSeconds }
    $deadline = [DateTime]::UtcNow.AddSeconds($effectiveTimeout)
    $swipes = 0
    do {
        $document = Get-UiDocument
        foreach ($node in $document.SelectNodes('//node')) {
            if ($Description -and $node.GetAttribute('content-desc') -eq $Description) { return $node }
            if ($Text -and $node.GetAttribute('text') -eq $Text) { return $node }
        }
        if ($Scroll -and $swipes -lt 10) {
            Invoke-Adb shell input swipe 540 1900 540 500 300 | Out-Null
            ++$swipes
            Start-Sleep -Milliseconds 250
        } else {
            Start-Sleep -Milliseconds 350
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Assert-UiNode {
    param(
        [string]$Description,
        [int]$TimeoutSeconds = 12,
        [switch]$Scroll
    )
    $node = Find-UiNode -Description $Description -TimeoutSeconds $TimeoutSeconds -Scroll:$Scroll
    if ($null -eq $node) { throw "UI node not found: $Description" }
    return $node
}

function Get-NodeText($node) { return $node.GetAttribute('text') }

function Hide-SoftKeyboard {
    for ($attempt = 0; $attempt -lt 4; ++$attempt) {
        $state = (Invoke-Adb shell dumpsys input_method -AllowFailure).Text
        if ($state -notmatch '(?m)^\s*mInputShown=true\s*$') { return }
        Invoke-Adb shell input keyevent KEYCODE_BACK | Out-Null
        Start-Sleep -Milliseconds 350
    }
    throw 'Soft keyboard remained visible after BACK'
}

function Tap-UiNode($node) {
    $description = $node.GetAttribute('content-desc')
    $nodeText = $node.GetAttribute('text')
    $className = $node.GetAttribute('class')
    if ($className -notmatch 'EditText|AutoCompleteTextView') {
        Hide-SoftKeyboard
        $refetched = if ($description) {
            Find-UiNode -Description $description -TimeoutSeconds 4
        } else {
            Find-UiNode -Text $nodeText -TimeoutSeconds 4
        }
        if ($null -ne $refetched) { $node = $refetched }
    }
    for ($attempt = 0; $attempt -lt 6; ++$attempt) {
        $bounds = $node.GetAttribute('bounds')
        $match = [regex]::Match($bounds, '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$')
        if (-not $match.Success) { throw "Invalid UI bounds: $bounds" }
        $left = [int]$match.Groups[1].Value
        $top = [int]$match.Groups[2].Value
        $right = [int]$match.Groups[3].Value
        $bottom = [int]$match.Groups[4].Value
        # Pixel 8's gesture/navigation inset begins below y=2300.  Buttons
        # ending at 2274 are fully tappable even though the ScrollView cannot
        # move them any farther upward at end-of-content.
        if ($top -ge 140 -and $bottom -le 2300 -and $bottom - $top -ge 40) {
            $x = [int](0.5 * ($left + $right))
            $y = [int](0.5 * ($top + $bottom))
            Invoke-Adb shell input tap $x $y | Out-Null
            Start-Sleep -Milliseconds 250
            return
        }
        if ($bottom -gt 2300 -or $bottom - $top -lt 40) {
            Invoke-Adb shell input swipe 540 1800 540 1050 220 | Out-Null
        } else {
            Invoke-Adb shell input swipe 540 500 540 1200 220 | Out-Null
        }
        Start-Sleep -Milliseconds 250
        $node = if ($description) {
            Find-UiNode -Description $description -TimeoutSeconds 4
        } else {
            Find-UiNode -Text $nodeText -TimeoutSeconds 4
        }
        if ($null -eq $node) { continue }
    }
    throw "UI target never reached a safe tap area: desc=$description text=$nodeText"
}

function Scroll-ToTop {
    for ($index = 0; $index -lt 8; ++$index) {
        Invoke-Adb shell input swipe 540 450 540 1950 180 | Out-Null
    }
    Start-Sleep -Milliseconds 300
}

function Assert-Checked([string]$description, [bool]$expected, [switch]$Scroll) {
    $node = Assert-UiNode -Description $description -Scroll:$Scroll
    $actual = $node.GetAttribute('checked') -eq 'true'
    if ($actual -ne $expected) {
        throw "Unexpected checked state for ${description}: actual=$actual expected=$expected"
    }
}

function Enter-ExactText([string]$description, [string]$value) {
    $node = Assert-UiNode -Description $description
    Tap-UiNode $node
    for ($attempt = 0; $attempt -lt 4; ++$attempt) {
        # Select-all/delete is deterministic across IMEs.  Plain `input text`
        # may otherwise be consumed as pinyin by the user's current keyboard.
        Invoke-Adb shell input keycombination 113 29 | Out-Null # CTRL_LEFT + A
        Invoke-Adb shell input keyevent 67 | Out-Null           # DEL
        Invoke-Adb shell input text $value | Out-Null
        Start-Sleep -Milliseconds 250
        $node = Assert-UiNode -Description $description -TimeoutSeconds 3
        if ((Get-NodeText $node) -ceq $value) {
            Hide-SoftKeyboard
            return
        }
        Invoke-Adb shell input keyevent KEYCODE_LANGUAGE_SWITCH | Out-Null
        Start-Sleep -Milliseconds 250
    }
    throw "Unable to enter exact ASCII text into ${description}: '$(Get-NodeText $node)'"
}

function Save-Screen([string]$name) {
    $remote = "/sdcard/$name.png"
    Invoke-Adb shell screencap -p $remote | Out-Null
    Invoke-Adb pull $remote (Join-Path $OutputDirectory "$name.png") | Out-Null
    $xml = (Invoke-Adb exec-out cat /sdcard/rtgum-manager-ui.xml -AllowFailure).Text
    if ($xml) { [IO.File]::WriteAllText((Join-Path $OutputDirectory "$name.xml"), $xml) }
}

function Launch-Manager {
    Invoke-Adb shell am force-stop $managerPackage | Out-Null
    Dismiss-Keyguard
    $start = Invoke-Adb shell am start -W -n $managerComponent
    if ($start.Text -notmatch 'Status: ok') { throw "Manager launch failed: $($start.Text)" }
    Assert-UiNode -Description 'rtgum:title' -TimeoutSeconds 15 | Out-Null
}

function Select-FixtureModule {
    Scroll-ToTop
    Tap-UiNode (Assert-UiNode -Description 'rtgum:pick-module')
    Start-Sleep -Seconds 1
    $file = Find-UiNode -Text $fixtureName -TimeoutSeconds 3
    if ($null -eq $file) {
        $downloads = Find-UiNode -Text 'Downloads' -TimeoutSeconds 2
        if ($null -eq $downloads) { $downloads = Find-UiNode -Text '下载' -TimeoutSeconds 2 }
        if ($null -eq $downloads) {
            $roots = Find-UiNode -Description 'Show roots' -TimeoutSeconds 1
            if ($null -eq $roots) { $roots = Find-UiNode -Description '显示根目录' -TimeoutSeconds 1 }
            if ($null -ne $roots) {
                Tap-UiNode $roots
                $downloads = Find-UiNode -Text 'Downloads' -TimeoutSeconds 3
                if ($null -eq $downloads) { $downloads = Find-UiNode -Text '下载' -TimeoutSeconds 3 }
            }
        }
        if ($null -ne $downloads) {
            Tap-UiNode $downloads
            $file = Find-UiNode -Text $fixtureName -TimeoutSeconds 8
        }
    }
    if ($null -eq $file) { throw "DocumentsUI did not expose $fixtureName" }
    Tap-UiNode $file
    $selected = Assert-UiNode -Description 'rtgum:selected-module' -TimeoutSeconds 12 -Scroll
    if ((Get-NodeText $selected) -notmatch [regex]::Escape($fixtureName)) {
        throw "Selected module label is wrong: $(Get-NodeText $selected)"
    }
}

function Push-Verified([string]$local, [string]$remote) {
    Invoke-Adb push $local $remote | Out-Null
    $localHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $local).Hash.ToLowerInvariant()
    $remoteLine = (Invoke-Adb shell sha256sum $remote).Text
    $remoteHash = ($remoteLine -split '\s+')[0].ToLowerInvariant()
    if ($localHash -cne $remoteHash) {
        throw "SHA-256 mismatch for ${remote}: local=$localHash remote=$remoteHash"
    }
    Write-Output "sha256-ok remote=$remote hash=$localHash"
}

function Invoke-Ctl {
    param([string[]]$Arguments, [switch]$Session, [switch]$AllowFailure)
    $environment = @("RTGUM_SUPERKEY=$script:superKey")
    if ($Session) { $environment += "RTGUM_SESSION_KEY=$script:sessionKey" }
    $result = Invoke-Adb shell env @environment $remoteCtl @Arguments -AllowFailure:$AllowFailure
    if (-not $AllowFailure -and $result.ExitCode -ne 0) {
        throw "ctl failed ($($Arguments -join ' ')): $($result.Text)"
    }
    return $result
}

function Load-Kpm {
    Invoke-Adb shell "mkdir -p $remoteRoot" | Out-Null
    Push-Verified $CtlPath $remoteCtl
    Push-Verified $KpmPath $remoteKpm
    Invoke-Adb shell chmod 0755 $remoteCtl | Out-Null
    Invoke-Adb shell sync | Out-Null
    $ready = Invoke-Ctl -Arguments @('ready')
    if ($ready.Text -notmatch 'kpver=0xd09\b') {
        throw "Unexpected KernelPatch readiness: $($ready.Text)"
    }
    $info = Invoke-Ctl -Arguments @('info') -AllowFailure
    if ($info.ExitCode -eq 0) {
        throw 'rtgum-stage1 is already loaded; start this isolated UI run with -FreshBoot'
    }
    $load = Invoke-Ctl -Arguments @('load', $remoteKpm)
    if ($load.Text -notmatch 'loaded module=rtgum-stage1') {
        throw "KPM load was not confirmed: $($load.Text)"
    }
    $script:kpmLoadedByRun = $true
}

function Enroll-CtlSession {
    $enroll = Invoke-Ctl -Arguments @('session-manager')
    $match = [regex]::Match($enroll.Text, '(?:session(?:-key)?|key)=([0-9a-fA-F]{64})')
    if (-not $match.Success) { throw "Cannot enroll cleanup session: $($enroll.Text)" }
    $script:sessionKey = $match.Groups[1].Value
}

function Clear-And-UnloadKpm {
    if (-not $script:kpmLoadedByRun) { return }
    Invoke-Adb shell am force-stop $managerPackage -AllowFailure | Out-Null
    Enroll-CtlSession
    $cleared = $false
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        $control = "env RTGUM_SUPERKEY=$script:superKey RTGUM_SESSION_KEY=$script:sessionKey " +
            "$remoteCtl control 'daemon-config-clear 1'"
        $clear = Invoke-Adb shell $control -AllowFailure
        if ($clear.ExitCode -eq 0 -and $clear.Text -match '^ok\b') {
            $cleared = $true
            break
        }
        if ($clear.Text -notmatch 'code=-16|retry=1') {
            throw "KPM config cleanup failed: $($clear.Text)"
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $cleared) { throw 'KPM config cleanup timed out' }
    $unload = Invoke-Ctl -Arguments @('unload') -Session -AllowFailure
    if ($unload.ExitCode -ne 0 -or $unload.Text -notmatch 'unloaded module=rtgum-stage1') {
        throw "KPM unload failed: $($unload.Text)"
    }
    $script:kpmLoadedByRun = $false
}

function Wait-KernelSyncCount([int]$count) {
    Scroll-ToTop
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        $node = Find-UiNode -Description 'rtgum:kernel-status' -TimeoutSeconds 1
        if ($null -ne $node -and (Get-NodeText $node) -match "已同步\s+$count\s+条") { return }
        Start-Sleep -Milliseconds 250
    }
    $text = if ($null -ne $node) { Get-NodeText $node } else { '<missing>' }
    throw "KPM sync count did not reach ${count}: $text"
}

function Remove-FixtureThroughUi {
    Launch-Manager
    $delete = Find-UiNode -Description "rtgum:record:${fixturePackage}:delete" `
        -TimeoutSeconds 3 -Scroll
    if ($null -ne $delete) {
        Tap-UiNode $delete
        Start-Sleep -Milliseconds 800
        if ($null -ne (Find-UiNode -Description "rtgum:record:$fixturePackage" -TimeoutSeconds 1)) {
            throw 'Fixture record is still visible after delete'
        }
    }
}

$script:kpmLoadedByRun = $false
$runSucceeded = $false
try {
& $AdbPath start-server | Out-Null
if ($FreshBoot) { Start-FreshBoot } else { Wait-ForAndroid }
$script:initialImeSubtype = (Invoke-Adb shell settings get secure selected_input_method_subtype `
    -AllowFailure).Text
$fingerprint = (Invoke-Adb shell getprop ro.build.fingerprint).Text
if ($fingerprint -ne 'google/shiba/shiba:16/CP1A.260405.005/15001963:user/release-keys') {
    throw "Unexpected device build: $fingerprint"
}
$bootId = (Invoke-Adb shell cat /proc/sys/kernel/random/boot_id).Text
$script:superKey = [IO.File]::ReadAllText($superKeyFile).Trim()

$beforeVersion = Get-PackageVersion
$legacyXml = Read-PrivateFile 'shared_prefs/MainActivity.xml' -Optional
$namedXml = Read-PrivateFile 'shared_prefs/manager_state.xml' -Optional
$baselineRecords = if ($namedXml) {
    Read-RecordsFromPreferences $namedXml
} else {
    Read-RecordsFromPreferences $legacyXml
}
if (@($baselineRecords | Where-Object { $_.package -eq $fixturePackage }).Count -ne 0) {
    throw "Remove the previous UI fixture before running again: $fixturePackage"
}
$baselineEnabledCount = @($baselineRecords | Where-Object { [bool]$_.enabled }).Count
$backup = Backup-ManagerData ("before-v{0}" -f $beforeVersion.Code)
Write-Output "manager-before versionCode=$($beforeVersion.Code) versionName=$($beforeVersion.Name) records=$($baselineRecords.Count) backup=$backup"

$nextCode = $beforeVersion.Code + 1
$nextName = if ($nextCode -eq 2) { '0.2.0' } else { "0.2.$($nextCode - 2)" }
$apkName = "rtgum-manager-ui-v$nextCode.apk"
& $builder -OutputDirectory $OutputDirectory -VersionCode $nextCode `
    -VersionName $nextName -OutputApkName $apkName
if ($LASTEXITCODE -ne 0) { throw 'Manager APK build failed' }
$upgradeApk = Join-Path $OutputDirectory $apkName

$installedPath = ((Invoke-Adb shell pm path $managerPackage).Text -replace '^package:', '').Trim()
$installedApk = Join-Path $OutputDirectory "manager-installed-v$($beforeVersion.Code).apk"
Invoke-Adb pull $installedPath $installedApk | Out-Null
$apksigner = Get-ApkSigner
$oldSigner = Get-CertificateDigest $installedApk $apksigner
$newSigner = Get-CertificateDigest $upgradeApk $apksigner
if ($oldSigner -cne $newSigner) {
    throw "Refusing upgrade with a different signer: installed=$oldSigner new=$newSigner"
}

$install = Invoke-Adb install -r $upgradeApk
if ($install.Text -notmatch 'Success') { throw "Manager upgrade failed: $($install.Text)" }
$afterVersion = Get-PackageVersion
if ($afterVersion.Code -ne $nextCode -or $afterVersion.Name -ne $nextName) {
    throw "Unexpected upgraded version: $($afterVersion.Code)/$($afterVersion.Name)"
}

Launch-Manager
$blocked = Assert-UiNode -Description 'rtgum:permission-status-blocked' -TimeoutSeconds 15
if ((Get-NodeText $blocked) -notmatch '未就绪') {
    throw "Permission guidance is unclear: $(Get-NodeText $blocked)"
}
$filePermission = Assert-UiNode -Description 'rtgum:file-permission-status'
if ((Get-NodeText $filePermission) -notmatch '无需存储权限') {
    throw 'SAF permission guidance is absent'
}
foreach ($record in $baselineRecords) {
    $package = [string]$record.package
    Assert-UiNode -Description "rtgum:record:$package" -TimeoutSeconds 3 -Scroll | Out-Null
    Assert-Checked "rtgum:record:${package}:enabled" ([bool]$record.enabled) -Scroll
    Assert-Checked "rtgum:record:${package}:art-hook" ([bool]$record.art_hook) -Scroll
    Assert-Checked "rtgum:record:${package}:memory-access" ([bool]$record.memory_access) -Scroll
    Assert-Checked "rtgum:record:${package}:anti-debug" ([bool]$record.anti_debug) -Scroll
}
Scroll-ToTop
Save-Screen '01-permission-guidance'

$migratedXml = Read-PrivateFile 'shared_prefs/manager_state.xml'
$migratedRecords = Read-RecordsFromPreferences $migratedXml
if ($migratedRecords.Count -ne $baselineRecords.Count) {
    throw "Upgrade migration changed record count: before=$($baselineRecords.Count) after=$($migratedRecords.Count)"
}
foreach ($record in $baselineRecords) {
    Assert-RecordEquivalent $record $migratedRecords 'Migrated'
}
if ($migratedXml -notmatch '<int name="schema_version" value="2"') {
    throw 'Named Manager state does not contain schema_version=2'
}

Load-Kpm
Scroll-ToTop
Tap-UiNode (Assert-UiNode -Description 'rtgum:permission-retry')
$granted = Assert-UiNode -Description 'rtgum:permission-status-granted' -TimeoutSeconds 20
if ((Get-NodeText $granted) -notmatch '已授权') { throw 'KPM permission grant is not visible' }
$kernel = Assert-UiNode -Description 'rtgum:kernel-status'
if ((Get-NodeText $kernel) -notmatch '已连接 KPM') {
    throw "KPM synchronization failed: $(Get-NodeText $kernel)"
}
Save-Screen '02-kpm-authorized'

Push-Verified $ModulePath $remoteFixture
Invoke-Adb shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE `
    -d "file://$remoteFixture" | Out-Null
Scroll-ToTop
$packageInput = Assert-UiNode -Description 'rtgum:package-input'
Enter-ExactText 'rtgum:package-input' $fixturePackage
$packageInput = Assert-UiNode -Description 'rtgum:package-input' -TimeoutSeconds 3
if ((Get-NodeText $packageInput) -cne $fixturePackage) {
    throw "Package input did not receive exact text: '$(Get-NodeText $packageInput)'"
}
Select-FixtureModule
Scroll-ToTop
$packageInput = Assert-UiNode -Description 'rtgum:package-input' -TimeoutSeconds 3
if ((Get-NodeText $packageInput) -cne $fixturePackage) {
    throw "Package input changed after DocumentsUI: '$(Get-NodeText $packageInput)'"
}

foreach ($description in @('rtgum:new-art-hook', 'rtgum:new-memory-access', 'rtgum:new-anti-debug')) {
    $toggle = Assert-UiNode -Description $description -Scroll
    if ($toggle.GetAttribute('checked') -ne 'true') { Tap-UiNode $toggle }
    Assert-Checked $description $true -Scroll
}
$save = Assert-UiNode -Description 'rtgum:save-config' -Scroll
Tap-UiNode $save
$savedStatus = $null
for ($attempt = 0; $attempt -lt 20; ++$attempt) {
    $savedStatus = Find-UiNode -Description 'rtgum:operation-status' -TimeoutSeconds 1 -Scroll
    if ($null -ne $savedStatus -and (Get-NodeText $savedStatus) -match '配置已保存') { break }
    Start-Sleep -Milliseconds 250
}
if ($null -eq $savedStatus -or (Get-NodeText $savedStatus) -notmatch '配置已保存') {
    $statusText = if ($null -ne $savedStatus) { Get-NodeText $savedStatus } else { '<missing>' }
    throw "Save button did not complete: $statusText"
}
$fixture = Find-UiNode -Description "rtgum:record:$fixturePackage" -TimeoutSeconds 15 -Scroll
if ($null -eq $fixture) {
    $status = Find-UiNode -Description 'rtgum:operation-status' -TimeoutSeconds 3 -Scroll
    $statusText = if ($null -ne $status) { Get-NodeText $status } else { '<missing>' }
    throw "Manager did not save fixture; operation status: $statusText"
}
Assert-Checked "rtgum:record:${fixturePackage}:enabled" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:art-hook" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:memory-access" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:anti-debug" $true -Scroll
Wait-KernelSyncCount ($baselineEnabledCount + 1)
$kernel = Assert-UiNode -Description 'rtgum:kernel-status'
Save-Screen '03-fixture-saved'

Launch-Manager
Assert-UiNode -Description "rtgum:record:$fixturePackage" -TimeoutSeconds 12 -Scroll | Out-Null
Assert-Checked "rtgum:record:${fixturePackage}:enabled" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:art-hook" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:memory-access" $true -Scroll
Assert-Checked "rtgum:record:${fixturePackage}:anti-debug" $true -Scroll
Scroll-ToTop
Assert-UiNode -Description 'rtgum:permission-status-granted' -TimeoutSeconds 20 | Out-Null
Save-Screen '04-relaunch-persisted'

$finalXml = Read-PrivateFile 'shared_prefs/manager_state.xml'
$finalRecords = Read-RecordsFromPreferences $finalXml
$savedFixture = @($finalRecords | Where-Object { $_.package -eq $fixturePackage })
if ($savedFixture.Count -ne 1 -or -not $savedFixture[0].enabled -or
    -not $savedFixture[0].art_hook -or -not $savedFixture[0].memory_access -or
    -not $savedFixture[0].anti_debug) {
    throw 'Fixture state did not survive process restart'
}
$expectedModuleHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ModulePath).Hash.ToLowerInvariant()
if ([string]$savedFixture[0].sha256 -cne $expectedModuleHash) {
    throw 'Fixture module hash changed in Manager storage'
}

if (-not $KeepFixture) {
    Remove-FixtureThroughUi
    Start-Sleep -Seconds 1
    $cleanXml = Read-PrivateFile 'shared_prefs/manager_state.xml'
    $cleanRecords = Read-RecordsFromPreferences $cleanXml
    if (@($cleanRecords | Where-Object { $_.package -eq $fixturePackage }).Count -ne 0) {
        throw 'Fixture record remains in persistent state'
    }
    foreach ($record in $baselineRecords) {
        Assert-RecordEquivalent $record $cleanRecords 'Restored baseline'
    }
    Wait-KernelSyncCount $baselineEnabledCount
}

Clear-And-UnloadKpm
Invoke-Adb shell rm -f $remoteFixture -AllowFailure | Out-Null
$finalBootId = (Invoke-Adb shell cat /proc/sys/kernel/random/boot_id).Text
if ($finalBootId -ne $bootId) { throw 'Device rebooted during Manager UI automation' }
$crashLog = (Invoke-Adb logcat -b crash -d -t 200 -AllowFailure).Text
if ($crashLog -match 'FATAL EXCEPTION.*dev\.rtgum\.manager|Cmdline: dev\.rtgum\.manager') {
    throw 'Manager crash was found in the crash log'
}

Write-Output 'manager-ui-smoke PASS'
Write-Output "upgrade=$($beforeVersion.Code)/$($beforeVersion.Name)->$($afterVersion.Code)/$($afterVersion.Name) signer=$newSigner"
Write-Output "legacy-records=$($baselineRecords.Count) migration=schema-v2 permission=blocked->granted restart-persistence=pass kpm-sync=pass"
Write-Output "artifacts=$OutputDirectory"
$runSucceeded = $true
} finally {
    if ($script:initialImeSubtype -match '^-?\d+$') {
        Invoke-Adb shell settings put secure selected_input_method_subtype `
            $script:initialImeSubtype -AllowFailure | Out-Null
    }
    if (-not $runSucceeded) {
        if ($script:kpmLoadedByRun) {
            try { Clear-And-UnloadKpm } catch {
                Write-Warning "Automatic KPM cleanup failed: $($_.Exception.Message)"
            }
        }
        Invoke-Adb shell rm -f $remoteFixture -AllowFailure | Out-Null
    }
}
