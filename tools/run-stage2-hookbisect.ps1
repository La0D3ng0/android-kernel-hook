param(
    [int]$PauseSeconds = 30,
    [switch]$SkipBaseline,
    [switch]$PostBisect
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$keyFile = Join-Path $project "out\device\stage0-superkey.txt"
$sessFile = Join-Path $project "out\device\stage2-session-key.txt"
$streamFile = Join-Path $project "out\device\stage2-hookbisect-stream.txt"
$outFile = Join-Path $project "out\device\stage2-hookbisect-log.txt"

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss.fff"), $Message
    Add-Content -Path $outFile -Value $line
    Write-Host $line
}

function Test-DeviceAlive {
    param([int]$TimeoutMs = 15000)
    $tmp = Join-Path $env:TEMP "rtgum-alive-$PID.txt"
    $tmpErr = Join-Path $env:TEMP "rtgum-alive-$PID.err"
    Remove-Item $tmp, $tmpErr -ErrorAction SilentlyContinue
    $p = Start-Process -FilePath "adb" -ArgumentList @("shell", "echo alive") `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $tmp -RedirectStandardError $tmpErr
    if (-not $p.WaitForExit($TimeoutMs)) {
        $p.Kill()
        return $false
    }
    $content = ""
    if (Test-Path $tmp) { $content = (Get-Content $tmp -Raw) }
    return ($content -match "alive")
}

function Invoke-HookStep {
    param([string]$Name, [string]$Command, [int]$Pause)

    $key = (Get-Content $keyFile -Raw).Trim()
    $sess = (Get-Content $sessFile -Raw).Trim()
    $remote = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$sess /data/local/tmp/rtgum-stage1/rtgum-stage1-ctl control $Command"
    Write-Log "STEP $Name : ctl control $Command"
    $resp = adb shell $remote 2>&1
    Write-Log "STEP $Name : response=[$resp]"

    Write-Log "STEP $Name : pausing $Pause seconds"
    Start-Sleep -Seconds $Pause
    if (-not (Test-DeviceAlive)) {
        Write-Log "FREEZE AFTER: $Name"
        $tail = Get-Content $streamFile -Tail 8 -ErrorAction SilentlyContinue
        Write-Log "STREAM-TAIL:"
        foreach ($line in $tail) { Write-Log "  $line" }
        return $false
    }
    $key = (Get-Content $keyFile -Raw).Trim()
    $sess = (Get-Content $sessFile -Raw).Trim()
    $ping = adb shell "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$sess /data/local/tmp/rtgum-stage1/rtgum-stage1-ctl control ping" 2>&1
    Write-Log "STEP $Name : ping=[$ping]"
    return ($ping -match "pong")
}

Remove-Item $outFile -ErrorAction SilentlyContinue
Write-Log "hook-bisect start; stream=$streamFile"

$key = (Get-Content $keyFile -Raw).Trim()
$sess = (Get-Content $sessFile -Raw).Trim()
if (-not $SkipBaseline) {
    Write-Log "baseline: 20s idle wait"
    Start-Sleep -Seconds 20
    if (-not (Test-DeviceAlive)) {
        Write-Log "FREEZE DURING BASELINE"
        exit 2
    }
    Write-Log "baseline: alive"
}

$steps = @(
    @{ Name = "hook-comm";  Command = "hook-comm" },
    @{ Name = "hook-sysni"; Command = "hook-sysni" },
    @{ Name = "hook-poll";  Command = "hook-poll" },
    @{ Name = "hook-epoll"; Command = "hook-epoll" }
)

foreach ($step in $steps) {
    $ok = Invoke-HookStep -Name $step.Name -Command $step.Command -Pause $PauseSeconds
    if (-not $ok) {
        Write-Log "RESULT: freeze attributed to $($step.Name)"
        exit 1
    }
}

Write-Log "ALL FOUR HOOKS SURVIVED in isolation/sequence"
if ($PostBisect) {
    Write-Log "running stage2-bisect with hooks pre-armed"
    $remote = "RTGUM_SUPERKEY=$key RTGUM_SESSION_KEY=$sess /data/local/tmp/rtgum-stage1/rtgum-stage1-ctl stage2-bisect"
    $resp = adb shell $remote 2>&1
    Write-Log "stage2-bisect response=[$resp]"
    if (-not (Test-DeviceAlive)) {
        Write-Log "FREEZE AFTER: stage2-bisect (hooks+ghost-alloc+fread interaction)"
        exit 1
    }
    Write-Log "stage2-bisect survived"
}
Write-Log "RESULT: no freeze"
exit 0
