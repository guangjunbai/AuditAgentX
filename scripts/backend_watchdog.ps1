param(
    [int]$IntervalSeconds = 10
)

$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $root 'data\runtime'
$stopFile = Join-Path $runtime 'backend-watchdog.stop'
$watchdogLog = Join-Path $runtime 'backend-watchdog.log'

New-Item -ItemType Directory -Force -Path $runtime | Out-Null
Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue

function Write-WatchdogLog([string]$Message) {
    Add-Content -LiteralPath $watchdogLog -Encoding UTF8 -Value (
        '{0:o} {1}' -f (Get-Date), $Message
    )
}

function Test-BackendHealth {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 `
            -Uri 'http://127.0.0.1:8000/health'
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Test-BackendListener {
    return $null -ne (Get-NetTCPConnection -State Listen -LocalPort 8000 `
        -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Start-StableBackend {
    $stdout = Join-Path $runtime 'backend.stdout.log'
    $stderr = Join-Path $runtime 'backend.stderr.log'
    $process = Start-Process -FilePath 'python.exe' `
        -ArgumentList @('-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000') `
        -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    Write-WatchdogLog "started stable backend pid=$($process.Id)"
}

Write-WatchdogLog "watchdog started pid=$PID interval=${IntervalSeconds}s"
while (-not (Test-Path -LiteralPath $stopFile)) {
    if (-not (Test-BackendHealth)) {
        if (Test-BackendListener) {
            Write-WatchdogLog 'health failed but port 8000 is still owned; preserving the active process'
        }
        else {
            Start-StableBackend
        }
    }
    Start-Sleep -Seconds ([Math]::Max(5, $IntervalSeconds))
}
Write-WatchdogLog 'watchdog stopped by stop file'
