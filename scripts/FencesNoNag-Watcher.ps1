#Requires -Version 5.1
<#
    Fences 6 "license not found" popup suppressor.   (no admin required)

    Root cause
    ----------
    Stardock Application Services (SAS 2.11.3.4644) keeps its scheduler inside
    explorer.exe and Fences.exe. Roughly every 30 minutes a UiTask or
    ValidateLicenseTask fires and launches the activation UI host:

        SdDisplay.exe -prodId=2688 -ProdName=Fences6 -company=Stardock
                      -prodVer=6.5.8.1 -startUi=1 -parentPid=<pid>

    Because %ProgramData%\Stardock\Fences6\License.sig is absent (renamed to
    License.sig.disabled, holding a Trial signature that has expired) the native
    layer resolves LicenseState = NoLicense and SdDisplay renders the
    "no license found / Buy / Enter product key" panel.

    See docs/sas-display-nag.md for the string offsets, log cadence and why the
    managed/native patches in this repository cannot suppress it.

    Fix
    ---
    Poll for SdDisplay.exe and kill it immediately, so the window never finishes
    drawing. Only SdDisplay.exe is targeted - Fences.exe, DesktopDock64.dll and
    explorer.exe are never touched, so desktop fences keep working normally.

    For the admin-required permanent alternative, see Disable-SdDisplayNag.ps1.

    This file is ASCII-only on purpose: Windows PowerShell 5.1 decodes BOM-less
    UTF-8 as ANSI, and non-ASCII text corrupts the token stream (the parser then
    reports a bogus "catch block must be the last" error).
#>
[CmdletBinding()]
param(
    [int] $PollMs = 250
)

$ErrorActionPreference = 'SilentlyContinue'

# --- single instance: an autostart task and a Startup shortcut may both point here ---
$mutex = $null
try {
    $mutex = New-Object System.Threading.Mutex($false, 'Global\FencesNoNagWatcher')
    if (-not $mutex.WaitOne(0)) {
        exit 0
    }
} catch {
    try {
        $mutex = New-Object System.Threading.Mutex($false, 'Local\FencesNoNagWatcher')
        if (-not $mutex.WaitOne(0)) {
            exit 0
        }
    } catch {
        $mutex = $null
    }
}

$logDir = Join-Path $env:LOCALAPPDATA 'FencesNoNag'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$log = Join-Path $logDir 'watcher.log'

# rotate at 1 MB so the file cannot grow without bound
if ((Test-Path $log) -and ((Get-Item $log).Length -gt 1MB)) {
    Move-Item -LiteralPath $log -Destination "$log.old" -Force
}

function Note($m) {
    $line = '{0:o}  {1}' -f (Get-Date), $m
    Add-Content -LiteralPath $log -Value $line -Encoding utf8
}

Note "watcher start (pid $PID, poll ${PollMs}ms)"

try {
    while ($true) {
        $procs = [System.Diagnostics.Process]::GetProcessesByName('SdDisplay')
        foreach ($p in $procs) {
            $procId = $p.Id
            try {
                $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue).CommandLine
                $p.Kill()
                # Give the kernel a moment, then confirm it is really gone.
                $p.WaitForExit(1500) | Out-Null
                if (-not $p.HasExited) {
                    throw 'still alive after Kill()'
                }
                Note "killed pid $procId :: $cmd"
            } catch {
                # Fallback: taskkill reaches processes Kill() refused to touch.
                # The process is hit ~250ms after launch, while it is still
                # initialising, and its handle can be protected.
                & "$env:WINDIR\System32\taskkill.exe" /f /pid $procId 2>&1 | Out-Null
                Start-Sleep -Milliseconds 100
                $still = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($still) {
                    try {
                        & "$env:WINDIR\System32\taskkill.exe" /f /t /pid $procId 2>&1 | Out-Null
                    } catch {
                        $null = $_
                    }
                    $still = Get-Process -Id $procId -ErrorAction SilentlyContinue
                }
                if ($still) {
                    Note "KILL FAILED pid $procId : $($_.Exception.Message)"
                } else {
                    Note "killed pid $procId via taskkill"
                }
            } finally {
                try {
                    $p.Dispose()
                } catch {
                    $null = $_
                }
            }
        }
        Start-Sleep -Milliseconds $PollMs
    }
} finally {
    try {
        if ($null -ne $mutex) {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }
    } catch {
        $null = $_
    }
}
