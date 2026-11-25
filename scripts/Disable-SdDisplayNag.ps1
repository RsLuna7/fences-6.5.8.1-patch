#Requires -Version 5.1
<#
    Stop the recurring "Fences 6 license not found" popup.   (permanent option)

    Root cause
    ----------
    Stardock Application Services (SAS 2.11.3.4644) ships SdDisplay.exe as its
    activation / marketing UI host. The SAS scheduler lives inside
    SdAppServices_x64.dll, loaded into explorer.exe and Fences.exe, and owns the
    UiTask / ValidateLicenseTask timers. About every 30 minutes it launches:

        SdDisplay.exe -prodId=2688 -ProdName=Fences6 -company=Stardock
                      -prodVer=6.5.8.1 -startUi=1 -parentPid=<pid>

    Because %ProgramData%\Stardock\Fences6\License.sig is absent (the patch flow
    renamed it to License.sig.disabled, whose payload is an expired Trial), the
    native layer resolves LicenseState = NoLicense and SdDisplay renders the
    "no license found / Buy / Enter product key" panel.

    See docs/sas-display-nag.md for the full analysis.

    Fix
    ---
    Rename the UI host so SAS's ShowUI cannot start it. SAS logs
    "[ShowUI] Unable to run process" and returns; no window is created.
    Fences.exe never needs SdDisplay.exe - it is purely the activation surface.

    This file is ASCII-only on purpose: Windows PowerShell 5.1 decodes BOM-less
    UTF-8 as ANSI, and non-ASCII text corrupts the token stream.
#>
[CmdletBinding()]
param(
    [switch] $Restore,
    [switch] $WhatIf
)

$ErrorActionPreference = 'Stop'

$dir    = [Environment]::ExpandEnvironmentVariables('%ProgramFiles(x86)%\Stardock\Fences')
$target = Join-Path $dir 'SdDisplay.exe'
$stash  = Join-Path $dir 'SdDisplay.exe.disabled'

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'This script must run elevated (it writes into Program Files).' 'Red'
    exit 1
}

if ($Restore) {
    if (Test-Path $stash) {
        if (-not $WhatIf) { Move-Item -LiteralPath $stash -Destination $target -Force }
        Say "restored: $target" 'Green'
    } else {
        Say 'nothing to restore (no SdDisplay.exe.disabled present)' 'Yellow'
    }
    exit 0
}

# Kill any instance that is up right now so the popup disappears immediately.
Get-Process -Name SdDisplay -ErrorAction SilentlyContinue | ForEach-Object {
    Say "stopping running SdDisplay PID $($_.Id)"
    if (-not $WhatIf) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
}

if (Test-Path $target) {
    if ($WhatIf) {
        Say "would rename: $target  ->  $stash"
    } else {
        Move-Item -LiteralPath $target -Destination $stash -Force
        Say "disabled: $stash" 'Green'
    }
} elseif (Test-Path $stash) {
    Say 'already disabled' 'Green'
} else {
    Say "SdDisplay.exe not found under $dir" 'Yellow'
    exit 2
}

if (Test-Path $target) {
    Say 'WARNING: SdDisplay.exe is still present' 'Red'
    exit 3
}

Say 'verified: the ShowUI launch path is gone' 'Green'
Say ''
Say 'Undo with:  Disable-SdDisplayNag.ps1 -Restore' 'DarkGray'
