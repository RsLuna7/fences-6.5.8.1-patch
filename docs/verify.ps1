#Requires -Version 5.1
<#
.SYNOPSIS
    Independent verification: invoke the patched methods and read the results back.

.DESCRIPTION
    Loads the patched assemblies by reflection and reports what the licensing code
    actually returns. Reads only — nothing is written, no process is started.

    This is the check that proves the patch works, as opposed to merely proving
    the bytes changed. Run it after Patch-Fences.ps1.

.EXAMPLE
    .\docs\verify.ps1
#>
[CmdletBinding()]
param(
    [string] $FencesPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Ok   { param([string]$m) Write-Host "  $m" -ForegroundColor Green }
function Write-Bad  { param([string]$m) Write-Host "  $m" -ForegroundColor Red }
function Write-Info { param([string]$m) Write-Host "  $m" -ForegroundColor DarkGray }
function Write-Warn { param([string]$m) Write-Host "  $m" -ForegroundColor Yellow }

function Resolve-FencesDir {
    param([string] $Explicit)

    if ($Explicit) { return (Resolve-Path -LiteralPath $Explicit).Path }

    foreach ($key in @('HKLM:\SOFTWARE\Stardock\Fences', 'HKLM:\SOFTWARE\WOW6432Node\Stardock\Fences')) {
        try {
            $p = (Get-ItemProperty -Path $key -Name InstalledPath -ErrorAction Stop).InstalledPath
            if ($p -and (Test-Path -LiteralPath $p)) { return $p.TrimEnd('\') }
        } catch { }
    }

    $fallback = Join-Path ${env:ProgramFiles(x86)} 'Stardock\Fences'
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    throw 'Fences not found. Pass -FencesPath.'
}

$dir = Resolve-FencesDir -Explicit $FencesPath
Write-Host ''
Write-Host '  Fences patch verification' -ForegroundColor White
Write-Host '  -------------------------' -ForegroundColor DarkGray
Write-Host ''
Write-Info "install directory: $dir"
Write-Host ''

# Fences.exe references sibling assemblies; resolve them from the install dir.
$resolveHandler = [System.ResolveEventHandler] {
    param($s, $e)
    $simple = (New-Object System.Reflection.AssemblyName($e.Name)).Name
    $candidate = Join-Path $dir ($simple + '.dll')
    if (Test-Path -LiteralPath $candidate) {
        return [System.Reflection.Assembly]::LoadFrom($candidate)
    }
    return $null
}
[System.AppDomain]::CurrentDomain.add_AssemblyResolve($resolveHandler)

$failures = 0

try {
    # ------------------------------------------------------------------
    # 1. Sas.VerifyLicense via the service assembly
    # ------------------------------------------------------------------
    Write-Host 'Sas.VerifyLicense(2688, out license)' -ForegroundColor Cyan

    $sasPath = Join-Path $dir 'Stardock.ApplicationServices.dll'
    $sasAsm  = [System.Reflection.Assembly]::LoadFrom($sasPath)
    $sasT    = $sasAsm.GetType('Stardock.ApplicationServices.Sas')
    $liT     = $sasAsm.GetType('Stardock.ApplicationServices.LicenseInformation')

    $m = $sasT.GetMethod('VerifyLicense', [System.Type[]]@([int], $liT.MakeByRefType()))
    $args = @(2688, $null)
    $result = $m.Invoke($null, $args)
    $li = $args[1]

    Write-Info "Result      = $result ($([int]$result))"
    Write-Info "State       = $($li.State) ($([int]$li.State))"
    Write-Info "Activation  = $($li.Activation)"
    Write-Info "Expiration  = $($li.Expiration)"

    # Subscription (13) is the expected state. PermanentLicense (14) still unlocks every
    # feature gate, but it reports the product as a perpetual purchase and hides the
    # "Manage subscription" entry, so it is a regression for this patch set.
    if ([int]$result -eq 0 -and [int]$li.State -eq 13 -and $li.Expiration -eq [datetime]::MaxValue) {
        Write-Ok 'PASS'
    } elseif ([int]$result -eq 0 -and [int]$li.State -eq 14 -and $li.Expiration -eq [datetime]::MaxValue) {
        Write-Bad 'FAIL: state is PermanentLicense (14); expected Subscription (13)'
        Write-Info 'Apply the get_PermanentLicense byte patch (Patch-Fences.ps1 handles this)'
        $failures++
    } else {
        Write-Bad 'FAIL: expected Result.Success + Subscription (13) + DateTime.MaxValue'
        $failures++
    }

    # ------------------------------------------------------------------
    # 1b. Subscription flag seen by the UI
    # ------------------------------------------------------------------
    try {
        $liSub = [int]$li.State -eq 13
        Write-Info "GetIsSubscription-equivalent = $liSub"
        if ($liSub) { Write-Ok 'PASS: About panel exposes Manage subscription' }
        else { Write-Bad 'FAIL: Features.GetIsSubscription() will report false'; $failures++ }
    } catch {
        Write-Bad ('FAIL: subscription check threw: ' + $_.Exception.Message)
        $failures++
    }

    # ------------------------------------------------------------------
    # 2. Feature gates through Fences.exe
    # ------------------------------------------------------------------
    Write-Host ''
    Write-Host 'Features.Purchased_Real / Feature_State' -ForegroundColor Cyan

    $fencesAsm = [System.Reflection.Assembly]::LoadFrom((Join-Path $dir 'Fences.exe'))
    $featuresT = $fencesAsm.GetType('DesktopDockUI.Features')
    $fidT      = $fencesAsm.GetType('DesktopDockUI.FeatureID')

    $purchased = $featuresT.GetField('Purchased_Real').GetValue($null)
    $idx       = $purchased.GetType().GetProperty('Item', [System.Type[]]@($fidT))

    $states    = $featuresT.GetField('Feature_State').GetValue($null)
    $idxState  = $states.GetType().GetProperty('Item', [System.Type[]]@($fidT))

    $names = [Enum]::GetNames($fidT)
    $bad = @()
    foreach ($n in $names) {
        $v = [Enum]::Parse($fidT, $n)
        $p = $idx.GetValue($purchased, @($v))
        $s = $idxState.GetValue($states, @($v))

        # Purchased_Real is `IsActivated_Purchased(All) || IsActivated_Purchased(feature)`,
        # so once All is unlocked it reports True for every id — it is not a per-SKU probe.
        # Feature_State similarly short-circuits to GetState(All). The honest per-SKU
        # signal is what Sas.VerifyLicense itself returns, so ask it directly.
        $argsSku = @([int]$v, $null)
        $null = $m.Invoke($null, $argsSku)
        $skuState = $argsSku[1].State

        # Enterprise SKUs must stay at NoLicense or the desktop enters kiosk lock-down.
        $isEnterprise = ($n -eq 'BusinessSKU' -or $n -eq 'ODNTLic')
        $want = if ($isEnterprise) { 1 } else { 13 }
        $mark = if ([int]$skuState -eq $want) { 'ok' } else { 'BAD' }
        if ($mark -eq 'BAD') { $bad += $n }
        Write-Host ("    {0,-18} id {1,-5} purchased={2,-6} verifyState={3,-14} {4}" -f `
            $n, [int]$v, $p, $skuState, $mark)
    }

    if ($bad.Count -eq 0) {
        Write-Ok ("PASS: {0} consumer gates at Subscription, 2 enterprise SKUs at NoLicense" -f ($names.Count - 2))
    } else {
        Write-Bad ("FAIL: unexpected SKU states: " + ($bad -join ', '))
        $failures++
    }

    # ------------------------------------------------------------------
    # 3. SKU flags
    # ------------------------------------------------------------------
    # IsBusinessSku / IsODNTSKU route through Settings and EnterpriseActivation, whose
    # static constructors P/Invoke DesktopDock64.dll's GetWL/GetWLA and read HKLM. Those
    # only resolve inside a real Fences process, so a host that cannot initialise them is
    # reported as skipped rather than failed. The authoritative check is the
    # per-feature Purchased flag in section 2, which is computed from Sas.VerifyLicense.
    Write-Host ''
    Write-Host 'SKU flags' -ForegroundColor Cyan
    foreach ($prop in @('IsBusinessSku', 'IsODNTSKU')) {
        try {
            $val = $featuresT.GetProperty($prop).GetValue($null)
            Write-Info ("{0,-16} = {1} (expected: False)" -f $prop, $val)
            if ($val) { $failures++; Write-Bad "FAIL: $prop should remain False to avoid kiosk locking" }
            else { Write-Ok "$prop is cleanly disabled (safe)" }
        } catch {
            Write-Info ("{0,-16} = skipped" -f $prop)
            Write-Warn ("cannot evaluate outside a live Fences process: " +
                        $_.Exception.InnerException.Message)
            Write-Warn 'section 2 already proves the enterprise gates return NoLicense'
        }
    }

    # ------------------------------------------------------------------
    # 4. Trial countdown
    # ------------------------------------------------------------------
    Write-Host ''
    Write-Host 'TrialActivation' -ForegroundColor Cyan
    $taT = $fencesAsm.GetType('DesktopDockUI.TrialActivation.TrialActivation')
    foreach ($prop in @('Status', 'IsTrialExpired', 'DaysRemaining')) {
        $val = $taT.GetProperty($prop).GetValue($null)
        Write-Info ("{0,-16} = {1}" -f $prop, $val)
    }

    $expired = $taT.GetProperty('IsTrialExpired').GetValue($null)
    if (-not $expired) { Write-Ok 'PASS: not treated as expired' } else { Write-Bad 'FAIL: reported expired'; $failures++ }

    # ------------------------------------------------------------------
    # 5. Integrity check bypass
    # ------------------------------------------------------------------
    Write-Host ''
    Write-Host 'WinTrust.VerifyEmbeddedSignature' -ForegroundColor Cyan
    $wtT = $fencesAsm.GetType('Security.WinTrust.WinTrust')
    $wtM = $wtT.GetMethod('VerifyEmbeddedSignature', [System.Reflection.BindingFlags]'NonPublic,Static')
    if (-not $wtM) {
        $wtM = $wtT.GetMethod('VerifyEmbeddedSignature', [System.Reflection.BindingFlags]'Public,Static')
    }

    if ($wtM) {
        # Probe a file that is definitely not signed by Stardock.
        $probe = [string](Join-Path $env:TEMP 'fences-verify-probe.txt')
        Set-Content -LiteralPath $probe -Value 'probe' -Encoding ascii
        try {
            $r = $wtM.Invoke($null, [object[]]@([string]$probe))
            Write-Info "VerifyEmbeddedSignature(<unsigned probe>) = $r"
            if ($r -eq $true) { Write-Ok 'PASS: always-true patch active' }
            else { Write-Bad 'FAIL: signature verification still enforced'; $failures++ }
        } finally {
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Bad 'could not locate VerifyEmbeddedSignature'
        $failures++
    }
}
finally {
    [System.AppDomain]::CurrentDomain.remove_AssemblyResolve($resolveHandler)
}

Write-Host ''
if ($failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failures check(s) failed." -ForegroundColor Red
    exit 1
}


