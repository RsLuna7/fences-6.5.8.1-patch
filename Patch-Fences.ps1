#Requires -Version 5.1
<#
.SYNOPSIS
    Stardock Fences 6.5.8.1 license / ad-panel patch.

.DESCRIPTION
    Applies three IL patches to a local Stardock Fences 6.5.8.1 installation:

      1. Stardock.ApplicationServices.dll -> Sas::VerifyLicense(int32, out LicenseInformation)
         Returns LicenseInformation.PermanentLicense + Result.Success.

      2. Fences.exe -> WinTrust::VerifyEmbeddedSignature(string)
         Always returns true. Required because patching Fences.exe breaks its own
         Authenticode check, which otherwise fires BlockUIVisibility().

      3. Fences.exe -> NewUIPanel::ShowAdPanel(string)
         Returns immediately, so the trial/purchase bar never renders.

    Every patch is guarded: the script verifies the original IL bytes before writing,
    refuses to run on an unrecognised build, and keeps .orig-backup copies.

    A .NET NGEN native image (Fences.ni.exe) shadows the IL. The script purges it,
    otherwise the patches appear to have no effect.

.PARAMETER FencesPath
    Fences install directory. Defaults to the value read from
    HKLM\SOFTWARE\Stardock\Fences\InstalledPath, then to the standard
    Program Files (x86) location.

.PARAMETER DryRun
    Analyse and report only. Nothing is written, no process is touched.

.PARAMETER Restore
    Revert both files from their .orig-backup copies and purge the NGEN image.

.PARAMETER Force
    Skip the version / hash compatibility check.

.EXAMPLE
    .\Patch-Fences.ps1 -DryRun

.EXAMPLE
    .\Patch-Fences.ps1

.EXAMPLE
    .\Patch-Fences.ps1 -Restore
#>
[CmdletBinding()]
param(
    [string] $FencesPath,
    [switch] $DryRun,
    [switch] $Restore,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Target build fingerprint
# ---------------------------------------------------------------------------
$TargetVersion = '6.5.8.1'

$TargetHashes = @{
    'Fences.exe'                        = 'CE8BF948B70636844EA3245F33E29B1E9B837FE78547DEB45E9743F9A6D1A499'
    'Stardock.ApplicationServices.dll'  = '1A3DD0894A700397CE213911D8EFB2B993C6EB8A3BDAA8A37E00E93720538C80'
}

# ---------------------------------------------------------------------------
# Patch definitions
#
# Each entry names a method, its metadata RVA, and the exact original IL bytes
# that must be present at that body. `Expect` is a prefix check; the full body
# length comes from the fat method header.
# ---------------------------------------------------------------------------
$Patches = @(
    @{
        File      = 'Stardock.ApplicationServices.dll'
        Method    = 'Sas::VerifyLicense(int32, out LicenseInformation)'
        Rva       = 0x21FC
        Expect    = [byte[]](0x00,0x02,0x12,0x00,0x12,0x01,0x12,0x02,0x28,0x13,0x00,0x00,0x06)
        # ldarg.1 ; call LicenseInformation::get_PermanentLicense ; stind.ref ; ldc.i4.0 ; ret
        NewIl     = [byte[]](0x03, 0x28,0x09,0x00,0x00,0x06, 0x51, 0x16, 0x2A)
        Note      = 'license state -> PermanentLicense'
    },
    @{
        File      = 'Fences.exe'
        Method    = 'WinTrust::VerifyEmbeddedSignature(string)'
        Rva       = 0x36E4
        # nop ; ldarg.0 ; newobj WinTrustData::.ctor(string) ; stloc.0 ; ldloca.s 1 ; ldstr GUID
        Expect    = [byte[]](0x00,0x02,0x73,0x44,0x00,0x00,0x06,0x0A,0x12,0x01,0x72,0x39,0x03,0x00,0x70,0x28)
        # ldc.i4.1 ; ret
        NewIl     = [byte[]](0x17, 0x2A)
        Note      = 'integrity check -> true'
    },
    @{
        File      = 'Fences.exe'
        Method    = 'NewUIPanel::ShowAdPanel(string)'
        Rva       = 0x96048
        # nop ; ldc.i4.0 ; stloc.0 ; br.s ; ldarg.0 ; ldfld AdPanelBuySingleButtonTextOriginal
        Expect    = [byte[]](0x00,0x16,0x0A,0x2B,0x00,0x02,0x7B,0xF5,0x07,0x00,0x04,0x72,0x99,0x02,0x00,0x70)
        # ret
        NewIl     = [byte[]](0x2A)
        Note      = 'ad panel -> never shown'
    }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "    $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "    $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "    $m" -ForegroundColor Red }

function Get-FencesDirectory {
    param([string] $Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "Path not found: $Explicit" }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }

    foreach ($key in @('HKLM:\SOFTWARE\Stardock\Fences', 'HKLM:\SOFTWARE\WOW6432Node\Stardock\Fences')) {
        try {
            $p = (Get-ItemProperty -Path $key -Name InstalledPath -ErrorAction Stop).InstalledPath
            if ($p -and (Test-Path -LiteralPath $p)) { return $p.TrimEnd('\') }
        } catch { }
    }

    $fallback = Join-Path ${env:ProgramFiles(x86)} 'Stardock\Fences'
    if (Test-Path -LiteralPath $fallback) { return $fallback }

    throw 'Fences installation not found. Pass -FencesPath explicitly.'
}

function Get-PeSections {
    param([byte[]] $Bytes)

    $peOff   = [BitConverter]::ToInt32($Bytes, 0x3C)
    $numSec  = [BitConverter]::ToUInt16($Bytes, $peOff + 6)
    $optSize = [BitConverter]::ToUInt16($Bytes, $peOff + 20)
    $start   = $peOff + 24 + $optSize

    $list = @()
    for ($i = 0; $i -lt $numSec; $i++) {
        $o = $start + $i * 40
        $list += [pscustomobject]@{
            Name    = [System.Text.Encoding]::ASCII.GetString($Bytes, $o, 8).TrimEnd([char]0)
            VSize   = [BitConverter]::ToUInt32($Bytes, $o + 8)
            VAddr   = [BitConverter]::ToUInt32($Bytes, $o + 12)
            RawSize = [BitConverter]::ToUInt32($Bytes, $o + 16)
            RawPtr  = [BitConverter]::ToUInt32($Bytes, $o + 20)
        }
    }
    return $list
}

function Convert-RvaToOffset {
    param([uint32] $Rva, $Sections)

    foreach ($s in $Sections) {
        if ($Rva -ge $s.VAddr -and $Rva -lt ($s.VAddr + $s.VSize)) {
            return [int]($s.RawPtr + ($Rva - $s.VAddr))
        }
    }
    throw ('RVA 0x{0:X} is not mapped by any section' -f $Rva)
}

function Stop-FencesProcesses {
    param([string] $Dir)

    $stopped = @()
    foreach ($p in (Get-Process -Name Fences -ErrorAction SilentlyContinue)) {
        $stopped += $p.Id
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }

    # rundll32 also holds the install directory during startup
    foreach ($p in (Get-Process -Name rundll32 -ErrorAction SilentlyContinue)) {
        try {
            $hit = $false
            foreach ($m in $p.Modules) {
                if ($m.FileName -and $m.FileName.StartsWith($Dir, 'OrdinalIgnoreCase')) { $hit = $true; break }
            }
            if ($hit) {
                $stopped += $p.Id
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    if ($stopped.Count -gt 0) {
        Write-Ok ("stopped PID(s): " + ($stopped -join ', '))
        Start-Sleep -Seconds 2
    }
    return $stopped
}

function Clear-NgenImage {
    param([string] $ExePath)

    $purged = @()
    foreach ($ngen in @(
        'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe',
        'C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe'
    )) {
        if (Test-Path -LiteralPath $ngen) {
            $out = & $ngen uninstall $ExePath 2>&1 | Out-String
            if ($out -match 'Uninstalling') { $purged += $ngen }
        }
    }

    foreach ($d in @(
        'C:\Windows\assembly\NativeImages_v4.0.30319_64\Fences',
        'C:\Windows\assembly\NativeImages_v4.0.30319_32\Fences'
    )) {
        if (Test-Path -LiteralPath $d) {
            try { Remove-Item -LiteralPath $d -Recurse -Force; $purged += $d } catch { }
        }
    }
    return $purged
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    Write-Host ''
    Write-Host '  Stardock Fences license / ad-panel patch' -ForegroundColor White
    Write-Host '  ---------------------------------------' -ForegroundColor DarkGray
    Write-Host ''

    $dir = Get-FencesDirectory -Explicit $FencesPath
    Write-Step "install directory: $dir"

    # Probe actual write access instead of assuming elevation is required: a
    # user-writable install directory (or a -FencesPath copy) needs no elevation.
    if (-not $DryRun) {
        $probe = Join-Path $dir '.write-probe.tmp'
        try {
            [System.IO.File]::WriteAllText($probe, 'x')
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        } catch {
            throw "Cannot write to '$dir'. Re-run from an elevated shell, or pass -FencesPath pointing at a writable copy."
        }
    }

    # ---------------- Restore mode ----------------
    if ($Restore) {
        Write-Step 'restore mode'

        Stop-FencesProcesses -Dir $dir | Out-Null

        foreach ($name in @('Fences.exe', 'Stardock.ApplicationServices.dll')) {
            $live = Join-Path $dir $name
            $bak  = "$live.orig-backup"

            if (-not (Test-Path -LiteralPath $bak)) {
                Write-Warn "$name : no .orig-backup present, skipped"
                continue
            }

            $stash = "$live.restoring"
            if (Test-Path -LiteralPath $stash) { Remove-Item -LiteralPath $stash -Force -ErrorAction SilentlyContinue }

            Move-Item -LiteralPath $live -Destination $stash -Force -ErrorAction SilentlyContinue
            Copy-Item -LiteralPath $bak -Destination $live -Force

            $h = (Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash
            if ($TargetHashes.ContainsKey($name) -and $h -ne $TargetHashes[$name]) {
                Write-Warn "$name : restored hash differs from the recorded original"
            } else {
                Write-Ok "$name : restored"
            }
        }

        $restorePurged = @(Clear-NgenImage -ExePath (Join-Path $dir 'Fences.exe'))
        foreach ($x in $restorePurged) { Write-Ok "purged NGEN: $x" }

        Start-Process -FilePath (Join-Path $dir 'Fences.exe') -WorkingDirectory $dir -ErrorAction SilentlyContinue
        Write-Ok 'Fences relaunched'
        Write-Host ''
        Write-Host 'Restore complete.' -ForegroundColor Green
        exit 0
    }

    # ---------------- Compatibility check ----------------
    Write-Step 'checking build fingerprint'

    $versionFile = Join-Path $dir 'FencesVersion.txt'
    if (Test-Path -LiteralPath $versionFile) {
        $installed = (Get-Content -LiteralPath $versionFile -Raw).Trim()
        if ($installed -ne $TargetVersion) {
            $msg = "installed version is $installed, patches target $TargetVersion"
            if ($Force) { Write-Warn "$msg (continuing due to -Force)" }
            else { throw "$msg. Use -Force to attempt anyway." }
        } else {
            Write-Ok "version $installed"
        }
    }

    foreach ($name in $TargetHashes.Keys) {
        $f = Join-Path $dir $name
        if (-not (Test-Path -LiteralPath $f)) { throw "missing file: $f" }

        $bak = "$f.orig-backup"
        $probe = if (Test-Path -LiteralPath $bak) { $bak } else { $f }
        $h = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash

        if ($h -eq $TargetHashes[$name]) {
            Write-Ok ("{0} : hash matches" -f $name)
        } elseif ($Force) {
            Write-Warn ("{0} : hash {1} != expected (continuing due to -Force)" -f $name, $h.Substring(0,16))
        } else {
            throw ("{0} : unexpected hash {1}. This build is not the one these patches were derived from. Use -Force to attempt anyway." -f $name, $h)
        }
    }

    # ---------------- Analyse every patch ----------------
    Write-Step 'analysing method bodies'

    $plan = @()
    foreach ($p in $Patches) {
        $file = Join-Path $dir $p.File
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $secs  = Get-PeSections -Bytes $bytes
        $off   = Convert-RvaToOffset -Rva $p.Rva -Sections $secs

        $expectedTiny = [byte](($p.NewIl.Length -shl 2) -bor 0x02)

        # Detect an already-patched body first: the patch converts the fat header
        # into a tiny one, so the fat-header check below would otherwise reject it.
        $alreadyPatched = $false
        if ($bytes[$off] -eq $expectedTiny) {
            $cur = $bytes[($off+1)..($off + $p.NewIl.Length)]
            $alreadyPatched = ($cur -join ',') -eq ($p.NewIl -join ',')
        }

        if ($alreadyPatched) {
            $codeSize = $p.NewIl.Length
            $ilStart  = $off + 1
            $match    = $true
        } else {
            $flags = [BitConverter]::ToUInt16($bytes, $off)
            if (($flags -band 0x3) -ne 0x3) {
                throw ("{0} : method at RVA 0x{1:X} does not use a fat header and does not carry the expected patch" -f $p.Method, $p.Rva)
            }
            $codeSize = [BitConverter]::ToUInt32($bytes, $off + 4)
            $ilStart  = $off + 12

            $actual = $bytes[$ilStart..($ilStart + $p.Expect.Length - 1)]
            $match  = ($actual -join ',') -eq ($p.Expect -join ',')
        }

        $state = if ($alreadyPatched) { 'already-patched' }
                 elseif ($match)      { 'patchable' }
                 else                 { 'unrecognised' }

        $colour = switch ($state) {
            'patchable'       { 'Green' }
            'already-patched' { 'DarkGray' }
            default           { 'Red' }
        }
        Write-Host ("    [{0}] {1}" -f $state, $p.Method) -ForegroundColor $colour
        Write-Host ("           {0}  RVA 0x{1:X}  body 0x{2:X}  {3} bytes  ({4})" -f `
            $p.File, $p.Rva, $off, $codeSize, $p.Note) -ForegroundColor DarkGray

        if ($state -eq 'unrecognised' -and -not $Force) {
            throw ("{0} : IL does not match the recorded original. Refusing to patch." -f $p.Method)
        }

        $plan += [pscustomobject]@{
            Def            = $p
            Offset         = $off
            CodeSize       = $codeSize
            IlStart        = $ilStart
            State          = $state
            AlreadyPatched = $alreadyPatched
            TinyHeader     = $expectedTiny
        }
    }

    if ($DryRun) {
        Write-Host ''
        Write-Host 'Dry run: nothing was modified.' -ForegroundColor Yellow
        exit 0
    }

    # ---------------- Apply ----------------
    Write-Step 'applying patches'

    Stop-FencesProcesses -Dir $dir | Out-Null

    $touchedFiles = @()
    foreach ($group in ($plan | Group-Object { $_.Def.File })) {
        $fileName = $group.Name
        $live     = Join-Path $dir $fileName
        $bak      = "$live.orig-backup"

        if (-not (Test-Path -LiteralPath $bak)) {
            Copy-Item -LiteralPath $live -Destination $bak -Force
            Write-Ok "$fileName : backup created"
        } else {
            Write-Ok "$fileName : backup already present"
        }

        $bytes = [System.IO.File]::ReadAllBytes($bak)
        $buf   = New-Object byte[] $bytes.Length
        [Array]::Copy($bytes, 0, $buf, 0, $bytes.Length)

        foreach ($item in $group.Group) {
            if ($item.AlreadyPatched) {
                Write-Ok ("{0} : already patched, skipped" -f $item.Def.Method)
                continue
            }

            $newIl = $item.Def.NewIl
            $tiny  = [byte](($newIl.Length -shl 2) -bor 0x02)

            # fat header (12 bytes) + body  ->  tiny header (1 byte) + new body + zero padding
            $buf[$item.Offset] = $tiny
            [Array]::Copy($newIl, 0, $buf, $item.Offset + 1, $newIl.Length)
            $padEnd = $item.Offset + 12 + $item.CodeSize
            for ($i = $item.Offset + 1 + $newIl.Length; $i -lt $padEnd; $i++) { $buf[$i] = 0 }

            Write-Ok ("{0} : patched" -f $item.Def.Method)
        }

        # stage then swap, because a mapped file cannot be overwritten in place
        $staged = "$live.patched-new"
        if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged -Force }
        [System.IO.File]::WriteAllBytes($staged, $buf)

        $old = "$live.locked-old"
        $swapped = $false
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            try {
                if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue }
                Move-Item -LiteralPath $live -Destination $old -Force
                Move-Item -LiteralPath $staged -Destination $live -Force
                $swapped = $true
                break
            } catch {
                Start-Sleep -Seconds 2
            }
        }
        if (-not $swapped) { throw "$fileName : could not replace the file (still locked)" }

        $touchedFiles += $fileName
    }

    # ---------------- NGEN ----------------
    Write-Step 'purging .NET native images'

    $exePath = Join-Path $dir 'Fences.exe'
    $purged  = @(Clear-NgenImage -ExePath $exePath)
    if ($purged.Count -eq 0) {
        Write-Ok 'nothing to purge'
    } else {
        foreach ($x in $purged) { Write-Ok "removed $x" }
    }

    # ---------------- Verify ----------------
    Write-Step 'verifying'

    foreach ($item in $plan) {
        $file  = Join-Path $dir $item.Def.File
        $bytes = [System.IO.File]::ReadAllBytes($file)

        # After patching, every body is tiny-header + new IL, regardless of whether
        # this run wrote it or a previous one did.
        $hdrOk = $bytes[$item.Offset] -eq $item.TinyHeader
        $cur   = $bytes[($item.Offset+1)..($item.Offset + $item.Def.NewIl.Length)]
        $ilOk  = ($cur -join ',') -eq ($item.Def.NewIl -join ',')

        if ($hdrOk -and $ilOk) {
            Write-Ok ("{0} : ok" -f $item.Def.Method)
        } else {
            Write-Fail ("{0} : verification failed (header={1} il={2})" -f $item.Def.Method, $hdrOk, $ilOk)
        }
    }

    # ---------------- Relaunch ----------------
    $exePath = Join-Path $dir 'Fences.exe'
    if (Test-Path -LiteralPath $exePath) {
        Write-Step 'relaunching Fences'
        Start-Process -FilePath $exePath -WorkingDirectory $dir -ErrorAction SilentlyContinue
        Write-Ok 'started'
    } else {
        Write-Warn 'Fences.exe not present in target directory, nothing to relaunch'
    }

    Write-Host ''
    Write-Host 'Done.' -ForegroundColor Green
    Write-Host 'Backups: *.orig-backup next to each patched file. Run with -Restore to revert.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0
}
catch {
    Write-Host ''
    Write-Fail ("FAILED: " + $_.Exception.Message)
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    exit 1
}
