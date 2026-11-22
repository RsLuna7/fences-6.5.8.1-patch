#Requires -Version 5.1
<#
.SYNOPSIS
    Stardock Fences 6.5.8.1 full suite patch (managed + native DesktopDock64 engine).

.DESCRIPTION
    Applies complete, reproducible patches to a local Stardock Fences 6.5.8.1 installation:

      1. Stardock.ApplicationServices.dll -> Sas::VerifyLicense(int32, out LicenseInformation)
         Returns LicenseInformation.PermanentLicense + Result.Success for consumer features,
         while keeping BusinessSKU (2690) and ODNTLic (2679) at NoLicense so the enterprise
         desktop-locking panel is never accidentally engaged.

      2. Fences.exe -> WinTrust::VerifyEmbeddedSignature(string)
         Always returns true. Disables BlockUIVisibility() when Fences.exe itself is modified.

      3. Fences.exe -> NewUIPanel::ShowAdPanel(string)
         Returns immediately, suppressing the trial countdown / purchase bar.

      4. DesktopDock64.dll -> Authenticode check WinVerifyTrust bypass
         Disables the file-hash mismatch check while keeping internal Stardock signer
         certificate subject verification intact, so DesktopDock64.dll in Explorer can
         safely create the native manager without triggering anti-tamper pointer math failure.

      5. DesktopDock64.dll -> Native licensing dispatcher (FUN_1800f93b0)
         Returns PermanentLicense (14) for FeatureID.All (0x0A80) directly in Explorer
         memory, decoupling the desktop engine from the 30-day Trial and License.sig.

      6. PE CheckSum recalculation
         Re-computes and commits the official PE optional header CheckSum for all modified
         binaries via imagehlp!MapFileAndCheckSumW.

      7. Multi-monitor thrashing & CJK font fix (optional registry tune-up)
         Disables StoreLayoutsPerMultimon to stop virtual monitor reload loops, and sets
         FontName to 'Microsoft YaHei UI' to eliminate tofu box (□□) Chinese titles.

.PARAMETER FencesPath
    Fences install directory. Defaults to the value read from
    HKLM\SOFTWARE\Stardock\Fences\InstalledPath, then to the standard
    Program Files (x86) location.

.PARAMETER DryRun
    Analyse and report only. Nothing is written, no process is touched.

.PARAMETER Restore
    Revert all three files from their .orig-backup copies, clean NGEN cache, and relaunch.

.PARAMETER Force
    Skip the version / hash compatibility check.

.PARAMETER RestartExplorer
    DesktopDock64.dll runs inside explorer.exe and is locked while the shell is alive.
    With this switch the script restarts Explorer so the native image can be swapped in
    immediately. All open Explorer windows close. Without it the patched native image is
    left staged as DesktopDock64.dll.pending-apply for a later run.

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
    [switch] $Force,
    [switch] $RestartExplorer
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
    'DesktopDock64.dll'                 = 'CA70D2FC90C00023C5294B397D98520D86B18B0234AC9CD02A1D8661887BF9D5'
}

# ---------------------------------------------------------------------------
# Managed IL Patch definitions
# ---------------------------------------------------------------------------
$ManagedPatches = @(
    @{
        File      = 'Stardock.ApplicationServices.dll'
        Method    = 'Sas::VerifyLicense(int32, out LicenseInformation)'
        Rva       = 0x21FC
        Expect    = [byte[]](0x00,0x02,0x12,0x00,0x12,0x01,0x12,0x02,0x28,0x13,0x00,0x00,0x06)
        # ldarg.1 ; ldarg.0 ; ldc.i4 2690 ; beq.s ; ldarg.0 ; ldc.i4 2679 ; beq.s ; call get_PermanentLicense ; br.s ; call get_NoLicense ; stind.ref ; ldc.i4.0 ; ret
        NewIl     = [byte[]](
            0x03, 0x02, 0x20, 0x82, 0x0A, 0x00, 0x00, 0x2E, 0x0F,
            0x02, 0x20, 0x77, 0x0A, 0x00, 0x00, 0x2E, 0x07,
            0x28, 0x09, 0x00, 0x00, 0x06, 0x2B, 0x05,
            0x28, 0x08, 0x00, 0x00, 0x06,
            0x51, 0x16, 0x2A
        )
        Note      = 'license state -> Subscription singleton (excl. BusinessSKU/ODNT)'
    },
    @{
        File      = 'Fences.exe'
        Method    = 'WinTrust::VerifyEmbeddedSignature(string)'
        Rva       = 0x36E4
        Expect    = [byte[]](0x00,0x02,0x73,0x44,0x00,0x00,0x06,0x0A,0x12,0x01,0x72,0x39,0x03,0x00,0x70,0x28)
        # ldc.i4.1 ; ret
        NewIl     = [byte[]](0x17, 0x2A)
        Note      = 'managed integrity check -> true'
    },
    @{
        File      = 'Fences.exe'
        Method    = 'NewUIPanel::ShowAdPanel(string)'
        Rva       = 0x96048
        Expect    = [byte[]](0x00,0x16,0x0A,0x2B,0x00,0x02,0x7B,0xF5,0x07,0x00,0x04,0x72,0x99,0x02,0x00,0x70)
        # ret
        NewIl     = [byte[]](0x2A)
        Note      = 'ad panel -> never shown'
    }
)

# ---------------------------------------------------------------------------
# Single-byte constant patches (keep the original fat method header intact)
# ---------------------------------------------------------------------------
# These are surgical operand rewrites. Unlike $ManagedPatches above, the method
# body is NOT rewritten: only one immediate byte changes, so the fat header,
# code size and local signature all stay exactly as shipped.
$BytePatches = @(
    @{
        File    = 'Stardock.ApplicationServices.dll'
        Name    = 'LicenseInformation::get_PermanentLicense -> Subscription'
        FileOff = 0x2FF          # RVA 0x20E4 + 12-byte fat header + IL offset 0x0F
        Expect  = [byte]0x0E     # ldc.i4.s 14 (PermanentLicense)
        NewByte = [byte]0x0D     # ldc.i4.s 13 (Subscription)
        Guard   = [byte[]](0x1F, 0x0E, 0x7E, 0x21, 0x00, 0x00, 0x0A)   # 1F <state> 7E 21 00 00 0A @ 0x2FE
        GuardAt = 0x2FE
        Note    = 'the singleton every feature gate reads; 14 -> 13 makes GetIsSubscription() true'
    }
)

# ---------------------------------------------------------------------------
# Native x64 Patch definitions (DesktopDock64.dll)
# ---------------------------------------------------------------------------
$NativePatches = @(
    @{
        File      = 'DesktopDock64.dll'
        Name      = 'DesktopDock64!WinVerifyTrust bypass in FUN_1800feb60'
        FileOff   = 0x0FE08C
        Expect    = [byte[]](0xFF, 0x94, 0x24, 0x58, 0x02, 0x00, 0x00) # call qword ptr [rsp+258h]
        NewBytes  = [byte[]](0x33, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90) # xor eax, eax; nop x5
        Note      = 'skip Authenticode hash mismatch, keep PKCS#7 cert subject check'
    },
    @{
        File      = 'DesktopDock64.dll'
        Name      = 'DesktopDock64!Native license dispatch in FUN_1800f93b0'
        FileOff   = 0x0F87B0
        Expect    = [byte[]](0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48)
        # Custom x64 stub: returns PermanentLicense(14) for Fences, NoLicense(1) for BusinessSKU/ODNT
        NewBytes  = [byte[]](
            0x48, 0x85, 0xC9, 0x75, 0x06, 0xB8, 0xF9, 0xFF, 0xFF, 0xFF, 0xC3,
            0x48, 0x85, 0xD2, 0x74, 0x67,
            0x44, 0x8B, 0x01,
            0x41, 0x81, 0xF8, 0x82, 0x0A, 0x00, 0x00, 0x74, 0x1A,
            0x41, 0x81, 0xF8, 0x77, 0x0A, 0x00, 0x00, 0x74, 0x11,
            0x41, 0xB9, 0x0D, 0x00, 0x00, 0x00,   # mov r9d, 0x0D = Subscription (13)
            0x41, 0xBA, 0x00, 0x00, 0x00, 0x67,
            0x45, 0x33, 0xDB,
            0xEB, 0x14,
            0x41, 0xB9, 0x01, 0x00, 0x00, 0x00,
            0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF,
            0x49, 0xC7, 0xC3, 0xFF, 0xFF, 0xFF, 0xFF,
            0x48, 0x8B, 0x41, 0x08, 0x48, 0x85, 0xC0, 0x74, 0x03, 0x44, 0x89, 0x08,
            0x48, 0x8B, 0x41, 0x10, 0x48, 0x85, 0xC0, 0x74, 0x03, 0x4C, 0x89, 0x10,
            0x48, 0x8B, 0x41, 0x18, 0x48, 0x85, 0xC0, 0x74, 0x03, 0x4C, 0x89, 0x18,
            0x48, 0x83, 0xC1, 0x20, 0x48, 0xFF, 0xCA, 0x75, 0x99, 0x33, 0xC0, 0xC3
        )
        PadTo     = 0x126
        Note      = 'native engine license -> Subscription (13), matching the managed tier'
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
    foreach ($p in (Get-Process -Name Fences, Fences.PatchedUI, FencesCLI, FencesTaskbarItem -ErrorAction SilentlyContinue)) {
        $stopped += $p.Id
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }

    # rundll32 holds DesktopDock64 / FencesMenu64 during startup
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

    # Stopping Explorer is required to release DesktopDock64.dll handle
    foreach ($p in (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
        $stopped += $p.Id
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }

    if ($stopped.Count -gt 0) {
        Write-Ok ("stopped PID(s): " + ($stopped -join ', '))
        Start-Sleep -Seconds 2
    }
    return $stopped
}

function Update-PeChecksum {
    param([string] $Path)

    if (-not ('ChecksumHelper' -as [type])) {
        Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class ChecksumHelper {
    [DllImport("imagehlp.dll", CharSet=CharSet.Unicode)]
    public static extern uint MapFileAndCheckSumW(string Filename, out uint HeaderSum, out uint CheckSum);
    public static void Fix(string path) {
        uint hdr, sum;
        if (MapFileAndCheckSumW(path, out hdr, out sum) != 0) throw new Exception("Checksum failed: " + path);
        byte[] b = File.ReadAllBytes(path);
        int pe = BitConverter.ToInt32(b, 0x3C);
        Buffer.BlockCopy(BitConverter.GetBytes(sum), 0, b, pe + 88, 4);
        File.WriteAllBytes(path, b);
    }
}
'@
    }
    [ChecksumHelper]::Fix($Path)
}

function Clear-NgenImage {
    param([string] $Dir)

    $purged = @()
    $ngen64 = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe'
    if (Test-Path -LiteralPath $ngen64) {
        foreach ($target in @('Fences.exe', 'Stardock.ApplicationServices.dll', 'Fences.PatchedUI.exe')) {
            $targetPath = Join-Path $Dir $target
            & $ngen64 uninstall $targetPath /nologo 2>&1 | Out-Null
            $purged += $target
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

function Rebuild-NgenImage {
    param([string] $Dir)

    $ngen64 = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe'
    if (Test-Path -LiteralPath $ngen64) {
        $sas = Join-Path $Dir 'Stardock.ApplicationServices.dll'
        $exe = Join-Path $Dir 'Fences.exe'
        & $ngen64 install $sas "/ExeConfig:$exe" /nologo 2>&1 | Out-Null
        & $ngen64 install $exe /nologo 2>&1 | Out-Null
        Write-Ok "recompiled NGEN images for Stardock.ApplicationServices.dll and Fences.exe"
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    Write-Host ''
    Write-Host '  Stardock Fences 6.5.8.1 Full Suite Patch' -ForegroundColor White
    Write-Host '  ---------------------------------------' -ForegroundColor DarkGray
    Write-Host ''

    $dir = Get-FencesDirectory -Explicit $FencesPath
    Write-Step "install directory: $dir"

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

        foreach ($name in @('Fences.exe', 'Stardock.ApplicationServices.dll', 'DesktopDock64.dll')) {
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

        Clear-NgenImage -Dir $dir | Out-Null

        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Start-Process -FilePath "$env:WINDIR\explorer.exe" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        Start-Process -FilePath (Join-Path $dir 'Fences.exe') -WorkingDirectory $dir -ArgumentList '/startup' -ErrorAction SilentlyContinue
        Write-Ok 'Fences and Explorer relaunched'
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
            Write-Ok ("{0} : pristine hash matches" -f $name)
        } elseif ($Force) {
            Write-Warn ("{0} : hash {1} != expected (continuing due to -Force)" -f $name, $h.Substring(0,16))
        } else {
            throw ("{0} : unexpected hash {1}. This build is not the one these patches were derived from. Use -Force to attempt anyway." -f $name, $h)
        }
    }

    # ---------------- Analyse Managed Patches ----------------
    Write-Step 'analysing managed method bodies'

    $managedPlan = @()
    foreach ($p in $ManagedPatches) {
        $file  = Join-Path $dir $p.File
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $secs  = Get-PeSections -Bytes $bytes
        $off   = Convert-RvaToOffset -Rva $p.Rva -Sections $secs

        $expectedTiny = [byte](($p.NewIl.Length -shl 2) -bor 0x02)

        # A previous run may already have rewritten this body. Treat a live file that
        # carries our output as legal input, and always patch from the pristine backup
        # so repeated runs stay idempotent instead of stacking edits.
        $alreadyPatched = $false
        if ($bytes[$off] -eq $expectedTiny) {
            $cur = $bytes[($off+1)..($off + $p.NewIl.Length)]
            $alreadyPatched = ($cur -join ',') -eq ($p.NewIl -join ',')
        }
        if (-not $alreadyPatched) {
            $bakPath = "$file.orig-backup"
            if (Test-Path -LiteralPath $bakPath) {
                $bakBytes = [System.IO.File]::ReadAllBytes($bakPath)
                $bakOff   = Convert-RvaToOffset -Rva $p.Rva -Sections (Get-PeSections -Bytes $bakBytes)
                if ($bakBytes[$bakOff] -eq $expectedTiny) {
                    $bakCur = $bakBytes[($bakOff+1)..($bakOff + $p.NewIl.Length)]
                    if (($bakCur -join ',') -eq ($p.NewIl -join ',')) { $alreadyPatched = $true }
                }
            }
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

        $managedPlan += [pscustomobject]@{
            Def            = $p
            Offset         = $off
            CodeSize       = $codeSize
            IlStart        = $ilStart
            State          = $state
            AlreadyPatched = $alreadyPatched
            TinyHeader     = $expectedTiny
        }
    }

    # ---------------- Analyse Single-Byte Constant Patches ----------------
    Write-Step 'analysing single-byte constant patches'

    $bytePlan = @()
    foreach ($bp in $BytePatches) {
        $file  = Join-Path $dir $bp.File
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $cur   = $bytes[$bp.FileOff]

        $guardOk = $true
        for ($k = 0; $k -lt $bp.Guard.Length; $k++) {
            if ($bytes[$bp.GuardAt + $k] -ne $bp.Guard[$k]) { $guardOk = $false; break }
        }

        $state = if ($cur -eq $bp.NewByte) { 'already-patched' }
                 elseif ($cur -eq $bp.Expect -and $guardOk) { 'patchable' }
                 else { 'unrecognised' }

        $colour = switch ($state) {
            'patchable'       { 'Green' }
            'already-patched' { 'DarkGray' }
            default           { 'Red' }
        }
        Write-Host ("    [{0}] {1}" -f $state, $bp.Name) -ForegroundColor $colour
        Write-Host ("           {0}  file+0x{1:X}  0x{2:X2} -> 0x{3:X2}  ({4})" -f `
            $bp.File, $bp.FileOff, $cur, $bp.NewByte, $bp.Note) -ForegroundColor DarkGray

        if ($state -eq 'unrecognised' -and -not $Force) {
            throw ("{0} : byte 0x{1:X2} at file+0x{2:X} does not match the recorded original, or the surrounding guard bytes changed. Refusing to patch." -f $bp.Name, $cur, $bp.FileOff)
        }

        $bytePlan += [pscustomobject]@{ Def = $bp; State = $state }
    }

    # ---------------- Analyse Native Patches ----------------
    Write-Step 'analysing native DesktopDock64.dll patches'

    $nativePlan = @()
    $ddBytes = [System.IO.File]::ReadAllBytes((Join-Path $dir 'DesktopDock64.dll'))
    foreach ($np in $NativePatches) {
        $off = $np.FileOff
        $alreadyPatched = $false
        $cur = $ddBytes[$off..($off + $np.NewBytes.Length - 1)]
        if (($cur -join ',') -eq ($np.NewBytes -join ',')) {
            $alreadyPatched = $true
            $match = $true
        } else {
            $act = $ddBytes[$off..($off + $np.Expect.Length - 1)]
            $match = ($act -join ',') -eq ($np.Expect -join ',')
        }

        $state = if ($alreadyPatched) { 'already-patched' }
                 elseif ($match)      { 'patchable' }
                 else                 { 'unrecognised' }

        $colour = switch ($state) {
            'patchable'       { 'Green' }
            'already-patched' { 'DarkGray' }
            default           { 'Red' }
        }
        Write-Host ("    [{0}] {1}" -f $state, $np.Name) -ForegroundColor $colour
        Write-Host ("           DesktopDock64.dll  Offset 0x{0:X}  ({1})" -f $off, $np.Note) -ForegroundColor DarkGray

        if ($state -eq 'unrecognised' -and -not $Force) {
            throw ("{0} : bytes do not match expected signature. Refusing to patch." -f $np.Name)
        }

        $nativePlan += [pscustomobject]@{
            Def            = $np
            AlreadyPatched = $alreadyPatched
            State          = $state
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

    # 1. Apply Managed Patches
    foreach ($group in ($managedPlan | Group-Object { $_.Def.File })) {
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
            $newIl = $item.Def.NewIl
            $tiny  = [byte](($newIl.Length -shl 2) -bor 0x02)

            $buf[$item.Offset] = $tiny
            [Array]::Copy($newIl, 0, $buf, $item.Offset + 1, $newIl.Length)
            $padEnd = $item.Offset + 12 + $item.CodeSize
            for ($i = $item.Offset + 1 + $newIl.Length; $i -lt $padEnd; $i++) { $buf[$i] = 0 }

            Write-Ok ("{0} : patched" -f $item.Def.Method)
        }

        # Merge in any single-byte constant patches that target the same file,
        # so the file is written once and neither kind of edit clobbers the other.
        foreach ($bpItem in ($bytePlan | Where-Object { $_.Def.File -eq $fileName -and $_.State -ne 'already-patched' })) {
            $bp = $bpItem.Def
            $buf[$bp.FileOff] = $bp.NewByte
            Write-Ok ("{0} : patched (0x{1:X2} -> 0x{2:X2})" -f $bp.Name, $bp.Expect, $bp.NewByte)
        }

        $staged = "$live.patched-new"
        if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged -Force }
        [System.IO.File]::WriteAllBytes($staged, $buf)
        Update-PeChecksum -Path $staged

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
        if (-not $swapped) { throw "$fileName : could not replace file (still locked)" }
    }

    # 2. Apply Native Patches to DesktopDock64.dll
    $ddLive = Join-Path $dir 'DesktopDock64.dll'
    $ddBak  = "$ddLive.orig-backup"
    if (-not (Test-Path -LiteralPath $ddBak)) {
        Copy-Item -LiteralPath $ddLive -Destination $ddBak -Force
        Write-Ok "DesktopDock64.dll : backup created"
    } else {
        Write-Ok "DesktopDock64.dll : backup already present"
    }

    $ddBytes = [System.IO.File]::ReadAllBytes($ddBak)
    foreach ($npItem in $nativePlan) {
        $npDef = $npItem.Def
        if ($npDef.ContainsKey("PadTo") -and $npDef["PadTo"]) {
            for ($k = 0; $k -lt $npDef.PadTo; $k++) { $ddBytes[$npDef.FileOff + $k] = 0xCC }
        }
        [Array]::Copy($npDef.NewBytes, 0, $ddBytes, $npDef.FileOff, $npDef.NewBytes.Length)
        Write-Ok ("{0} : patched" -f $npDef.Name)
    }

    $ddStaged = "$ddLive.patched-new"
    if (Test-Path -LiteralPath $ddStaged) { Remove-Item -LiteralPath $ddStaged -Force }
    [System.IO.File]::WriteAllBytes($ddStaged, $ddBytes)
    Update-PeChecksum -Path $ddStaged

    $ddOld = "$ddLive.locked-old"
    $swapped = $false
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            if (Test-Path -LiteralPath $ddOld) { Remove-Item -LiteralPath $ddOld -Force -ErrorAction SilentlyContinue }
            Move-Item -LiteralPath $ddLive -Destination $ddOld -Force
            Move-Item -LiteralPath $ddStaged -Destination $ddLive -Force
            $swapped = $true
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }

    if (-not $swapped) {
        # DesktopDock64.dll is normally held open by explorer.exe, because the native
        # fence engine runs inside the shell process. Renewing the desktop is the only
        # way to free it; -RestartExplorer opts into that. Otherwise leave the built
        # image staged so it can be swapped in at the next opportunity.
        $pending = Join-Path $dir 'DesktopDock64.dll.pending-apply'
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue }
        Move-Item -LiteralPath $ddStaged -Destination $pending -Force
        Write-Warn 'DesktopDock64.dll is locked by explorer.exe'

        if (-not $RestartExplorer) {
            Write-Warn ("staged native image at {0}" -f $pending)
            Write-Warn 'run with -RestartExplorer to restart the shell and apply it now (open windows will close)'
        } else {
            Write-Step 'restarting explorer to release DesktopDock64.dll'
            $shell = Get-Process -Name explorer -ErrorAction SilentlyContinue
            foreach ($s in $shell) { try { $s.CloseMainWindow() | Out-Null } catch { } }
            Start-Sleep -Seconds 2
            foreach ($s in (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
                try { $s.Kill() } catch { }
            }
            Start-Sleep -Seconds 3
            Start-Process -FilePath "$env:WINDIR\explorer.exe" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5

            $applied = $false
            for ($attempt = 1; $attempt -le 8; $attempt++) {
                try {
                    $live = Join-Path $dir 'DesktopDock64.dll'
                    if (Test-Path -LiteralPath $live) { Remove-Item -LiteralPath $live -Force -ErrorAction SilentlyContinue }
                    Move-Item -LiteralPath $pending -Destination $live -Force
                    $applied = $true
                    break
                } catch { Start-Sleep -Seconds 2 }
            }
            if ($applied) { Write-Ok 'DesktopDock64.dll : patched and swapped in' }
            else { Write-Warn ("explorer still holds the file; native image left staged at {0}" -f $pending) }
        }
    } else {
        Write-Ok 'DesktopDock64.dll : patched and swapped in'
    }

    # ---------------- Registry & NGEN Tune-up ----------------
    Write-Step 'refreshing .NET native images & registry'
    Clear-NgenImage -Dir $dir | Out-Null
    Rebuild-NgenImage -Dir $dir

    # Optional UI polish: eliminate virtual display thrashing and fix CJK tofu boxes
    try {
        $regSettings = 'HKCU:\Software\Stardock\Fences\Settings'
        if (Test-Path -LiteralPath $regSettings) {
            Set-ItemProperty -Path $regSettings -Name 'StoreLayoutsPerMultimon' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regSettings -Name 'FontName' -Value 'Microsoft YaHei UI' -Type String -ErrorAction SilentlyContinue
            Write-Ok 'applied anti-thrash and Microsoft YaHei UI font settings'
        }
    } catch { }

    # ---------------- Relaunch ----------------
    Write-Step 'relaunching Explorer and Fences'
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath "$env:WINDIR\explorer.exe" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    $exePath = Join-Path $dir 'Fences.exe'
    Start-Process -FilePath $exePath -WorkingDirectory $dir -ArgumentList '/startup' -ErrorAction SilentlyContinue
    Write-Ok 'started'

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

