# Fences 6.5.8.1 — Full-Suite Patch Archive (Managed + Native Desktop Engine)

A reproducible patch archive for **Stardock Fences 6.5.8.1**.

The goal: on any machine running Fences 6.5.8.1, run one script, and trial limitations are permanently lifted across both the managed UI (`Fences.exe` / `Stardock.ApplicationServices.dll`) and the native desktop engine (`DesktopDock64.dll` inside `explorer.exe`), while avoiding enterprise kiosk locks, multi-monitor reload loops, and CJK font corruption.

> **Status:** verified against the shipped build
> `Fences 6.5.8.1` (`FencesVersion.txt`), on Windows 11 26200 x64.
> Backups and a one-command restore are built in.

---

## What it does

Fences 6.5.8.1 enforces licensing and integrity across two distinct execution tiers:

1. **Managed .NET UI Tier** (`Fences.exe` + `Stardock.ApplicationServices.dll`)
2. **Native Explorer Desktop Tier** (`DesktopDock64.dll` loaded directly inside `explorer.exe`)

Targeting only the managed assembly leaves the native desktop engine constrained to a 30-day trial and trips native Authenticode integrity checks. This repository applies an orchestrated patch covering both tiers:

| # | Tier | Binary | Target / Function | Effect |
|---|------|--------|-------------------|--------|
| 1 | Managed | `Stardock.ApplicationServices.dll` | `Sas::VerifyLicense(int32, out LicenseInformation)` | Returns `PermanentLicense (14)` + `Result.Success (0)` for consumer features. Excludes `BusinessSKU (2690)` and `ODNTLic (2679)` to prevent accidental enterprise desktop-locking. |
| 2 | Managed | `Fences.exe` | `WinTrust::VerifyEmbeddedSignature(string)` | Returns `true`. Disables `BlockUIVisibility()` 500ms timer when `Fences.exe` is modified. |
| 3 | Managed | `Fences.exe` | `NewUIPanel::ShowAdPanel(string)` | Returns immediately — suppresses the trial countdown and purchase banner. |
| 4 | Native | `DesktopDock64.dll` | `FUN_1800feb60` (`FileOff 0x0FE08C`) | Bypasses `WinVerifyTrust` file-hash comparison (`xor eax, eax; nop x5`) while preserving PKCS#7 certificate subject decoding and anti-tamper pointer math (`DAT_180745dd0`). |
| 5 | Native | `DesktopDock64.dll` | `FUN_1800f93b0` (`FileOff 0x0F87B0`) | Dispatches `LicenseState = 14 (PermanentLicense)` directly inside `explorer.exe` memory, liberating the native fence manager from `License.sig`. |
| 6 | PE Header | All modified binaries | Optional Header CheckSum | Re-calculates and commits valid PE CheckSums via `imagehlp!MapFileAndCheckSumW`. |
| 7 | Settings | Registry HKCU | `Settings\StoreLayoutsPerMultimon` & `FontName` | Disables multi-monitor profile thrashing (`DISPLAY1` ↔ `DISPLAY5` loop) and configures `Microsoft YaHei UI` to eliminate CJK tofu box (`□□`) titles. |

---

## Critical Architecture Traps Solved

### 1. Native Authenticode Pointer Math Trap in `DesktopDock64.dll`
Before instantiating the desktop fence manager (`FUN_1801e04f0`), `DesktopDock64.dll` executes an anti-tamper sequence (`FUN_180112f60`):
- It subtracts `0xFA0` (4000) from `hwndListView`.
- It executes 11 verification rounds against internal components, adding varying values (`+400`, `+2800`, `+200`, `+200`, `+400`) depending on exact `FUN_1800feb60` return values.
- If `FUN_1800feb60` is coarsely patched to return `1` unconditionally, inverted checks (`DAT_180745dd0 == 1`) fail to evaluate, the pointer delta never equals `+4000`, `IsWindow` fails, and the native manager pointer (`DesktopDock64.dll+0x74b1a8`) stays `0` — **rendering zero fences on the desktop**.
- **Solution:** A surgical 7-byte bypass at `RVA 0x0FEC8C` (`FileOff 0x0FE08C`) that bypasses only the `WinVerifyTrust` API call, allowing valid PKCS#7 certificate subject checks and arithmetic adjustments to succeed naturally.

### 2. The BusinessSKU Desktop Lockdown Trap
Unconditionally returning `PermanentLicense` for all feature IDs sets `Features.IsBusinessSku = true`. This exposes the enterprise deployment panel (`FeaturesDeployments2`) and engages Windows desktop locked modes (`DesktopLockedFlags`), restricting icon dragging, desktop right-clicking, and fence repositioning.
- **Solution:** `Sas::VerifyLicense` and `FUN_1800f93b0` explicitly exempt `FeatureID.BusinessSKU (2690 / 0x0A82)` and `FeatureID.ODNTLic (2679 / 0x0A77)`, returning `NoLicense (1)` for enterprise flags while granting `PermanentLicense (14)` to all standard Fences features.

### 3. NGEN Native Image Shadowing
`Fences.exe` and `Stardock.ApplicationServices.dll` have precompiled 64-bit CLR4 native images in `%SystemRoot%\assembly\NativeImages_v4.0.30319_64\`. Without flushing and recompiling these with `ngen.exe install`, the CLR ignores patched IL and executes stale cached methods.
- **Solution:** `Patch-Fences.ps1` purges stale NGEN caches and recompiles fresh native images bound to `/ExeConfig:Fences.exe`.

### 4. Multi-Monitor Profile Thrashing Loop
When virtual display drivers (e.g., remote desktop adapters, GameViewer, NoMachine) introduce secondary displays like `\\.\DISPLAY5`, Fences triggers `/syncmultimon` background loops. This repeatedly saves and reloads layouts, reverting custom layouts back to default 4-group templates.
- **Solution:** Setting `StoreLayoutsPerMultimon = 0` locks layout persistence to the primary desktop workarea.

---

## Requirements

- Windows 10/11 x64
- **Fences 6.5.8.1** installed (`FencesVersion.txt`)
- PowerShell 5.1+
- Administrator privileges (for writing to `%ProgramFiles(x86)%\Stardock\Fences` and NGEN)

Pristine binary SHA-256 baseline:
```
Fences.exe                        CE8BF948B70636844EA3245F33E29B1E9B837FE78547DEB45E9743F9A6D1A499
Stardock.ApplicationServices.dll  1A3DD0894A700397CE213911D8EFB2B993C6EB8A3BDAA8A37E00E93720538C80
DesktopDock64.dll                 CA70D2FC90C00023C5294B397D98520D86B18B0234AC9CD02A1D8661887BF9D5
```

Resulting patched SHA-256:
```
Fences.exe                        E9DFF6354E903B59AD7AE1C6B9FB10A2FF4CD302564B00809ABCBFC0D26C7E13
Stardock.ApplicationServices.dll  175A8AF77D3D69A39BEA989F77DB629351E440B96681728DAF2E5FE5BED36030
DesktopDock64.dll                 2D936968BEED21465C63FF6F5AD66B55C1261679575C8241EEF0E8CCF704B433
```

---

## Usage

```powershell
# 1. Dry run analysis (read-only)
.\Patch-Fences.ps1 -DryRun

# 2. Apply patch (elevated shell)
.\Patch-Fences.ps1

# 3. Verify runtime licensing and feature states
.\docs\verify.ps1

# 4. Revert to original binaries
.\Patch-Fences.ps1 -Restore
```

---

## Verification Output

Running `.\docs\verify.ps1` confirms complete status:

```text
Sas.VerifyLicense(2688, out license)
  Result      = Success (0)
  State       = PermanentLicense (14)
  PASS

Features.Purchased_Real / Feature_State
  PASS: all 13 feature gates unlocked

SKU flags
  IsBusinessSku    = False (expected: False)
  IsBusinessSku is cleanly disabled (safe)
  IsODNTSKU        = False (expected: False)
  IsODNTSKU is cleanly disabled (safe)

TrialActivation
  Status           = Valid
  IsTrialExpired   = False
  PASS: not treated as expired

WinTrust.VerifyEmbeddedSignature
  PASS: always-true patch active

All checks passed.
```

---

## Legal

This repository archives reverse-engineering research on software the author legally installed. Fences is a commercial product of Stardock Systems, Inc. No copyrighted binary files are distributed here — only patch instructions and scripts applied against user-supplied local installations.
