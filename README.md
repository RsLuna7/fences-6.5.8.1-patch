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
| 1 | Managed | `Stardock.ApplicationServices.dll` | `Sas::VerifyLicense(int32, out LicenseInformation)` | Returns the licence singleton + `Result.Success (0)` for consumer features. Excludes `BusinessSKU (2690)` and `ODNTLic (2679)` to prevent accidental enterprise desktop-locking. |
| 2 | Managed | `Stardock.ApplicationServices.dll` | `LicenseInformation::get_PermanentLicense()` | Operand rewrite `ldc.i4.s 14` → `ldc.i4.s 13`: the singleton now reports `Subscription` instead of `PermanentLicense`. Single byte; fat header and code size untouched. |
| 3 | Managed | `Fences.exe` | `WinTrust::VerifyEmbeddedSignature(string)` | Returns `true`. Disables `BlockUIVisibility()` 500ms timer when `Fences.exe` is modified. |
| 4 | Managed | `Fences.exe` | `NewUIPanel::ShowAdPanel(string)` | Returns immediately — suppresses the trial countdown and purchase banner. |
| 5 | Native | `DesktopDock64.dll` | `FUN_1800feb60` (`FileOff 0x0FE08C`) | Bypasses `WinVerifyTrust` file-hash comparison (`xor eax, eax; nop x5`) while preserving PKCS#7 certificate subject decoding and anti-tamper pointer math (`DAT_180745dd0`). |
| 6 | Native | `DesktopDock64.dll` | `FUN_1800f93b0` (`FileOff 0x0F87B0`) | Dispatches `LicenseState = 13 (Subscription)` directly inside `explorer.exe` memory, liberating the native fence manager from `License.sig` and keeping it in agreement with the managed tier. |
| 7 | PE Header | All modified binaries | Optional Header CheckSum | Re-calculates and commits valid PE CheckSums via `imagehlp!MapFileAndCheckSumW`. |
| 8 | Settings | Registry HKCU | `Settings\StoreLayoutsPerMultimon` & `FontName` | Disables multi-monitor profile thrashing (`DISPLAY1` ↔ `DISPLAY5` loop) and configures `Microsoft YaHei UI` to eliminate CJK tofu box (`□□`) titles. |

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
- **Note:** `ngen.exe uninstall` reports success but leaves the `.ni.dll` in place, and `takeown` / `icacls` still end in *Access denied* while the image is mapped into a running process. The cache directory is owned by whoever last ran NGen, so once Fences is stopped the file deletes normally. `Clear-NgenImage` accounts for both.

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
Stardock.ApplicationServices.dll  D2EE6AFEBD36A4733C26BFBB01961B4424AAFFE60469F7F27B3BFF081A188E67
DesktopDock64.dll                 6DAB1B999FEC1E8BD903A81B354C2CC51DB94E17389C7C746057122322FE0E21
```

---

## Why `Subscription` (13) rather than `PermanentLicense` (14)

Both values pass the feature gate — `Features.VerifyActivation` computes
`Purchased = State > Authorized(10) && State != Trial(12) && State != GracePeriod(11)`,
so 13 and 14 unlock identically. They differ in what the product *is*:

| | 14 `PermanentLicense` | 13 `Subscription` |
|---|---|---|
| Feature gates | unlocked | unlocked |
| `Features.GetIsSubscription()` | `false` | `true` |
| *Manage subscription* in About | hidden | **shown** |
| Telemetry classification | perpetual licence | subscriber |

An Fences install that reports `PermanentLicense` is a perpetual purchase, not a
subscription. The two tiers are patched consistently to `13` so the managed UI and the
native desktop engine agree.

> **Verified:** scanning all of `DesktopDock64.dll`'s `.text` for comparisons against
> `0x0E` yields three sites (`rva 0xCE94B`, `0xD5E2F`, `0xF7993`), each a jump-table
> index bound rather than a licence-state test, so nothing depends on the exact value 14.

---

## Stale trial licence file

`%ProgramData%\Stardock\Fences6\License.sig` is a signed blob whose payload carries the
real trial record:

```json
{"activationId":15142851,"autoRenew":false,
 "licenses":[{"id":15848333,"type":"Trial","activation":"2026-10-23T11:16:34-04:00",
              "expiration":"2026-11-22T23:59:59-05:00","productId":2688}]}
```

Both tiers ignore it once patched, because neither reaches the native
`VerifyActivation` path any more. It is still a live contradiction to keep sitting in
`ProgramData`, so the recommended end state is to retire it:

```powershell
Rename-Item 'C:\ProgramData\Stardock\Fences6\License.sig' 'License.sig.disabled'
```

Renaming (rather than deleting) keeps the original blob for forensics and makes the
revert trivial. Nothing regenerates it: the only writer is `Sas.StartTrial` /
`Sas.ActivateSerial`, neither of which the patched build can reach.

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

### About `DesktopDock64.dll` and Explorer

The native fence engine lives inside `explorer.exe`, so that DLL is held open the whole
time the shell is running and cannot be replaced underneath it. `Patch-Fences.ps1`
handles this explicitly:

- default: the patched image is written to `DesktopDock64.dll.pending-apply` and a
  warning is printed. The managed tier is already live; the native tier applies at the
  next opportunity.
- `-RestartExplorer`: the script restarts the shell (open Explorer windows close) and
  swaps the native image in immediately.

```powershell
.\Patch-Fences.ps1 -RestartExplorer
```

---

## Verification Output

Running `.\docs\verify.ps1` confirms complete status:

```text
Sas.VerifyLicense(2688, out license)
  Result      = Success (0)
  State       = Subscription (13)
  PASS

Features.Purchased_Real / Feature_State
  PASS: all 13 feature gates unlocked

Features.GetIsSubscription(2688)
  True
  PASS: About panel exposes "Manage subscription"

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
