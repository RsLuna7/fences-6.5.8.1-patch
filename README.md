# Fences 6.5.8.1 — License / Ad-Panel Patch Archive

A reproducible IL-patch archive for **Stardock Fences 6.5.8.1**.

The goal: on any machine, install Fences 6.5.8.1, run one script, and the trial
limitations are gone — including the paid-feature gates and the purchase bar.

> **Status:** verified against the shipped build
> `Fences 6.5.8.1` (`FencesVersion.txt`), on Windows 11 26200 x64.
> Backups and a one-command restore are built in.

---

## What it does

Fences gates features on a `LicenseState` enum:

| Value | Name | Passes `State > Authorized`? |
|------:|------|------------------------------|
| 0 | Unknown | no |
| 1 | NoLicense | no |
| 2 | TrialExpired | no |
| 10 | Authorized | — (the threshold) |
| 11 | GracePeriod | yes, but explicitly excluded |
| 12 | Trial | yes, but explicitly excluded |
| 13 | Subscription | yes |
| 14 | PermanentLicense | yes |

`Features.VerifyActivation` computes:

```csharp
Purchases[feature] = state > LicenseState.Authorized        // > 10
                  && state != LicenseState.Trial            // != 12
                  && state != LicenseState.GracePeriod;     // != 11
```

So a trial is **not** merely a countdown — `Trial(12)` is explicitly excluded,
which is why paid features stay locked during the 30-day window.

Three patches move the whole product to `PermanentLicense` and silence the
purchase UI:

| # | File | Method | Effect |
|---|------|--------|--------|
| 1 | `Stardock.ApplicationServices.dll` | `Sas::VerifyLicense(int32, out LicenseInformation)` | Returns `LicenseInformation.PermanentLicense` + `Result.Success` |
| 2 | `Fences.exe` | `WinTrust::VerifyEmbeddedSignature(string)` | Always `true` (see note below) |
| 3 | `Fences.exe` | `NewUIPanel::ShowAdPanel(string)` | Returns immediately — no trial/purchase bar |

Patch 2 is not optional. `Fences.exe` verifies its own Authenticode signature at
startup via `CheckSign.Verified` → `CheckSign.Verify(path)` →
`WinTrust.VerifyEmbeddedSignature(path)`, covering `Fences.exe`,
`DesktopDock*.dll` and `SdAppServices*.dll`. Modifying the exe trips that check,
which calls `BlockUIVisibility()` — a 500 ms timer that keeps hiding the main
window. Patching the verifier to `true` disables the whole check.

Note that `Stardock.ApplicationServices.dll` is **not** in that list, which is
why patch 1 alone does not trip anything.

---

## Two traps worth knowing

### 1. The .NET NGEN image shadows your IL

After patching `Fences.exe` you will still see, in
`%APPDATA%\Stardock\Fences\TroubleshootingLog\fences_debug_info.txt`:

```
FencesUI - INTEGRITY COMPROMISED - WinTrustResult -2146762496 for ...\Fences.exe
FencesUI - BAD SIGNATURES on dlls
```

…and the UI keeps vanishing. The cause is not the patch — it is
`C:\Windows\assembly\NativeImages_v4.0.30319_64\Fences\Fences.ni.exe`, a
precompiled native image the CLR prefers over your modified IL.

The script runs `ngen.exe uninstall` and deletes the image directory. Without
this step, editing IL is a no-op.

### 2. Fat header + `initLocals` rejects an unused-locals body

Every target method has a *fat* method header with `initLocals = true` and a
declared local signature. Replacing the body with a short sequence that never
touches those locals makes the JIT reject the method with:

```
Common Language Runtime detected an invalid program.
```

The fix is to rewrite the header as a *tiny* header (`(codeSize << 2) | 0x02`),
which declares no locals at all. The script does this for every patch. The old
fat body is zero-filled; it is unreachable.

---

## Requirements

- Windows 10/11 x64
- **Fences 6.5.8.1** installed (other builds have different RVAs — see *Porting*)
- PowerShell 5.1+ (the in-box `powershell.exe` is fine)
- Administrator rights (the install lives under `Program Files (x86)`)

The script verifies the SHA-256 of both target files before touching them:

```
Fences.exe                        CE8BF948B70636844EA3245F33E29B1E9B837FE78547DEB45E9743F9A6D1A499
Stardock.ApplicationServices.dll  1A3DD0894A700397CE213911D8EFB2B993C6EB8A3BDAA8A37E00E93720538C80
```

A mismatch means the build is not the one these patches were derived from, and
the script refuses to run (override with `-Force` at your own risk).

---

## Usage

```powershell
# 1. Inspect only — no writes, no processes touched
.\Patch-Fences.ps1 -DryRun

# 2. Apply (elevated shell)
.\Patch-Fences.ps1

# 3. Revert to the shipped binaries
.\Patch-Fences.ps1 -Restore
```

Typical dry run:

```
==> checking build fingerprint
    version 6.5.8.1
    Stardock.ApplicationServices.dll : hash matches
    Fences.exe : hash matches
==> analysing method bodies
    [patchable] Sas::VerifyLicense(int32, out LicenseInformation)
           Stardock.ApplicationServices.dll  RVA 0x21FC  body 0x3FC  32 bytes
    [patchable] WinTrust::VerifyEmbeddedSignature(string)
           Fences.exe  RVA 0x36E4  body 0x18E4  160 bytes
    [patchable] NewUIPanel::ShowAdPanel(string)
           Fences.exe  RVA 0x96048  body 0x94248  705 bytes
```

Each method reports one of `patchable`, `already-patched`, or `unrecognised`.
The script is idempotent: a second run skips what is already done.

### Parameters

| Parameter | Meaning |
|-----------|---------|
| `-FencesPath <dir>` | Install directory. Defaults to `HKLM\SOFTWARE\Stardock\Fences\InstalledPath`, then `%ProgramFiles(x86)%\Stardock\Fences` |
| `-DryRun` | Analyse and report only |
| `-Restore` | Revert both files from `*.orig-backup`, purge NGEN, relaunch |
| `-Force` | Skip the version/hash compatibility gate |

---

## What you get after patching

Verified by invoking the patched assembly directly:

```
Sas.VerifyLicense(2688, out license)
  Result      = Success (0)
  State       = PermanentLicense (14)
  Expiration  = 12/31/9999 11:59:59 PM
```

All 13 `FeatureID` values resolve to `PermanentLicense` / `Purchased = true`:

```
Quickhide 489 | FolderViews 490 | Swipe 491 | Organization 492
Snapshots 493 | Customization 494 | ODNTLic 2679 | All 2688
BusinessSKU 2690 | BusinessLicensing 5001 | RollUpFences 5002
Tabs 5003 | Deployments 5004
```

Knock-on effects:

- `NewUIDialog.DoNewUI` no longer bails out to the activation screen
- the trial/purchase bar is gone
- `UnlockPurchaseButton` hides; `ManageButton` shows
- `IsBusinessSku` / `IsODNTSKU` become `true`
- `TrialActivation.DaysRemaining` reports a huge number (~2.9M) because
  expiration is `DateTime.MaxValue`; the value is never rendered once the ad
  panel is suppressed

---

## Files

```
Patch-Fences.ps1          the patcher
docs/patch-details.md     per-method IL before/after, RVAs, offsets
docs/analysis.md          how the licensing chain was mapped
docs/verify.ps1           independent verification (invoke patched methods)
```

---

## Porting to another Fences version

The script keys off RVAs, so a new build needs re-derivation:

1. Decompile with ILSpy (`ilspycmd -p -o out Fences.exe`) or dnSpy.
2. Find the same three methods by name.
3. Get each method's `RVA` from the IL dump (`// Method begins at RVA 0x...`).
4. Read the original IL bytes at that RVA (map RVA → file offset via the PE
   section table) and put a distinctive prefix into `Expect`.
5. Update `$TargetHashes` and `$TargetVersion`.

The `Expect` prefix is a safety net: it is what makes the script refuse to patch
an unknown build rather than corrupt it.

---

## Caveats

- **Upgrades wipe the patch.** Any Fences update replaces `Fences.exe` and the
  DLLs. Re-run the script afterwards (and expect to re-derive RVAs).
- **`License.sig` is untouched.** The 30-day trial signature stays on disk
  exactly as shipped. The patch makes the program stop consulting it via
  `Sas.VerifyLicense`. If some component ever called the native
  `SdAppServices_x64.dll!VerifyActivation` directly, it would still read `Trial`
  — no such call exists in `Fences.exe` 6.5.8.1.
- **Backups are per-file.** `*.orig-backup` sits next to each patched file, plus
  `*.locked-old` (the displaced original during the swap). Both are valid
  rollback sources.
- **Not tested on ARM64.** The patch targets the x64/x86 layout. `DesktopDockARM64.dll`
  is untouched, but the ARM64 build of `Fences.exe` would need its own RVAs.

---

## Legal

This repository archives a local reverse-engineering exercise on software the
author had installed. Fences is a commercial product of Stardock Systems, Inc.;
no binaries are redistributed here — only patch instructions against files you
supply yourself. Keep it private and use it on installations you own.
