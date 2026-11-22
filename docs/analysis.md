# How the licensing chain was mapped

Notes from the analysis pass, kept so the reasoning can be re-checked or
extended to another build.

## Targets

Both interesting binaries are managed .NET assemblies:

| File | Runtime | Notes |
|------|---------|-------|
| `Fences.exe` | .NET Framework 4.8, x86 PE | 6 929 MethodDef rows |
| `Stardock.ApplicationServices.dll` | .NET 2.0, x86 PE | SAS client wrapper, 289 MethodDef rows |

The native licensing engine is `SdAppServices_x64.dll` (C++, CryptoPP). It is
reached only through P/Invoke declared in `Stardock.ApplicationServices.dll`.

## The license file

`C:\ProgramData\Stardock\Fences6\License.sig` — 550 bytes, read as text hex and
decoded to:

```
[0..255]    256-byte signature   (RSA-2048, PKCS#1 v1.5, SHA-256)
[256..549]  294-byte JSON payload
```

Payload for a trial:

```json
{"activationId":15142851,
 "autoRenew":false,
 "machineSid":"S-1-5-21-...",
 "licenses":[{"id":15848333,
              "type":"Trial",
              "ActivationID":15142851,
              "activation":"2026-10-23T11:16:34-04:00",
              "expiration":"2026-11-22T23:59:59-05:00",
              "productId":2688}],
 "RequestInfo":null}
```

CryptoPP typeinfo in the native DLL confirms the scheme:

```
CryptoPP::TF_VerifierImpl<... RSA ... PKCS1v15 ... SHA256 ...>
```

Because the payload is signed and bound to `machineSid`, editing the JSON is not
viable — the signature fails and the native layer reports
`InvalidLicenseFile`.

`Cache.dat` is an opaque blob whose tail is a 512-hex-digit (256-byte) hash; it
is a cache, not an authority.

## The decision path

```
SdAppServices_x64.dll  (native)
  reads License.sig, verifies RSA signature, checks machineSid + expiration
        │
        ▼
Stardock.ApplicationServices.dll
  Sas::VerifyLicense(int32, out LicenseInformation)          ← patched here
  Sas::VerifyLicense(int32, out LicenseState, out DateTime, out DateTime)
        │
        ▼
Fences.exe :: DesktopDockUI.Activation_Sas
  VerifyActivation_Consumer(productId)
    if (!Settings.IsProVersion) return LicenseInformation.PermanentLicense;
    Sas.VerifyLicense(productId, out license)
  VerifyActivation(productId)
    consumer result, else EnterpriseActivation, else NoLicense
        │
        ▼
Fences.exe :: DesktopDockUI.Activation
  VerifyActivation(FeatureID)  ->  Activation_Sas or Activation_Fake
        │
        ▼
Fences.exe :: DesktopDockUI.Features
  VerifyActivation(Feature)
    FeatureInfo[Feature] = license
    Purchases[Feature]   = state > Authorized
                        && state != Trial
                        && state != GracePeriod
        │
        ▼
Features.IsActivated_Purchased(Feature)     ← every feature gate reads this
```

`Settings.IsProVersion` is a compile-time `=> true` on this build, so the
consumer SAS path is always taken.

## The enum that matters

```csharp
public enum LicenseState
{
    Unknown = 0, NoLicense = 1, TrialExpired = 2, SubscriptionExpired = 3,
    LicenseRevoked = 4, Authorized = 10, GracePeriod = 11, Trial = 12,
    Subscription = 13, PermanentLicense = 14
}
```

`Trial = 12` is greater than `Authorized = 10`, yet the gate explicitly excludes
it. That is the actual mechanism behind "trial limits features" — not a
countdown.

### 13 vs 14

Both `Subscription = 13` and `PermanentLicense = 14` clear the gate. The
difference is what the product claims to be:

```csharp
// Features.cs
public static bool GetIsSubscription(FeatureID Feature) =>
    FeatureInfo[Feature].State == LicenseState.Subscription;      // 13 only
```

That single predicate drives `About1UPAndStardock.ManageSubscriptionBtn.Visible`,
so a `PermanentLicense` build presents itself as a perpetual purchase and offers
no subscription management at all. The patch set therefore lands on **13**.

`Sas::VerifyLicense` hands back the `LicenseInformation.PermanentLicense`
singleton, and that singleton's `State` is the immediate inside
`get_PermanentLicense`. One operand byte there reaches every consumer at once:

```
IL_0016:  1F 0E  ->  1F 0D
          ldc.i4.s 14   ldc.i4.s 13
```

Rewriting `Sas::VerifyLicense` instead would mean allocating a fresh
`LicenseInformation` — more bytes, more risk, and it still would not fix the
singleton that other call paths read.

### A per-SKU caveat in the feature table

`Purchased_Real[f]` is `IsActivated_Purchased(All) || IsActivated_Purchased(f)`,
and `Feature_State[f]` short-circuits to `GetState(All)` whenever that is not
`NoLicense`. Once `All` is unlocked, **both indexers report success for every id**
— including `BusinessSKU` and `ODNTLic`. Neither is a per-SKU probe. To confirm
the enterprise gates are still held at `NoLicense`, call `Sas.VerifyLicense`
with 2690 / 2679 directly (`docs/verify.ps1` does exactly that).

## Where the countdown lives

```csharp
TrialActivation.DaysRemaining =>
    (int)Math.Floor((Features.GetExpirationDate(FeatureID.All) - DateTime.UtcNow).TotalDays)
```

With `PermanentLicense`, expiration is `DateTime.MaxValue`, so this returns
~2 912 147. It is only ever rendered inside `ShowAdPanel`, which patch 3 makes
inert.

## Integrity checking

`Program.VerifyIntegrety(bool)` → `CheckSign.Verified`, which verifies:

- `Application.ExecutablePath` (`Fences.exe`)
- `DesktopDockARM64.dll` / `DesktopDock64.dll` / `DesktopDock.dll`
- `SdAppServices_x64.dll` / `SdAppServices.dll`

via `CheckSign.Verify(path)` → `WinTrust.VerifyEmbeddedSignature(path)`, which
calls `WinTrustVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`.

**`Stardock.ApplicationServices.dll` is absent from that list.** That is why
patch 1 alone caused no complaint, and why patch 2 only became necessary once
`Fences.exe` itself was modified.

Failure handling:

```csharp
if (!CheckSign.Verified) {
    VerifyIntegretyFailed = true;
    BlockUIVisibility();                       // 500ms timer hiding MainForm
    Error.LogMessage("BAD SIGNATURES on dlls");
    MessageBox.Show(...);
    return false;
}
```

## NGEN

`ngen.exe display` reported a native image for `Fences.exe` and
`Stardock.ApplicationServices.dll`:

```
C:\Windows\assembly\NativeImages_v4.0.30319_64\Fences\Fences.ni.exe   17 937 920 bytes
C:\Windows\assembly\NativeImages_v4.0.30319_64\Stardock.Ap2ec9f628#\...\Stardock.ApplicationServices.ni.dll
                                                                        242 176 bytes
```

Created at install time. The CLR binds to the native image, so IL edits appear
to have no effect — the log keeps showing `INTEGRITY COMPROMISED` from the
cached machine code.

Empirically, three separate things defeat the obvious cleanup:

1. `ngen.exe uninstall <assembly>` exits 0 and prints `Uninstalling assembly …`
   while leaving the `.ni.dll` exactly where it was.
2. `takeown` + `icacls /grant` succeed and still produce *Access denied* on
   `del` — the image is mapped into a live process, and mapped files cannot be
   deleted regardless of ACL.
3. The cache directory is owned by whoever last ran NGen (here `PPOPIOS\viper`),
   not `TrustedInstaller`, so no ownership escalation is needed at all.

The working sequence is: stop Fences, delete the `.ni.dll`, then start Fences
again. Confirmed by reflection — with the image present, `get_PermanentLicense`
reported `IL len=47 byte14=0x0E`; after deleting it, `byte14=0x0D` and
`State = Subscription`.

## The native tier also carries licence logic

`DesktopDock64.dll` is not purely a rendering engine. `FUN_1800f93b0`
(`RVA 0x000F93B0`) is a dispatcher that walks an array of activation requests and
writes the licence state straight into each entry:

```asm
cmp     r8d, 0A82h        ; FeatureID.BusinessSKU
je      loc_nolic
cmp     r8d, 0A77h        ; FeatureID.ODNTLic
je      loc_nolic
mov     r9d, 0Eh          ; LicenseState  (stock: PermanentLicense)
```

It has exactly two direct callers (`rva 0x1DBB96`, `0x1DBC32`), both in the
Explorer-side initialisation path. Because the desktop fence manager runs inside
`explorer.exe`, this tier must be patched to the same value as the managed tier —
otherwise the shell believes it holds a perpetual licence while the settings UI
reports a subscription.

Scanning all of `.text` for comparisons against `0x0E` finds three sites
(`rva 0xCE94B`, `0xD5E2F`, `0xF7993`). All three are jump-table index bounds
(`movdqu` + range check), not licence tests, so changing `0Eh` to `0Dh` in the
dispatcher has no knock-on effect.

## Files that hold the binaries open

Replacing these files failed repeatedly with no useful message until Restart
Manager (`RmGetList`) was used to ask who actually had them open:

| Binary | Holder |
|---|---|
| `Stardock.ApplicationServices.dll` | `rundll32.exe "…\FencesMenu64.dll",StartFences` |
| `DesktopDock64.dll` | `explorer.exe` (the shell itself) |

Neither is `Fences.exe`. The `rundll32` host is a long-lived stub started at
login; the DLL only frees once it exits. `DesktopDock64.dll` cannot be replaced
while Explorer is running, which is why `Patch-Fences.ps1` gained
`-RestartExplorer` and a `*.pending-apply` fallback.

## Tools used

- ILSpy (`ilspycmd` 9.1) for IL and C# decompilation
- `objdump` (binutils, mingw64) for the x64 disassembly above
- `System.Reflection` (via PowerShell) to invoke patched methods and read back
  `LicenseState`, `Feature_State`, `Purchased_Real`
- Win32 `EnumChildWindows` / `GetWindowText` plus screen capture to confirm the
  ad panel actually disappeared from the UI
- Restart Manager (`RmGetList`) to identify the processes holding the files
- Byte-level differ (`hashlib` + section walker) to prove a given file differs
  from its `.orig-backup` by exactly N bytes, and where
