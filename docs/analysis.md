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
```

Created at install time. The CLR binds to the native image, so IL edits appear
to have no effect — the log keeps showing `INTEGRITY COMPROMISED` from the
cached machine code.

`ngen.exe uninstall <exe>` plus deleting the `Fences` image directory restores
IL-only execution, after which the patches take effect.

## Tools used

- ILSpy (`ilspycmd`) for IL and C# decompilation
- `System.Reflection` (via PowerShell) to invoke patched methods and read back
  `LicenseState`, `Feature_State`, `Purchased_Real`
- Win32 `EnumChildWindows` / `GetWindowText` plus screen capture to confirm the
  ad panel actually disappeared from the UI
- Restart Manager (`RmGetList`) to identify the process holding the files —
  it turned out to be a long-lived `rundll32.exe`, not just `Fences.exe`
