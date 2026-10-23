# Patch details — Fences 6.5.8.1

Exact byte-level record of the three patches. RVAs are metadata `MethodDef`
RVAs; file offsets assume the standard PE section table of this build.

## PE section table (both files)

### `Stardock.ApplicationServices.dll` (48 736 bytes)

| Section | VA | VSize | RawPtr | RawSize |
|---|---:|---:|---:|---:|
| `.text` | `0x00002000` | `0x00008ACC` | `0x00000200` | `0x00008C00` |
| `.rsrc` | `0x0000C000` | `0x000004DC` | `0x00008E00` | `0x00000600` |
| `.reloc` | `0x0000E000` | `0x0000000C` | `0x00009400` | `0x00000200` |

### `Fences.exe` (7 634 528 bytes)

| Section | VA | VSize | RawPtr |
|---|---:|---:|---:|
| `.text` | `0x00002000` | `0x0071ECA0` | `0x00000200` |
| `.rsrc` | `0x00722000` | `0x00026224` | `0x0071F000` |
| `.reloc` | `0x0074A000` | `0x0000000C` | `0x00745400` |

RVA → file offset: `RawPtr + (RVA - VAddr)` for the containing section.

---

## Patch 1 — `Sas::VerifyLicense(int32, out LicenseInformation)`

**File:** `Stardock.ApplicationServices.dll`
**RVA:** `0x21FC` → **file offset `0x3FC`**

### Original

Fat header (12 bytes) at `0x3FC`:

```
13 30 04 00 20 00 00 00 06 00 00 11
```

- flags `0x3013` → fat, `initLocals = true`
- maxstack `4`
- code size `0x20` (32 bytes)
- local sig `0x11000006` → `[0] LicenseState, [1] DateTime, [2] DateTime, [3] Result, [4] Result`

IL at `0x408`:

```
00 02 12 00 12 01 12 02 28 13 00 00 06 0D 03 06
07 08 73 01 00 00 06 51 09 13 04 2B 00 11 04 2A
```

Decoded:

```
nop
ldarg.0                       ; productId
ldloca.s 0                    ; &state
ldloca.s 1                    ; &activation
ldloca.s 2                    ; &expiration
call Sas::VerifyLicense(int32, LicenseState&, DateTime&, DateTime&)
stloc.3                       ; result
ldarg.1                       ; &license
ldloc.0 / ldloc.1 / ldloc.2   ; state, activation, expiration
newobj LicenseInformation::.ctor(LicenseState, DateTime, DateTime)
stind.ref                     ; *(&license) = new LicenseInformation(...)
ldloc.3
stloc.s 4
br.s
ldloc.s 4
ret
```

### Patched

Tiny header `0x26` = `(9 << 2) | 0x02`, then 9 bytes of IL:

```
26 03 28 09 00 00 06 51 16 2A
```

Decoded:

```
ldarg.1                                   ; &license
call LicenseInformation::get_PermanentLicense()   ; MethodDef 0x06000009
stind.ref                                 ; *(&license) = PermanentLicense
ldc.i4.0                                  ; Result.Success
ret
```

C# equivalent:

```csharp
public static Result VerifyLicense(int productId, out LicenseInformation license)
{
    license = LicenseInformation.PermanentLicense;
    return Result.Success;
}
```

`LicenseInformation.PermanentLicense` is a cached static instance constructed as
`(LicenseState.PermanentLicense, DateTime.MinValue, DateTime.MaxValue)`.

---

## Patch 2 — `WinTrust::VerifyEmbeddedSignature(string)`

**File:** `Fences.exe`
**RVA:** `0x36E4` → **file offset `0x18E4`**

### Original

Fat header at `0x18E4`:

```
1B 30 04 00 A0 00 00 00 1F 00 00 11
```

- flags `0x301B` → fat, `initLocals = true`, more sections
- code size `0xA0` (160 bytes)
- 8 locals

IL at `0x18F0`:

```
00 02 73 44 00 00 06 0A 12 01 72 39 03 00 70 28
9C 00 00 0A ...
```

Decoded (abridged):

```
nop
ldarg.0
newobj WinTrustData::.ctor(string)
stloc.0
ldloca.s 1
ldstr "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
call Guid::.ctor(string)
ldsfld WinTrust::INVALID_HANDLE_VALUE
ldloc.1
ldloc.0
call WinTrust::WinVerifyTrust(native int, Guid, WinTrustData)
stloc.2
...  ; ceq 0 -> stloc.3 ; negate -> stloc.s 4 ; if false, log "INTEGRITY COMPROMISED"
```

### Patched

Tiny header `0x0A` = `(2 << 2) | 0x02`:

```
0A 17 2A
```

Decoded:

```
ldc.i4.1     ; true
ret
```

### Why this is required

`CheckSign.Verified` calls `CheckSign.Verify(Application.ExecutablePath)` and the
same for `DesktopDock64.dll` / `SdAppServices_x64.dll`. `CheckSign.Verify(string)`
is a one-liner forwarding to `WinTrust.VerifyEmbeddedSignature(string)`.

A failed check sets `Program.VerifyIntegretyFailed`, logs
`FencesUI - INTEGRITY COMPROMISED`, shows a modal, and calls
`BlockUIVisibility()` — a `Timer` at 500 ms interval that repeatedly sets
`FenceUI.MainForm.Visible = false`. The app is unusable until this is patched.

---

## Patch 3 — `NewUIPanel::ShowAdPanel(string)`

**File:** `Fences.exe`
**RVA:** `0x96048` → **file offset `0x94248`**

### Original

Fat header at `0x94248`:

```
13 30 03 00 C1 02 00 00 B1 02 00 11
```

- flags `0x3013` → fat, `initLocals = true`
- code size `0x2C1` (705 bytes)

IL at `0x94254`:

```
00 16 0A 2B 00 02 7B F5 07 00 04 72 99 02 00 70 ...
```

Decoded (abridged):

```
nop
ldc.i4.0
stloc.0
br.s
ldarg.0
ldfld AdPanelBuySingleButtonTextOriginal
ldstr "Buy Now"
...
```

The body sets `AdPanelShowing = true`, reads
`TrialActivation.Status` / `TrialActivation.DaysRemaining`, and writes the
"`{0} days left in your free trial`" / "`Purchase ()`" strings into
`PurchaseText` and `AdPanelBuyAllButton`, then starts the slide-in timer.

### Patched

Tiny header `0x06` = `(1 << 2) | 0x02`:

```
06 2A
```

Decoded:

```
ret
```

Because the method is `void`, an immediate `ret` is a complete, valid body. The
ad panel never animates in, so no trial text or purchase button is ever
rendered. The separate `HideAdPanel()` path is irrelevant once `ShowAdPanel` is
inert.

---

## Why tiny headers

All three original methods carry a fat header with `initLocals = true` and a
declared local signature. A replacement body that leaves those locals untouched
is rejected by the JIT:

```
Common Language Runtime detected an invalid program.
```

Observed while developing this patch: variants that kept the fat header and
`initLocals` failed with that error for *every* attempted body, including
`ldc.i4.0; ret`. Switching to a tiny header — which declares no locals — made
all three work immediately.

Tiny header encoding: `(codeSize << 2) | 0x02`, one byte, body follows
immediately. The former fat header and old body bytes are zero-filled; they are
unreachable because nothing references them.

---

## Resulting file hashes

After all three patches:

```
Fences.exe                        7137C083DBCFEC17BACCEB2FC98941E72AD4A34078648FF0B2EB6E066870330C
Stardock.ApplicationServices.dll  D23A848E2909FE796BF00F784B5F282C63BC3CC3CEF276308B745DCD864F1F92
```

Pristine (as shipped):

```
Fences.exe                        CE8BF948B70636844EA3245F33E29B1E9B837FE78547DEB45E9743F9A6D1A499
Stardock.ApplicationServices.dll  1A3DD0894A700397CE213911D8EFB2B993C6EB8A3BDAA8A37E00E93720538C80
```

`Patch-Fences.ps1` reproduces the patched hashes byte-for-byte from the pristine
inputs — verified by patching a copy in a temp directory and comparing against a
hand-patched install.
