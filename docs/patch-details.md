# Patch Details — Fences 6.5.8.1 (Managed + Native Engine)

Exact byte-level record of the patches applied to Stardock Fences 6.5.8.1. RVAs are metadata `MethodDef` RVAs or PE image RVAs. File offsets assume the standard PE section tables of this build.

## PE Section Layouts

### 1. `Stardock.ApplicationServices.dll` (48 736 bytes)

| Section | VA | VSize | RawPtr | RawSize |
|---|---:|---:|---:|---:|
| `.text` | `0x00002000` | `0x00008ACC` | `0x00000200` | `0x00008C00` |
| `.rsrc` | `0x0000C000` | `0x000004DC` | `0x00008E00` | `0x00000600` |
| `.reloc` | `0x0000E000` | `0x0000000C` | `0x00009400` | `0x00000200` |

### 2. `Fences.exe` (7 634 528 bytes)

| Section | VA | VSize | RawPtr |
|---|---:|---:|---:|
| `.text` | `0x00002000` | `0x0071ECA0` | `0x00000200` |
| `.rsrc` | `0x00722000` | `0x00026224` | `0x0071F000` |
| `.reloc` | `0x0074A000` | `0x0000000C` | `0x00745400` |

### 3. `DesktopDock64.dll` (6 422 624 bytes)

| Section | VA | VSize | RawPtr | RawSize |
|---|---:|---:|---:|---:|
| `.text` | `0x00001000` | `0x00211678` | `0x00000400` | `0x00211800` |
| `.rdata` | `0x00213000` | `0x0036FF76` | `0x00211C00` | `0x00370000` |
| `.data` | `0x00583000` | `0x0028D524` | `0x00581C00` | `0x0003EA00` |
| `.pdata` | `0x00811000` | `0x0001BE34` | `0x005C0600` | `0x0001C000` |
| `.reloc` | `0x0085E000` | `0x00012A80` | `0x0060AC00` | `0x00012C00` |

---

## Patch 1 — `Stardock.ApplicationServices.dll!Sas::VerifyLicense`

- **RVA:** `0x000021FC` → **File Offset:** `0x000003FC` (1020 dec)
- **Original:** Fat header (12 bytes) + 32 bytes body = 44 bytes.
- **Patched:** Tiny header `0x82` (`(32 << 2) | 0x02`), 32 bytes IL, remaining bytes zero-padded:

```cil
0x00: ldarg.1
0x01: ldarg.0
0x02: ldc.i4 2690                       // 0x20 0x82 0x0A 0x00 0x00 (BusinessSKU)
0x07: beq.s 0x18                        // 0x2E 0x0F
0x09: ldarg.0
0x0A: ldc.i4 2679                       // 0x20 0x77 0x0A 0x00 0x00 (ODNTLic)
0x0F: beq.s 0x18                        // 0x2E 0x07
0x11: call LicenseInformation.get_PermanentLicense // 0x28 0x09 0x00 0x00 0x06
0x16: br.s 0x1D                         // 0x2B 0x05
0x18: call LicenseInformation.get_NoLicense        // 0x28 0x08 0x00 0x00 0x06
0x1D: stind.ref                         // 0x51
0x1E: ldc.i4.0                          // 0x16 (Result.Success)
0x1F: ret                               // 0x2A
```

---

## Patch 2 — `Fences.exe!WinTrust::VerifyEmbeddedSignature`

- **RVA:** `0x000036E4` → **File Offset:** `0x000018E4`
- **Original:** Fat header + 160 bytes Authenticode validation.
- **Patched:** Tiny header `0x0A` (`(2 << 2) | 0x02`), `ldc.i4.1` (`0x17`), `ret` (`0x2A`). Tail zero-padded.

---

## Patch 3 — `Fences.exe!NewUIPanel::ShowAdPanel`

- **RVA:** `0x00096048` → **File Offset:** `0x00094248`
- **Original:** Fat header + 705 bytes banner layout routines.
- **Patched:** Tiny header `0x06` (`(1 << 2) | 0x02`), `ret` (`0x2A`). Tail zero-padded.

---

## Patch 4 — `DesktopDock64.dll!FUN_1800feb60` (WinVerifyTrust Bypass)

- **RVA:** `0x000FEC8C` → **File Offset:** `0x000FE08C`
- **Original:** `FF 94 24 58 02 00 00` (`call qword ptr [rsp+258h]`)
- **Patched:** `33 C0 90 90 90 90 90` (`xor eax, eax; nop; nop; nop; nop; nop`)
- **Reasoning:** Bypasses WinVerifyTrust while preserving subsequent PKCS#7 certificate structure inspection, subject name verification (`STARDOCK SYSTEMS, INC.`), and pointer math calculations in the Explorer initialization loop.

---

## Patch 5 — `DesktopDock64.dll!FUN_1800f93b0` (Native License Query)

- **RVA:** `0x000F93B0` → **File Offset:** `0x000F87B0`
- **Original:** Calls native `SdAppServices_x64.dll!VerifyActivation` and validates trial periods.
- **Patched:** Custom x64 stub (122 bytes), padded with `0xCC`:

```asm
test    rcx, rcx
jnz     loc_valid
mov     eax, -7
ret
loc_valid:
test    rdx, rdx
jz      loc_done
loc_loop:
mov     r8d, dword ptr [rcx]
cmp     r8d, 0A82h                      ; FeatureID.BusinessSKU
je      loc_nolic
cmp     r8d, 0A77h                      ; FeatureID.ODNTLic
je      loc_nolic
mov     r9d, 14                         ; LicenseState.PermanentLicense
mov     r10d, 67000000h                 ; Activation timestamp dummy
xor     r11d, r11d                      ; Expiration timestamp (never)
jmp     loc_store
loc_nolic:
mov     r9d, 1                          ; LicenseState.NoLicense
mov     r10, -1
mov     r11, -1
loc_store:
mov     rax, [rcx+8]
test    rax, rax
jz      skip_st
mov     [rax], r9d
skip_st:
mov     rax, [rcx+10h]
test    rax, rax
jz      skip_act
mov     [rax], r10
skip_act:
mov     rax, [rcx+18h]
test    rax, rax
jz      skip_exp
mov     [rax], r11
skip_exp:
add     rcx, 20h
dec     rdx
jnz     loc_loop
loc_done:
xor     eax, eax
ret
```

---

## Resulting Binary Hashes

### Pristine (Stock Shipped Build):
```
Fences.exe                        CE8BF948B70636844EA3245F33E29B1E9B837FE78547DEB45E9743F9A6D1A499
Stardock.ApplicationServices.dll  1A3DD0894A700397CE213911D8EFB2B993C6EB8A3BDAA8A37E00E93720538C80
DesktopDock64.dll                 CA70D2FC90C00023C5294B397D98520D86B18B0234AC9CD02A1D8661887BF9D5
```

### Patched:
```
Fences.exe                        E9DFF6354E903B59AD7AE1C6B9FB10A2FF4CD302564B00809ABCBFC0D26C7E13
Stardock.ApplicationServices.dll  175A8AF77D3D69A39BEA989F77DB629351E440B96681728DAF2E5FE5BED36030
DesktopDock64.dll                 2D936968BEED21465C63FF6F5AD66B55C1261679575C8241EEF0E8CCF704B433
```
