# The recurring "license not found" dialog — Stardock Application Services

> Applies to **Fences 6.5.8.1** with **SAS 2.11.3.4644** (`SdDisplay.exe` FileVersion
> `2.11.3.4644`), Windows 11 26200 x64.
>
> Even after `Patch-Fences.ps1` has fully unlocked every feature gate, a dialog can
> still appear roughly every 30 minutes:
>
> ```
> Fences 6 未找到许可证
> [购买]  [输入产品密钥]
> ```
>
> This document explains where it comes from, why the managed and native patches in
> this repository cannot suppress it, and the two ways to stop it.

---

## 1. The dialog does not belong to `Fences.exe`

Enumerating top-level windows while the dialog is up shows the owning process is
`SdDisplay.exe`, not `Fences.exe`:

```
PID=<pid>  class=#32770  visible=True
  Button :: 确定
  Static :: Unable to display ui key '1'
```

`SdDisplay.exe` is the activation / marketing UI host shipped with **Stardock
Application Services (SAS)**. It is a separate .NET 4.8 AnyCPU assembly
(`MVID` varies per build) sitting next to `Fences.exe` in the install directory.

The `Unable to display ui key '1'` static is the tell: SAS handed the shell a UI key
it could not resolve from its own `Default.spak` package, so `SdDisplay` degraded to a
bare `#32770` dialog with whatever buttons the key declared — which is exactly the
two-button panel above.

---

## 2. Who keeps relaunching it

The SAS scheduler lives inside `SdAppServices_x64.dll` / `SdAppServices.dll`, which are
loaded **into `explorer.exe` and `Fences.exe`**. It owns four task types, visible as
string symbols in the native module:

```
UiTask
ValidateLicenseTask
UpdateCheckTask
SuspendWatchDogTask
```

When a `UiTask` / `ValidateLicenseTask` fires, SAS builds this command line
(the format string is at ASCII offset `0x13E5D0` in `SdAppServices_x64.dll`):

```
SdDisplay.exe -prodId=2688 -ProdName=Fences6 -company=Stardock
              -prodVer=6.5.8.1 -startUi=1 -parentPid=<pid>
```

Supporting strings in the same module:

```
[ShowUI] Unable to run process: '<path>', in '<dir>'
[ShowUI] Process Ran: '<path>' successfully
Unable to run SdDisplay.exe
Unable to start Scheduler, already started
Starting the Scheduler, flags=<n>
Displaying UI with key '<key>'
```

Observed cadence in `%LOCALAPPDATA%\Stardock\Fences6\SasLog.txt` — strictly 30 minutes:

```text
00:14:19  Initialize: ... Process Name '...\SdDisplay.exe'
00:44:50  Initialize: ... Process Name '...\SdDisplay.exe'
01:15:21  Initialize: ... Process Name '...\SdDisplay.exe'
01:45:51  Initialize: ... Process Name '...\SdDisplay.exe'
02:16:22  Initialize: ... Process Name '...\SdDisplay.exe'
02:46:54  Initialize: ... Process Name '...\SdDisplay.exe'
```

The scheduler also logs `[SuspendWatchDogTask] Executing.` on its own hourly rhythm,
which is how you can tell the two timers apart in the log.

---

## 3. Why the existing patches cannot suppress it

`Patch-Fences.ps1` intercepts two tiers:

| Tier | Binary | Patched function |
|---|---|---|
| Managed | `Stardock.ApplicationServices.dll` | `Sas::VerifyLicense(int32, out LicenseInformation)` |
| Managed | `Fences.exe` | `WinTrust::VerifyEmbeddedSignature`, `NewUIPanel::ShowAdPanel` |
| Native | `DesktopDock64.dll` | `FUN_1800feb60` (WinVerifyTrust), `FUN_1800f93b0` (license dispatch) |

`SdDisplay.exe` / `SdAppServices_x64.dll` are **neither** of those. They are the SAS
engine itself, and SAS does not call the patched managed entry point — it reads its own
on-disk state directly:

```text
C:\ProgramData\Stardock\Fences6\License.sig           -> absent
C:\ProgramData\Stardock\Fences6\License.sig.disabled  -> present (renamed by the patch flow)
```

`Fences.exe`'s own debug report confirms what SAS sees
(`%APPDATA%\Stardock\Fences\TroubleshootingLog\fences_debug_info.txt`):

```text
Sig Info:  <not found> - dir exists ~ C:\ProgramData\Stardock\Fences6\License.sig
SASInitResult:  0
SASState:       13
```

Note the split: the **managed** layer reports `SASState: 13` (Subscription, patched),
while the **native** layer independently resolves `NoLicense` because the on-disk
signature is gone. That is the whole bug in one line.

If `License.sig` is restored from the `.disabled` copy, its payload is an already
expired Trial:

```json
{"activationId":<id>,"autoRenew":false,
 "machineSid":"<MACHINE_SID>",
 "licenses":[{"id":<id>,"type":"Trial","activationId":<id>,
              "activation":"<ISO8601>","expiration":"<ISO8601>",
              "productId":2688}]}
```

Once `expiration` passes, SAS resolves `NoLicense` and `SdDisplay` renders the panel.
Restoring the file therefore does **not** help — it just swaps "not found" for
"trial expired". Deleting it does not help either.

---

## 4. Two ways to stop it

### 4a. Permanent: make the UI host unlaunchable

Rename the host so SAS's `ShowUI` cannot start it:

```
SdDisplay.exe  ->  SdDisplay.exe.disabled
```

SAS logs one line — `[ShowUI] Unable to run process` — and returns. No process, no
window, no overhead. This is the cleanest option.

Use [`scripts/Disable-SdDisplayNag.ps1`](../scripts/Disable-SdDisplayNag.ps1) from an
elevated shell (it writes into `%ProgramFiles(x86)%`):

```powershell
.\scripts\Disable-SdDisplayNag.ps1            # disable
.\scripts\Disable-SdDisplayNag.ps1 -Restore   # undo
.\scripts\Disable-SdDisplayNag.ps1 -WhatIf    # show what would happen
```

`Fences.exe` never needs `SdDisplay.exe`. Desktop fences, roll-up, tabs, snapshots and
layouts all keep working — the host is purely the activation/notification surface.

### 4b. No admin rights: poll and kill

[`scripts/FencesNoNag-Watcher.ps1`](../scripts/FencesNoNag-Watcher.ps1) polls for
`SdDisplay.exe` every 250 ms and kills it before the window finishes drawing.

```powershell
# run once, hidden
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden `
  -File .\scripts\FencesNoNag-Watcher.ps1
```

It is safe to run alongside 4a (it simply has nothing to kill), and it survives a
Fences upgrade, which 4a does not.

---

## 5. Implementation notes

### 5a. `Kill()` is not always allowed

The process is killed within ~250 ms of launch, which means it is still initialising and
its handle can be protected. `Process.Kill()` then throws `Access is denied`. The watcher
falls back to `taskkill /f /pid` and re-checks:

```
killed pid <a> :: "<path>" -prodId=2688 ... -startUi=1 -parentPid=<pid>
killed pid <b> via taskkill
```

Observed rate: about 1 in 4 launches hits the fallback path. Without it the window
leaks through.

### 5b. Single instance is mandatory

Two independent autostart paths are used (logon task + Startup shortcut). Both point at
the same script, so without a guard you end up with two pollers. A named mutex
(`Global\FencesNoNagWatcher`) makes the second copy exit immediately:

```powershell
$mutex = New-Object System.Threading.Mutex($false, 'Global\FencesNoNagWatcher')
if (-not $mutex.WaitOne(0)) { exit 0 }
```

Note the release must be guarded — if mutex creation itself failed, `$mutex` is `$null`
and calling `ReleaseMutex()` on it throws inside `finally`.

### 5c. Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI

This one wastes an hour if you hit it blind. A `.ps1` file saved as **UTF-8 without
BOM** containing non-ASCII comments is decoded as ANSI by `powershell.exe` 5.1, and the
mojibake corrupts the token stream. The parser then reports something completely
unrelated to the actual cause:

```text
表达式或语句中包含意外的标记"}"
catch 块必须是最后一个 catch 块
```

The file looks perfect in any UTF-8 editor and parses fine in PowerShell 7 (which
defaults to UTF-8). Two ways out:

* keep scripts **pure ASCII** (what this repo does), or
* save them **UTF-8 with BOM**.

To detect it:

```powershell
$b = [System.IO.File]::ReadAllBytes('.\scripts\FencesNoNag-Watcher.ps1')
"$($b[0]),$($b[1]),$($b[2])"   # 239,187,191 = BOM present
```

### 5d. A stuck `consent.exe` blocks every UAC prompt

If `Start-Process -Verb RunAs` fails silently — no UAC window, no error — check for an
orphaned consent broker:

```powershell
Get-CimInstance Win32_Process -Filter "Name='consent.exe'" |
  Select-Object ProcessId, ParentProcessId, ExecutablePath
```

A `consent.exe` whose `ExecutablePath` is empty and whose parent PID no longer exists is
a zombie holding the UAC channel. Every later elevation request is refused without ever
showing a prompt. It cannot be killed from a medium-integrity session (SYSTEM-owned);
reboot clears it.

Relevant policy values on the affected machine:

```text
EnableLUA                    = 1
ConsentPromptBehaviorAdmin   = 5     (prompt for consent, no credentials)
PromptOnSecureDesktop        = 0
```

---

## 6. Verifying the fix

Launch the exact command line SAS uses and confirm nothing appears:

```powershell
$exe = "$env:ProgramFiles(x86)\Stardock\Fences\SdDisplay.exe"
1..6 | ForEach-Object {
  Start-Process $exe -ArgumentList @(
    '-prodId=2688','-ProdName=Fences6','-company=Stardock',
    '-prodVer=6.5.8.1','-startUi=1',"-parentPid=$PID")
  Start-Sleep -Milliseconds 300
}
Get-Process SdDisplay -ErrorAction SilentlyContinue   # expect: nothing
```

With the watcher running, six rapid launches produce this log and zero surviving
processes:

```text
killed pid <a> :: "...\SdDisplay.exe" -prodId=2688 ... -startUi=1 -parentPid=<pid>
killed pid <b> via taskkill
killed pid <c> :: "...\SdDisplay.exe" -prodId=2688 ... -startUi=1 -parentPid=<pid>
```

---

## 7. Scope and limits

* **This is cosmetic.** The dialog is an activation nag; it does not disable features.
  If `Patch-Fences.ps1` has run, every feature gate is already unlocked
  (`AppLicenseState = 13`, all 13 `FeatureID` values resolve to Subscription).
* **A Fences upgrade undoes 4a.** Any update restores `SdDisplay.exe`; re-run the
  script. The watcher (4b) is unaffected because it matches on process name.
* **Do not delete `License.sig.disabled`.** It is the rollback source for the patch
  flow and its absence vs. presence is what SAS keys off. Moving it around only makes
  the state harder to reason about.
* **No binary is modified by either fix.** 4a renames a file; 4b kills a process.
  Neither touches code, and neither affects the patched binaries or their hashes.
