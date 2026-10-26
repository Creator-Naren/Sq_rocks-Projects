# USB Drop Attack Prevention Policy

Companion to `usb-drop-lab/`. The lab's benign beacon
(`usb_payload_sim.py`) shows what runs *after* a drive is inserted; this
document is the defensive half — how to make the insertion harmless or
impossible, and what to do when someone reports a drive.

---

## 1. Threat model: what a "dropped USB" actually exploits

| Vector | How it works | Still effective? |
|---|---|---|
| **AutoRun `open=`** | `autorun.inf` on the drive auto-ran a program on insertion | **No** on Windows 7+ for USB mass storage; the `open=` directive is ignored |
| **AutoPlay prompt** | Windows offers "open files" / "run program" on insertion | Only if AutoPlay is enabled and the *user* chooses — social, not automatic |
| **Curiosity double-click** | Bait-named `.lnk`, `.exe`, `.pdf`, `salary.xlsx.scr` | **Yes** — the dominant modern vector; relies on the human |
| **BadUSB / HID firmware** | Drive firmware re-enumerates as a keyboard and types commands | **Yes** — the OS trusts it as a real keyboard; mass-storage controls do not help |
| **Malicious cable (O.MG)** | Inline hardware injects keystrokes/network | **Yes** — physical supply-chain risk |
| **LNK + macro/script** | Shortcut runs `powershell`/`mshta`, or Office doc with macros | **Yes** if execution/ASR controls are missing |

Key point: **AutoRun is largely dead, so "disable AutoRun" alone no longer
protects you.** Most real-world drops now succeed because a *person* clicks
something, or because the device impersonates a keyboard.

---

## 2. Technical controls (defense in depth)

### 2.1 Turn AutoPlay / AutoRun off, everywhere

- **Group Policy** (per machine is not enough — apply to users too):
  `Computer Configuration > Administrative Templates > Windows Components >
  AutoPlay Policies > Turn off Autoplay` = **Enabled**, *All drives*.
- **Registry** (belt-and-braces):
  ```
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
      NoDriveTypeAutoRun = 0xFF        (DWORD)   ; disable for all drive types
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
      NoDriveTypeAutoRun = 0xFF        (DWORD)
  HKLM\...\Explorer\AutoplayHandlers
      DisableAutoplay = 1              (DWORD)
  ```
  `0xFF` = `0b11111111` disables AutoRun for removable, network, and unknown
  drive types.
- Verify with `gpedit.msc` / `reg query` and include it in your baseline
  image and MDM (Intune) compliance policy.

### 2.2 Attack Surface Reduction + execution control

- **WDAC / AppLocker**: allowlist what may execute; block executables,
  scripts, and `.lnk` from removable media.
- **Defender ASR rules** (or equivalent EDR policy):
  - *Block executable files from running unless they meet a prevalence,
    age, or trusted list criterion*
  - *Block Office applications from creating child processes*
  - *Block all Office applications from creating child processes* and
    *Block Win32 API calls from Office macros*
  - *Block Adobe Reader from creating child processes*
- **Block macros** from the internet (`Block macros from running in Office
  files from the internet`) and prefer disabling VBA in documents.
- **Mark-of-the-Web / SmartScreen**: keep enabled so files from removable
  media still carry reputation checks.

### 2.3 Device control / DLP for removable media

- **Block or read-only by default** for USB mass storage, then allowlist
  approved devices by hardware ID (VID/PID + serial).
- **Windows**: Defender **Device Control** (via Intune/Defender for
  Endpoint) or third-party DLP with a *removable media* policy:
  `Deny Executable Access`, `Deny Write Access`, or full **block**.
- Enforce **read-only** for the general population; grant write access only
  to a managed, encrypted, allowlisted fleet.
- Require **BitLocker To Go / encryption** on any sanctioned removable media.

### 2.4 Stop BadUSB / HID injection

- Default-deny **new HID devices** through device control or a
  "USB HID allowlist" policy.
- Disable unused USB ports via BIOS/UEFI, or physically **block/glue**
  ports on kiosks, OT/ICS consoles, and high-value workstations.
- On Linux labs, consider `usbguard` to allowlist device classes by VID/PID.

### 2.5 Scanning workflow for *sanctioned* media

- Mount **read-only** first; never let the OS auto-open it.
- Scan with the endpoint AV/EDR before reading files.
- Prefer a **dedicated, isolated "sheep-dip" host** for media from outside
  the organization.

---

## 3. Administrative & physical controls

- **Clean-desk / clean-floor** rules so drives are less likely to be "lost"
  and found.
- **Acceptable-use policy**: only IT-issued, encrypted removable media; no
  personal USB storage on corporate endpoints.
- **Hardware allowlisting**: purchase only devices with writable-firmware
  protections where possible; treat promotional/free drives as untrusted.
- **Segmentation**: high-value systems (finance, OT, admin jump hosts) get
  USB blocked outright.
- **Logging & monitoring**: alert on mass-storage insertion, new HID device
  enumeration, and processes spawning from removable-media paths
  (`E:\`, `/media/`, `/mnt/`).
- **Incident response**: treat found media as evidence; a drive can carry
  a beacon that phones home the moment it is mounted — do not mount it on a
  production host.

---

## 4. Awareness training (the control that catches the human vector)

Awareness is not optional here — it is the *primary* control for the
dominant "curious double-click" vector.

Train staff to:

1. **Never plug in** an unknown drive — regardless of the label
   ("PAYROLL", "CONFIDENTIAL", "PHOTOS", a colleague's name). Bait labels
   are chosen to trigger exactly the emotion they feel.
2. **Hand it in**: deliver found drives to IT/Security. Do not plug it in
   "just to see whose it is," and do not return it to where it was found.
3. **Recognize the double-click trap**: `.lnk`, `.exe`, `.scr`, `.bat`,
   `.js`, `.hta`, and double extensions (`invoice.pdf.exe`) on removable
   media.
4. **Report immediately** if a personal or unknown device was inserted, even
   briefly — speed matters for IR.

### Running the lab exercise safely

Use `usb-drop-lab/` for an authorized "dropped-drive" campaign:

- The beacon is **benign**: it writes `recon_log.txt` and an
  `AWARENESS_README.txt` and does nothing else — no network, no persistence.
- Place clearly-labelled drives (a controlled location, with physical-drop
  approval in writing) and **count insertions** as the metric.
- Debrief every person who plugged one in: the gain is the conversation,
  not the gotcha. Show `AWARENESS_README.txt`.
- **Legal/ethical prerequisite**: written authorization, defined scope,
  and a plan for recovering every drive. Never run an unattributed USB drop
  against people who have not been told a security-awareness program exists.

---

## 5. Control matrix (quick reference)

| Vector | Primary control | Secondary control |
|---|---|---|
| AutoRun `open=` | Disable AutoRun/AutoPlay (GPO + registry) | Baseline-image hardening |
| AutoPlay prompt | Disable AutoPlay for all drives | Awareness: never auto-run |
| Curious double-click | Awareness + WDAC/AppLocker (block ext from removable media) | Mark-of-the-Web, ASR |
| Malicious scripts/Office macros | Block macros from internet, ASR child-process rules | Script block logging |
| BadUSB / HID injection | Default-deny new HID devices, port blocking | usbguard / device control |
| Malicious cable (O.MG) | Physical port control, supplier diligence | Port-blocking on sensitive assets |
| Sanctioned media | Read-only mount + scan + sheep-dip host | Encryption (BitLocker To Go) |

---

## 6. Policy template (Acceptable Use addendum)

> **Removable Media Policy**
> 1. Only organization-issued, encrypted removable media may connect to
>    company systems.
> 2. AutoPlay/AutoRun is disabled on all managed endpoints; users must not
>    re-enable it.
> 3. Lost or found media must be reported to Security immediately and never
>    connected to any system.
> 4. High-sensitivity systems are USB-mass-storage-blocked and
>    HID-default-deny.
> 5. Files from external media are opened only on the isolated scan host
>    after AV/EDR clearance.
> 6. Violations are handled under the disciplinary policy; good-faith
>    reporting of found media is always rewarded, never penalized.

**Bottom line:** disable AutoRun/AutoPlay, block or read-only removable
media, deny new HID devices, allowlist execution — and train people to hand
in anything they find. No single control covers the modern USB-drop chain.
