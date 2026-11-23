## Archived

This repository is archived and is no longer maintained. Development has moved to a private repository.

This tool roots Meta Portal devices through a Linux kernel vulnerability (CVE-2026-43499, "GhostLock"). Meta's current Portal firmware, build 3051392000021050, includes the upstream fix for that vulnerability, and the root method here does not work on that build. The releases in this repository support only the firmware builds listed in the compatibility table below.

> ⚠️ **Under heavy development — not ready for release.** This project is being actively restructured and validated. It may not work on your device yet, behavior can change between commits, and there is no stable release. Use at your own risk.

# Meta Portal Root Provisioner

Provision and root Meta Portal devices with a controlled, exact-build
root exploit. All changes are persistent and survive reboots.

> **Credits:** This project is a fork of the original Portal provisioner
> created by [jxlarrea](https://github.com/jxlarrea) — the original
> project and its exploit work are his.

## Overview

The provisioner checks that the connected Portal has an exact supported
model and firmware build, briefly uses a root exploit during a controlled
reboot, applies the features you select, then checks them on a following
normal boot.

Root access itself is not persistent. It lasts only for the provisioning
window unless you enable automatic re-rooting after every reboot
(`--autoroot`), which makes root come back by itself after every reboot,
with no computer involved.

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

## What a full setup does

`--full` applies everything in the table below in one run (its exact
expansion is shown in [step 5](#5-run-the-provisioner)). To apply only
some of it, drop `--full` and combine the individual flags instead; each
is described under [Feature flags](#feature-flags).

| Feature | What it does |
| --- | --- |
| Root access for the run itself | Not a setting: the run opens a short window of root access to make the changes below, then the Portal goes back to normal. |
| Persistent wireless ADB | Keeps ADB available on port 5555 after setup, so later reboots no longer require USB activation. |
| Non-expiring ADB authorization | Keeps computers you already approved authorized instead of forgetting them after Android's timeout. |
| Audio fix | Stops the Portal from suppressing microphone audio while its speaker is playing. |
| Debloat | Turns off Meta's control and background services in one step: disables unused Meta apps, cloud clients and diagnostics, blocks Meta system updates, blocks Meta remote wipe, turns Android Private DNS off so the Portal uses the network's DNS, and disables Meta's app verifier so non-Meta apps can update normally. |
| Meta-account removal | Removes the Portal's local Meta accounts. **One-way: cannot be undone** (see [What can't be undone](#what-cant-be-undone)). |
| Presence optimization | Lowers Smart Camera CPU use while keeping full-view person detection. |
| Shizuku, running as root | Installs Shizuku; after every reboot it starts again, running as root, for apps that need deeper access. |
| Automatic re-rooting | Root comes back by itself after every reboot, with no computer involved. |

Not in a full setup (add the flag yourself if you want them):

- **Presence frame-rate cap** (`--presence-fps-cap`): a full setup does
  not cap how often the camera analysis runs.
- **System theme control** (`--system-theme-control`): a full setup does
  not change the Portal's light/dark theme.

The provisioner will not touch a Portal whose model and firmware build
do not exactly match a supported one, and it checks every change on a
following boot before calling the run done. Read-only status, dry-run
planning, backups and interrupted-run recovery are covered under
[Status, backups and recovery](#status-backups-and-recovery).

<a id="what-cant-be-undone"></a>
## What can't be undone

Almost everything the provisioner changes can be restored with
`--restore <name>`: a restore replays the original state the
provisioner recorded on the device before the change, and where no
original was recorded it returns the setting to its factory
default. The one exception is **Meta-account removal**
(`--remove-meta-accounts`): the accounts are deleted, and the
backup the provisioner keeps holds only account names and types,
never credentials, so there is nothing to restore from. Re-adding
an account is a manual sign-in on the device. A factory reset
remains the universal undo for everything else.

## Requirements

### Host computer

- Windows, macOS or Linux
- Python 3.9 or newer and Android Debug Bridge (`adb`)
- A USB data cable for initial stock-device setup

### Portal

- An exact model and firmware build listed under [Supported models](#supported-models)
- The initial on-screen setup (OOBE) completed so the Debug menu is available
- ADB enabled in the Portal's Debug menu (guided connect in step 3 handles the host authorization and the switch to wireless ADB)
- Stable network, a stable IP address and external power for several reboots
- For presence features: the physical camera cover open and the camera/microphone privacy control off. If the cover is closed, setup still finishes; the camera check then completes on a later run with the cover open. Nobody needs to remain in view during the reboot sequence.

## Supported models

| Model | Codename | Android | Supported firmware fingerprint | Kernel | Status |
| --- | --- | --- | --- | --- | --- |
| Meta Portal Go | `terry` | 10 | `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys` | `4.9.227-perf+` | Upstream-tested |
| Meta Portal 10-inch (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Fork-validated |
| Meta Portal+ (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Fork-validated |
| Meta Portal+ (2nd generation) | `cipher` | 10 | `Facebook/cipher_prod/cipher:10/QKQ1.210213.001/4051355900018050:user/prod-keys` | `4.9.227-perf+` | Upstream-tested |
| Meta Portal 10-inch (2nd generation) | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Fork-validated |
| Meta Portal Mini | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Fork-validated |
| Meta Portal TV | `ripley` | 9 | `Facebook/ripley_prod/ripley:9/PKQ1.191202.001/2041515800015050:user/prod-keys` | `4.4.153+` | Upstream-tested |

**Fork-validated** means this fork's maintainers have run the full
provisioning flow on that model and firmware build. **Upstream-tested**
models are supported by the same exact-build targets inherited from the
upstream project but have not yet been re-validated on the fork.

Thank you to [@protocol113](https://github.com/protocol113) for providing
Portal TV access and sharing the exploit timing observations that helped
validate `ripley` support.

Support is exact-build specific. Other models and firmware versions
need their own verified target before the provisioner will accept them.
The `aloha` software family is shared by more than one first-generation
form factor. The original 10-inch Portal and 15.6-inch Portal+ share
their firmware and kernel, but they are separate models and each is
checked against its own entry above.

To request support for another build, connect the Portal by USB and run:

```sh
python3 tools/provision_portal.py --status
```

Open an issue with the `target` section of the report: it gives the
retail model, the exact firmware build and the kernel. Delete the
report's serial line before posting (it is the Portal's ADB address),
and do not publish an ADB address, pairing code or account information.

## Step-by-step installation

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

### 1. Download the release bundle

Download `portal-provisioner-bundle-<version>.zip` from the project's
releases, extract it, and change into the extracted directory. The bundle
carries everything needed for every supported model, and needs no clone
and no Android toolchain.

Before anything changes on the Portal, the provisioner checks the
bundle matches the Portal's exact build and that its files are intact;
if either check fails it refuses to run and the Portal is left untouched.

### 2. Prepare the Portal

Complete the Portal's initial on-screen setup before continuing. The Debug
menu and its ADB control are unavailable until the out-of-box experience
(OOBE) has finished.

Open the Portal's physical camera cover and turn off its camera/microphone
privacy control.

<a id="connect-to-the-portal"></a>
### 3. Connect to the Portal

Stock firmware disables ADB after every reboot, and the first
connection is made over USB. Two things only you can do on the
Portal itself:

1. Open the Portal's Debug menu (available once the initial
   on-screen setup has finished) and turn ADB on.
2. When the Portal asks whether to allow this computer, tap
   **Allow**.

Everything else is guided. Plug in the USB data cable and run:

```sh
python3 tools/provision_portal.py --connect
```

Guided connect finds the USB-connected Portal, waits while you
do the two steps above (it says what it is waiting for), switches
the Portal to wireless ADB itself, reads the Portal's Wi-Fi
address from the device, and connects to it. It ends by printing
the serial, which looks like `192.168.1.100:5555`. You do not
need to find the address yourself; if you ever do need it, it is
also in your router's client list.

`--connect` can also be combined with a provisioning command
(`--connect --full`), in which case the run continues on the
wireless connection it just made.

Manual alternative: the same steps by hand are

```sh
adb -d get-state
adb -d tcpip 5555

export PORTAL_IP=192.168.1.100  # replace with the Portal's address
adb connect "$PORTAL_IP:5555"
adb -s "$PORTAL_IP:5555" get-state
```

Both state checks must print `device`. Keep USB connected during the first
provisioning run.

The provisioner begins from a clean reboot. On an unprovisioned Portal, enable
ADB again in the Debug menu and rerun `adb -d tcpip 5555` after every reboot
until the provisioner prints `WIRELESS_ADB_OK`. Keep a second terminal ready
for this step. After the first successful exploit, wireless ADB survives normal
reboots and USB is no longer needed.

### 4. Confirm compatibility

Use the serial guided connect printed (or `"$PORTAL_IP:5555"` if you
connected manually):

```sh
adb -s "$PORTAL_IP:5555" shell getprop ro.product.device
adb -s "$PORTAL_IP:5555" shell getprop ro.build.fingerprint
```

Both values must exactly match the [supported model](#supported-models). The
provisioner checks them again before changing anything.

<a id="run-the-provisioner"></a>
### 5. Run the provisioner

From inside the extracted bundle directory, run a full setup with:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" --full
```

Running from inside the extracted bundle is detected automatically, so
no `--bundle` flag is needed; `--bundle PATH` still names a bundle
explicitly when you run from a source checkout instead.

Before anything changes, the run prints a plain-language summary of
what it is about to do — including a warning when the one-way Meta
account removal is part of it — and, on an interactive terminal, asks
for confirmation. `--serial` also accepts a bare IP address (`:5555`
is added) and can be omitted when exactly one device is connected.

`--full` is a preset, not a separate mode: it is exactly this flag line:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --audio --debloat --remove-meta-accounts --optimize-presence \
  --disable-adb-auth-timeout --autoroot
```

To apply only some features, drop `--full` and combine the individual
flags you want; each is explained under [Feature flags](#feature-flags).

The Portal reboots several times and ends with `PROVISION_OK`.

## Feature flags

The flags fall into three groups: **the setup** (what the Portal
ends up as), **root access modes** (how much standing root access
the Portal keeps), and **run controls** (how this one run behaves;
they change no end state).

### The setup

Presets first: `--full` applies the whole documented setup line
(see step 5), and it is the only preset. Or combine the individual flags:

- `--audio` — disable hardware echo cancellation and noise suppression, so the microphone is not suppressed while the speaker plays.
- `--debloat` — turn off Meta's control and background services in one step: disable unused Meta apps, cloud clients and diagnostics (the list depends on the model: up to 196 components on most models, 39 on the Portal+ (1st generation) and 14 on Portal TV), block Meta system updates, block Meta remote wipe, turn Android Private DNS off so the Portal uses the network's DNS (including private LAN hostnames), and disable Meta's app verifier so non-Meta apps can update normally.
- `--remove-meta-accounts` — remove local Meta accounts. **One-way** (see [What can't be undone](#what-cant-be-undone)). Never part of a preset other than `--full`, and always a deliberate step.
- `--optimize-presence` — reduce AIService CPU use while preserving full-view, LED-free person detection.
- `--presence-fps-cap N` — cap Meta's presence-analysis frame rate (with `--optimize-presence`) without limiting the camera's capture rate.
- `--disable-adb-auth-timeout` — keep already-approved ADB computers authorized indefinitely. A new computer must still be approved on the Portal; this does not disable ADB authentication.
- `--persistent-wireless-adb` — apply only persistent wireless ADB (port 5555) plus the authorization-timeout change above, and nothing else. Wireless ADB persistence is also installed automatically whenever another privileged provisioning action runs.
- `--system-theme-control light|dark` — enable live light/dark theme control on locked Android 10 Portals and set the theme. (The Portal's own settings offer no system dark-theme switch on these builds — the Display panel's Night Mode is a dimming feature, not the Android theme — so the tool provides it.)

### Root access modes

- `--shizuku` — install Shizuku and start it automatically after every boot, giving apps ADB-shell privileges. `--shizuku-apk PATH` uses a specific Shizuku APK; `--remove-shizuku` removes Shizuku again.
- `--autoroot` — root comes back by itself after every reboot, with no computer involved: the Portal re-roots on each boot and restarts Shizuku as root. Implies `--shizuku`. One caution, in plain words: at the start of each boot there is a short window in which apps on the Portal could ask for root commands without any password; the window closes as soon as Shizuku has taken over, and none of it survives the boot. Autoroot tries at most 8 times in any hour, and it gives up rather than looping forever: attempts that start but never finish count against a failure budget. After 10 such boots in a row, the on-device helper turns autoroot off by itself and posts a notification. Setup also records the Portal software build it was made for: if the Portal later updates to a different build, the helper checks the build at every boot before trying anything, turns autoroot off for that build, and posts a notification naming the build it found, because the setup no longer matches it. Re-running setup for the new build turns it back on. Open the helper from the notification to turn it back on; if the fault is still there, it turns off again after 10 more bad boots. The helper app also shows the session state and offers stop, disable/enable and run-now controls. Validated end-to-end on the Portal+ (`aloha`) build; other supported models have not been validated for this mode.
- `--skip-shizuku-root` — with `--autoroot`, keep Shizuku in its normal shell mode instead of restarting it as root.

### Run controls

- `--connect` — guided connect (see step 3): find the USB-connected Portal, switch it to wireless ADB, read its Wi-Fi address and connect. Combined with action flags, the run continues on that connection; on its own it just connects and prints the serial.
- `--serial SERIAL` — the ADB serial to talk to: a USB serial, `IP:5555`, or a bare IP address (`:5555` is added). With no `--serial`, the only connected device is used.
- `--attempts N` — maximum exploit attempts per phase (default 12, between 1 and 100).
- `--verify-boots N` — verification boots after a run (default 1; `2` adds a second distinct verification boot).
- `--force` — redo the full provisioning from the start, even on an already provisioned Portal (see [Troubleshooting](#troubleshooting)).
- `--version` — print the provisioner version and exit.
- `--log-dir DIR` — where attempt logs are written (default: a timestamped directory in the system temp folder).
- `--bundle PATH` — provision from a prebuilt bundle (directory or archive) instead of building from source. Detected automatically when running from inside an extracted bundle.
- `--skip-build` — skip the source build and use outputs already built (source checkouts only).

## Restoring changes

`--restore <name>` undoes one feature; the flag is repeatable, so one
command can restore several. A restore replays the original state the
provisioner recorded before the change, or the factory default where no
original was recorded. The available names are:

`audio`, `debloat`, `presence`, `presence-fps`, `adb-auth-timeout`,
`camera-light`, `autoroot`, `wireless-adb`, `theme`,
`meta-authenticators`

Notes:

- `--restore debloat` undoes the whole debloat group (the disabled
  apps, the update block, the remote-wipe block, Private DNS and the
  app verifier) from the originals recorded before the change.
- `--restore autoroot` removes the autoroot helper, its runner and the
  ADB key it authorized. Shizuku stays installed; use
  `--remove-shizuku` to remove it.
- `--restore wireless-adb` returns a device to stock wireless-ADB
  behavior: it clears the saved port, so wireless ADB no longer turns
  itself back on after reboots.
- `--restore presence` also removes the frame-rate cap and its helper.
- `camera-light` is cleanup only: the camera indicator action is retired, and the restore removes what older runs installed.
- Meta-account removal has no restore (see [What can't be undone](#what-cant-be-undone)).

## Status, backups and recovery

### Status report

Print a read-only JSON report without exploiting or rebooting the Portal:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --status
```

The report includes the Portal's retail model, exact build and kernel
(the same information a support request for another build needs),
whether the build is supported, and the current state of the audio fix,
update blocking, remote-wipe protection, debloat, accounts, presence,
Private DNS, theme control, Shizuku, and the last provisioning run.

### Dry-run planning

Preview an action set without changing the device:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat --dry-run
```

The plan identifies required build outputs, host tools, exploit use,
estimated minimum reboots, and the current state.

### Diagnostics collection

Collect a read-only diagnostics bundle (device identity and a bug
report) without changing anything. It works on any build, supported
or not:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --collect-diagnostics
```

### Backup bundles

Create a private diagnostic and configuration archive before making changes:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --backup ./backups
```

`--backup` may also accompany a provisioning command. The archive
contains the status report, service dumps from the Portal, snapshots
that restores can put back, and a checksum list. It can contain account
names and device configuration, so store it as sensitive data.

### Interrupted-run recovery

If power or the host fails during a run, reconnect ADB and resume the
run from where it left off with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --recover
```

For a completed run, or a Portal with no interrupted run saved,
`--recover` prints the status and exits without changing anything.

<a id="running-and-troubleshooting"></a>
## Troubleshooting

The root exploit is a race, so a run may need several attempts. The
default maximum is 12 attempts per phase (`--attempts N`, between 1 and
100); a failed attempt normally just reboots the Portal and tries again.

- Before `WIRELESS_ADB_OK` has appeared, re-enable ADB in the Portal's Debug menu and run `adb -d tcpip 5555` after every reboot.
- If the Portal remains unresponsive, power-cycle it, restore USB and wireless ADB, and rerun the same command; completed provisioning actions are designed to be repeatable.
- Re-running on an already provisioned Portal is supported as-is: the provisioner pauses the on-device autoroot while it works and restores it when the run ends. If nothing has changed since setup finished, the rerun ends right away and changes nothing; if some settings have changed since, it applies just the difference using the root access already on the device, without re-running the exploit. Use `--force` to skip both shortcuts and redo the full provisioning from the start.
- Do not cut power (including with a smart plug) to a Portal that is stuck in a failed-boot state until it has either completed one clean boot or you have captured its state first (`adb shell dumpsys wifi` and `adb shell logcat -d`, saved off-device). A hard power cut lands without any filesystem sync, and a boot that connected to WiFi but never got a clean shutdown can lose the saved network record — the Portal then comes up with no WiFi configured and the password has to be re-entered by hand. Where a cut is genuinely unavoidable, treat WiFi re-entry afterwards as an expected follow-up, not a surprise.
- Display every available option with `python3 tools/provision_portal.py --help`. Read the final `PROVISION_OK` line and keep the attempt log directory when diagnosing a failure.

<a id="how-the-root-exploit-works"></a>
## How the root exploit works

The project adapts GhostLock,
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), to
specific Portal kernels. It works only on the exact model and firmware
builds listed under [Supported models](#supported-models): the
provisioner checks the Portal's identity before it starts and refuses
anything else.

The exploit opens a short window of root access during a controlled
reboot. The root-access path first repairs the small amount of damage
the race leaves behind in the kernel, then does the run's work. The
exploit does not install `su` or a root shell, and when the run is done
the Portal reboots normally and every change is checked on that
following boot.

## Advanced: building from source

Most users should use the release bundle (see
[Step-by-step installation](#step-by-step-installation)). Building from
source is an alternative for development or for a model the bundle does
not cover.

Source builds require:

- Linux or macOS with Git, GNU Make, Python 3.9 or newer and Android Debug Bridge (`adb`). Source builds are not supported under native Windows Python (the build drives GNU Make and POSIX shell recipes); on Windows use the prebuilt bundle, or run the source build inside WSL2
- Android NDK r28.2 (`28.2.13676358`)
- A JDK plus Android SDK Platform 36 and Build Tools containing `aapt`, `zipalign`, `apksigner` and `d8`
- A USB data cable for initial stock-device setup
- Internet access when the pinned Shizuku APK must be downloaded

The provisioner uses only the Python standard library. It finds an
SDK at the standard per-user locations (`$HOME/Android/Sdk`,
`$HOME/Library/Android/sdk` on macOS, `%LOCALAPPDATA%\Android\Sdk`
on Windows, `$HOME/android-sdk`); set `ANDROID_SDK_ROOT` for an SDK
installed anywhere else.

Clone the repository:

```sh
git clone https://github.com/itsgreat2misha/portal-root-kiosk-satellite.git
cd portal-root-kiosk-satellite
```

If your SDK is somewhere else, set these paths in the terminal where you run
the provisioner:

```sh
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export NDK="$ANDROID_SDK_ROOT/ndk/28.2.13676358"
export ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
export BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/37.0.0"
export D8="$BUILD_TOOLS/d8"
```

Then connect the Portal as in steps 2–4 of the installation guide and run
the provisioner from the checkout without `--bundle`:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" --full
```

Use `--skip-build` only when the required outputs have already been built
and have not changed. Every root-backed action requires both the selected
exploit library and `exploit-sentinel/build/portal-exploit-sentinel.apk`;
the provisioner installs that no-permission package temporarily, confirms
that `run-as` accepts it, and removes it automatically. The reference root
daemon is built with `make -C root-daemon`.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE)
and [NOTICE](NOTICE) for the full terms and attribution. This project is
a fork of the original Portal provisioner created by
[jxlarrea](https://github.com/jxlarrea); the exploit research and the
original implementation are his, and the fork's changes are recorded in
[FORK.md](FORK.md).
