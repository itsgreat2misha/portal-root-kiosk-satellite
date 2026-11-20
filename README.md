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
reboot, applies the features you select, then verifies them on a following
normal boot by default (`--verify-boots 2` verifies across two boots
instead).

Root access itself is not persistent. It lasts only for the provisioning
window unless you enable automatic re-rooting after every reboot
(`--autoroot`), which restores the root daemon and root-mode Shizuku on
each boot with no host involved.

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

## What a full setup does

Every feature is selected with its own flag. `--full` is a preset that
combines the core system features below (its exact expansion is shown in
[step 5](#5-run-the-provisioner)); combine individual flags instead if
you want only some of them. Each flag is described under
[Feature flags](#feature-flags).

| Feature | What it does |
| --- | --- |
| Temporary root provisioning | Opens a short privileged window for the selected changes, then returns the Portal to normal enforcing mode. |
| Persistent wireless ADB | Keeps ADB available on port 5555 after setup, so later reboots no longer require USB activation. |
| Non-expiring ADB authorization | Keeps computers you already approved authorized instead of forgetting their ADB keys after Android's timeout. |
| Hardware audio processing control | Stops the Portal from suppressing microphone audio while its speaker is playing. |
| Firmware-update blocking | Prevents an unexpected Meta update from breaking a known working setup. |
| Meta remote-wipe blocking | Disables Meta's known remote factory-reset entry points while retaining local recovery options. |
| Meta app debloat | Reduces background work from unused Meta apps, cloud clients and diagnostics. |
| Meta-account removal | Removes obsolete local account data while retaining services the camera and Portal need. **One-way: cannot be undone** (see [What can't be undone](#what-cant-be-undone)). |
| Presence optimization | Lowers AIService CPU use while preserving full-view, LED-free person detection. |
| Presence frame-rate cap | Optional: further reduces presence-analysis work without limiting the camera's capture frame rate. |
| DNS configuration | Optional: use the network-provided DNS server, or send DNS to a chosen filtering resolver. |
| Third-party app updates | Lets correctly signed third-party and other non-Meta APKs update normally. |
| Runtime system theme control | Optional: switches locked Android 10 Portals between light and dark mode. |
| Automatic Shizuku startup | Optional: starts Shizuku after every boot for apps that need ADB-shell privileges. |
| Per-boot root daemon | Optional: leaves a small root command daemon running on loopback for the rest of the boot. |
| Root-mode Shizuku | Optional: restarts Shizuku as UID 0 through the root daemon instead of as the shell user. |
| Automatic re-rooting | Optional: re-runs the exploit automatically after every reboot, with no host involved. |

The provisioner also refuses any kernel change unless the model and full
firmware fingerprint match a supported target exactly, retries
race-sensitive attempts, and accepts changes only after verification on
a following boot. Read-only status, dry-run planning, backup bundles and
interrupted-run recovery are covered under
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

Releases ship the bundle as both `.zip` and `.tar.gz`; on Windows
download the `.zip`. Run the provisioner with `python` on Windows
and `python3` on macOS/Linux (the examples in this document use
`python3`).

### Portal

- An exact model and firmware build listed under [Supported models](#supported-models)
- The initial on-screen setup (OOBE) completed so the Debug menu is available
- ADB enabled in the Portal's Debug menu and the host authorized over USB
- Wireless ADB enabled for the current boot with `adb -d tcpip 5555`
- Stable network, a stable IP address and external power for several reboots
- For presence features: the physical camera cover open and the camera/microphone privacy control off. A closed cover no longer fails the run: the durable presence state is verified and the live verification defers to a later run with the cover open. Nobody needs to remain in view during the reboot sequence.

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
The `aloha` software family is shared by more than one first-generation form
factor. The original 10-inch Portal and 15.6-inch Portal+ share their firmware
and kernel port, but the provisioner keeps separate exact product-model guards
for `Portal` and `Portal+`.

To request support for another build, open an issue with the retail model
and this output. Do not publish an ADB address, pairing code or account
information.

```sh
adb shell getprop ro.product.model
adb shell getprop ro.product.device
adb shell getprop ro.build.fingerprint
adb shell uname -a
```

## Step-by-step installation

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

### 1. Download the release bundle

Download `portal-provisioner-bundle-0.9.0.tar.gz` (or the `.zip` of the
same name on Windows) from the project's releases, extract it, and change
into the extracted directory. The bundle is a complete runnable checkout:
it carries one payload per supported model plus the shared helper APKs,
and needs no clone and no Android toolchain.

Before anything changes on the Portal, the provisioner checks the
bundle's manifest against the device's exact target and verifies every
file's SHA-256 hash (release bundles also carry a signature over the
manifest, checked against the project's pinned release certificate). A
bundle that does not carry the device's build, or whose files do not
verify, refuses the run and the device is left untouched.

### 2. Prepare the Portal

Complete the Portal's initial on-screen setup before continuing. The Debug
menu and its ADB control are unavailable until the out-of-box experience
(OOBE) has finished.

Open the Portal's physical camera cover and turn off its camera/microphone
privacy control.

<a id="connect-to-the-portal"></a>
### 3. Connect to the Portal

Stock firmware disables ADB after every reboot. Open the Portal's Debug menu,
enable ADB, connect the USB data cable, authorize the host and run:

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

```sh
adb -s "$PORTAL_IP:5555" shell getprop ro.product.device
adb -s "$PORTAL_IP:5555" shell getprop ro.build.fingerprint
```

Both values must exactly match the [supported model](#supported-models). The
provisioner checks them again before making any kernel change.

<a id="run-the-provisioner"></a>
### 5. Run the provisioner

From inside the extracted bundle directory, run a full setup with:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" --full \
  --bundle .
```

(`--bundle` names the bundle to provision from: the extracted directory
when you run from inside it, or the downloaded archive file when you run
from a source checkout instead.)

`--full` is a preset, not a separate mode: it expands to the documented
full-setup line plus `--autoroot`:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --audio --disable-updates --block-remote-wipe --debloat \
  --remove-meta-accounts --optimize-presence --allow-app-updates \
  --disable-adb-auth-timeout --autoroot
```

To apply only some features, drop `--full` and combine the individual
flags you want; each is explained under [Feature flags](#feature-flags).

The Portal reboots several times and ends with `PROVISION_OK` plus the
verification boot ID (two different boot IDs with `--verify-boots 2`).

## Feature flags

### Core features (all included in `--full`)

- `--audio` — disable hardware echo cancellation and noise suppression, so the microphone is not suppressed while the speaker plays.
- `--disable-updates` — block automatic Meta firmware updates.
- `--block-remote-wipe` — disable Meta's known remote factory-reset receivers; local recovery stays available.
- `--debloat` — disable unused Meta apps, cloud clients and diagnostics. The list depends on the model: up to 196 components on most models, 39 on the Portal+ (1st generation) and 14 on Portal TV. It also turns Android Private DNS off, so the Portal uses the DNS server supplied by the local network, including private LAN hostnames.
- `--remove-meta-accounts` — remove local Meta accounts. **One-way** (see [What can't be undone](#what-cant-be-undone)).
- `--optimize-presence` — reduce AIService CPU use while preserving full-view, LED-free person detection.
- `--allow-app-updates` — let correctly signed third-party and other non-Meta APKs update normally.
- `--disable-adb-auth-timeout` — keep already-approved ADB computers authorized indefinitely. A new computer must still be approved on the Portal; this does not disable ADB authentication.

### Standalone

- `--persistent-wireless-adb` — apply only persistent wireless ADB (port 5555) plus the authorization-timeout change above, and nothing else. Wireless ADB persistence is also installed automatically whenever another privileged provisioning action runs.

### Optional add-ons

- `--presence-fps-cap N` — cap Meta's presence-analysis frame rate (with `--optimize-presence`) without limiting the camera's capture rate.
- `--system-theme-control light|dark` — enable live light/dark theme control on locked Android 10 Portals and set the theme.
- `--shizuku` — install Shizuku and start it automatically after every boot. `--shizuku-apk PATH` uses a specific Shizuku APK; `--remove-shizuku` removes Shizuku again.
- `--autoroot` — re-run the exploit automatically after every reboot and restore the root daemon and root-mode Shizuku with no host involved. Implies `--shizuku` and the root-daemon step. During each boot's root window the root daemon listens on loopback (127.0.0.1:37373) with no authentication — any app on the Portal that can open a loopback connection can run commands as UID 0 while it is up; it is stopped once root-mode Shizuku is verified, and it never survives the boot on its own. A session allows up to 8 attempts in a 60-minute window. Attempts that start but never finish count against a failure budget: After 10 such boots in a row, the on-device helper turns autoroot off by itself and posts a notification instead of crash-looping the Portal. Open the helper from the notification to re-enable it; the budget re-arms, so a fault that is still there turns autoroot off again after 10 more bad boots. The helper app also shows the session state and offers stop, disable/enable and run-now controls. Validated end-to-end on the Portal+ (`aloha`) build; other supported models have not been validated for this mode.

### Run controls

- `--serial SERIAL` — the ADB serial to talk to (a USB serial or `IP:5555`).
- `--attempts N` — maximum exploit attempts per phase (default 12, between 1 and 100).
- `--verify-boots N` — verification boots after a run (default 1; `2` adds a second distinct verification boot).
- `--force` — redo the full race-based provisioning even on an already provisioned Portal (see [Troubleshooting](#troubleshooting)).
- `--log-dir DIR` — where attempt logs are written (default: a timestamped directory in the system temp folder).

## Restoring changes

`--restore <name>` undoes one feature; the flag is repeatable, so one
command can restore several. A restore replays the original state the
provisioner recorded before the change, or the factory default where no
original was recorded. The available names are:

`audio`, `bloat`, `remote-wipe`, `updates`, `dns`, `presence`,
`presence-fps`, `adb-auth-timeout`, `app-verifier`, `camera-light`,
`autoroot`, `wireless-adb`, `theme`, `meta-authenticators`

Notes:

- `--restore autoroot` uninstalls the autoroot helper and removes its staged runner, saved key material and authorized ADB key. Shizuku and the exploit sentinel stay installed; use `--remove-shizuku` for Shizuku itself.
- `--restore wireless-adb` returns a device to stock wireless-ADB behavior: it clears the persisted port and the boot-enforcement markers.
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

The report includes exact target support, boot and SELinux state, audio
and OTA markers, remote-wipe protection, debloat and account status, the
live presence pipeline, Private DNS, system-theme control, Shizuku
package and server state, and the last provisioning manifest.

### Dry-run planning

Preview an action set without changing the device:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat --dry-run
```

The plan identifies required build outputs, host tools, exploit use,
estimated minimum reboots, and the current state.

### Backup bundles

Create a private diagnostic and configuration archive before making changes:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --backup ./backups
```

`--backup` may also accompany a provisioning command. The archive
contains status, relevant Android service dumps, reversible device
snapshots, and a SHA-256 manifest. It can contain account names and
device configuration, so store it as sensitive data.

### Interrupted-run recovery

Every mutating run writes a state manifest at
`/data/local/tmp/portal-provision-state-v1.json`. It records the exact
target, firmware fingerprint, selected actions, Git revision, artifact
hashes, state, and verification boot IDs. If power or the host fails
during a run, reconnect ADB and resume the pending action set with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --recover
```

Recovery first removes stale staged files. It resumes only a validated
pending manifest; for a completed run or a device with no manifest, it
prints status and exits without changing the configuration.

<a id="running-and-troubleshooting"></a>
## Troubleshooting

Kernel exploitation is race-sensitive. The default maximum is 12 exploit
attempts (`--attempts N`, between 1 and 100); a failed race normally
causes a clean reboot and another attempt.

- Before `WIRELESS_ADB_OK` has appeared, re-enable ADB in the Portal's Debug menu and run `adb -d tcpip 5555` after every reboot.
- If the Portal remains unresponsive, power-cycle it, restore USB and wireless ADB, and rerun the same command; completed provisioning actions are designed to be repeatable.
- Re-running on an already provisioned Portal is supported as-is: the provisioner automatically pauses the on-device autoroot for the duration of the run and restores it when the run ends. If nothing has changed since the recorded provisioning completed, the rerun exits immediately as a no-op; if only settings or artifacts drifted, it applies just the difference through the device's existing root setup without re-running the exploit races. Use `--force` to bypass both shortcuts and redo the full race-based provisioning.
- Do not cut power (including with a smart plug) to a Portal that is stuck in a failed-boot state until it has either completed one clean boot or you have captured its state first (`adb shell dumpsys wifi` and `adb shell logcat -d`, saved off-device). A hard power cut lands without any filesystem sync, and a boot that connected to WiFi but never got a clean shutdown can lose the saved network record — the Portal then comes up with no WiFi configured and the password has to be re-entered by hand. Where a cut is genuinely unavoidable, treat WiFi re-entry afterwards as an expected follow-up, not a surprise.
- Display every available option with `python3 tools/provision_portal.py --help`. Read the final `PROVISION_OK` line and keep the attempt log directory when diagnosing a failure.

<a id="how-the-root-exploit-works"></a>
## How the root exploit works

The project adapts GhostLock,
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), to a
specific Portal kernel. The provisioner confirms the complete device
identity, reboots into a clean state, derives randomized kernel addresses
and starts the exploit through a staged native library. Temporary kernel
read/write access gives only that process the credentials needed to
perform the selected work.

The device then reboots normally with SELinux enforcing. In the default
flow the exploit does not install `su`, a root shell or a root daemon.
Features that must survive reboot use narrow configuration changes or
dedicated helpers with only the privileges they need, and the requested
state is verified on a following normal boot (two boots with
`--verify-boots 2`).

The root-payload step is the deliberate exception: it starts the
root daemon inside the privileged window instead of returning straight
to a normal boot. Because the race leaves the kernel's `proc_uid` lock
waiter tree damaged — the reason the stock flow reboots immediately —
the payload path first repairs that tree to its canonical empty state.
The repair is pattern-gated: it writes only when the current state
matches the exact expected damage shape, and it verifies the result by
read-back. On any mismatch it writes nothing and the attempt counts as
a miss.

Exact model and firmware checks prevent the provisioner from using one
build's kernel layout on another device.

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
