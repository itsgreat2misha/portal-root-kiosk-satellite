# Meta Portal Root Provisioner

Provision and root Meta Portal devices with a controlled, exact-build
root exploit. All changes are persistent and survive reboots.

> **Credits:** This project is a fork of the original Portal provisioner
> created by [jxlarrea](https://github.com/jxlarrea) — the original
> project and its exploit work are his.

## Overview

The provisioner checks that the connected Portal has an exact supported model
and firmware build, briefly uses a root exploit during a controlled reboot,
applies the features you select, then verifies them across two normal boots.
Persistent features use focused configuration changes or small boot helpers.

> [!NOTE]
> This is not a persistent root exploit. It is a timed, surgical way to change otherwise inaccessible system settings and make the most of a Portal device. All features applied by the provisioner are persistent and survive reboots — but root access itself does not, unless you deliberately enable one of the two opt-in root modes below: a root daemon that runs for the rest of the boot (`--custom-payload`), or automatic re-rooting after every reboot (`--autoroot`).

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

## What the provisioning does

| Feature | What it does and why it helps |
| --- | --- |
| [Temporary root provisioning](#how-the-root-exploit-works) | Opens a short privileged window for selected changes, then returns the Portal to normal enforcing mode. |
| [Persistent wireless ADB](#enable-only-persistent-wireless-adb) | Keeps ADB available on port 5555 after setup, so future reboots no longer require USB activation. |
| [Non-expiring ADB authorization](#disable-adb-authorization-timeout) | Keeps computers you already approved authorized instead of forgetting their ADB keys after Android's timeout. |
| [Hardware audio processing control](#disable-hardware-echo-cancellation-and-noise-suppression) | Stops the Portal from suppressing microphone audio while its speaker is playing audio or music. |
| [Firmware-update blocking](#disable-automatic-meta-firmware-updates) | Prevents an unexpected Meta update from breaking a known working setup. |
| [Meta remote-wipe blocking](#block-metas-known-remote-wipe-receivers) | Disables Meta's known remote factory-reset entry points while retaining local recovery options. |
| [Meta app debloat](#disable-unused-meta-applications) | Reduces background work from unused Meta apps, cloud clients and diagnostics. |
| [Meta-account removal](#remove-local-meta-accounts) | Removes obsolete local account data while retaining services needed by the camera and Portal. |
| [Presence optimization](#reduce-aiservice-cpu-use-while-preserving-presence-detection) | Lowers AIService CPU use while preserving full-view, LED-free person detection. |
| [Presence frame-rate cap](#optional-presence-analysis-frame-rate-cap) | Further reduces analysis work without limiting the camera's capture frame rate. |
| [Filtering Private DNS](#configure-dns) | Sends DNS to a chosen DNS-over-TLS resolver for network-level filtering. |
| [Network-provided DNS](#configure-dns) | Uses the DNS server supplied by the local network, including private LAN hostnames. |
| [Third-party app updates](#allow-third-party-app-updates) | Lets correctly signed third-party and other non-Meta APKs update normally. |
| [Runtime system theme control](#control-the-runtime-system-theme) | Switches locked Android 10 Portals between light and dark mode through a constrained UID-1000 worker. |
| [Automatic Shizuku startup](#install-shizuku-with-automatic-startup) | Starts Shizuku locally after every boot for apps that need ADB-shell privileges. |
| [Per-boot root daemon](#per-boot-root-daemon) | Leaves a small root command daemon running on loopback for the rest of the boot, after repairing the kernel lock state the exploit leaves behind. |
| [Root-mode Shizuku](#run-shizuku-as-root) | Restarts Shizuku as UID 0 through the root daemon instead of as the shell user. |
| [Automatic re-rooting](#automatic-re-rooting-with-autoroot) | Re-runs the exploit automatically after every reboot and restores the root daemon and root-mode Shizuku with no host involved. |
| [Read-only status](#status-report) | Reports the device, provisioning and runtime state without exploiting or rebooting. |
| [Dry-run planning](#dry-run-planning) | Shows required tools, actions and reboots before changing the Portal. |
| [Private backup bundles](#backup-bundles) | Saves diagnostics and reversible settings in a private, checksummed archive. |
| [Interrupted-run recovery](#interrupted-run-recovery) | Safely resumes a validated provisioning run after a host or power interruption. |
| [Exact-build safeguards](#supported-models) | Refuses kernel changes unless the model and full firmware fingerprint match. |
| [Automatic retry and verification](#running-and-troubleshooting) | Retries race-sensitive attempts and accepts changes only after two verified boots. |

## Requirements

### Host computer

- Linux x86_64 with Git, GNU Make, Python 3.9 or newer and Android Debug Bridge (`adb`)
- Android NDK r28.2 (`28.2.13676358`)
- A JDK plus Android SDK Platform 36 and Build Tools containing `aapt`, `zipalign`, `apksigner` and `d8`
- A USB data cable for initial stock-device setup
- Internet access when the pinned Shizuku APK must be downloaded

The provisioner uses only the Python standard library.

### Portal

- An exact model and firmware build listed under [Supported models](#supported-models)
- The initial on-screen setup (OOBE) completed so the Debug menu is available
- ADB enabled in the Portal's Debug menu and the host authorized over USB
- Wireless ADB enabled for the current boot with `adb -d tcpip 5555`
- Stable network, a stable IP address and external power for several reboots
- The physical camera cover open and camera/microphone privacy control off for presence features

Presence verification checks the live camera pipeline automatically. Nobody
needs to remain in view during the reboot sequence.

## Supported models

| Model | Codename | Android | Supported firmware fingerprint | Kernel | Status |
| --- | --- | --- | --- | --- | --- |
| Meta Portal Go | `terry` | 10 | `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal 10-inch (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Tested |
| Meta Portal+ (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Tested |
| Meta Portal+ (2nd generation) | `cipher` | 10 | `Facebook/cipher_prod/cipher:10/QKQ1.210213.001/4051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal 10-inch (2nd generation) | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal Mini | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal TV | `ripley` | 9 | `Facebook/ripley_prod/ripley:9/PKQ1.191202.001/2041515800015050:user/prod-keys` | `4.4.153+` | Tested |

Thank you to [@protocol113](https://github.com/protocol113) for providing
Portal TV access and sharing the exploit timing observations that helped
validate `ripley` support.

Support is exact-build specific. Other models and firmware versions
need their own verified target before the provisioner will accept them.
The `aloha` software family is shared by more than one first-generation form
factor. The original 10-inch Portal and 15.6-inch Portal+ share their firmware
and kernel port, but the provisioner keeps separate exact product-model guards
for `Portal` and `Portal+`.

Other firmware builds still need their own verified target. To request support,
open an issue with the retail model and this output. Do not publish an ADB
address, pairing code or account information.

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

### 1. Install and configure the host tools

Install the tools listed under [Requirements](#requirements), then clone the
repository. The provisioner automatically finds an SDK installed at
`$HOME/Android/Sdk` or `$HOME/android-sdk`.

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

There is no bundled profile: you select exactly the features you want.
A full setup combining the core system features looks like:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --audio --disable-updates --block-remote-wipe --debloat \
  --remove-meta-accounts --optimize-presence --allow-app-updates \
  --disable-adb-auth-timeout
```

Each flag is explained in the reference below; combine only the ones you
want. Common add-ons:

- `--presence-fps-cap 2` to reduce Meta's presence-analysis rate
- `--dhcp-dns` or `--privacy-dns HOSTNAME` to change DNS behavior
- `--system-theme-control light|dark` to enable and set live theme control
- `--shizuku` to install Shizuku with automatic startup
- `--custom-payload` to leave a per-boot root daemon running and restart
  Shizuku as root (a bare flag builds and uses this repository's daemon)
- `--autoroot` to re-establish root automatically after every reboot
  (it implies `--shizuku` and `--custom-payload`)

The Portal reboots several times and ends with `PROVISION_OK` plus two
different verification boot IDs.

## Provisioning feature reference

Every feature is selected with its own flag; there is no bundled
profile. The sections below give the technical details and rollback
commands for each. Features labeled **Optional add-on** are never part
of a default flow.

<a id="enable-only-persistent-wireless-adb"></a>
<details>
<summary><strong>Standalone setup:</strong> Enable only persistent wireless ADB</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --persistent-wireless-adb
```

This applies only wireless ADB persistence on TCP port 5555. It does not
enable audio changes, debloat, presence optimization, Shizuku,
or the other provisioning features. It also disables Android's authorization
timeout so computers you already approved do not lose access later. Wireless
ADB persistence is already installed automatically whenever another privileged
provisioning action runs; a new persistence install also disables the
authorization timeout.

On a stock Portal, continue manually enabling ADB in the Debug menu and running
`adb -d tcpip 5555` after each provisioning reboot until the command prints
`WIRELESS_ADB_OK`. Later reboots no longer require the USB host.

</details>
<p></p>

<a id="disable-adb-authorization-timeout"></a>
<details>
<summary>Keep approved ADB computers authorized</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --disable-adb-auth-timeout
```

Android normally expires approved ADB host keys after a period of inactivity.
This sets `adb_allowed_connection_time` to `0`, which tells Android to retain
previously approved keys indefinitely. A new computer must still be approved on
the Portal; this does not disable ADB authentication. The provisioner also
ensures Android's `adb_enabled` framework setting is on so the authorization
prompt can appear for that new computer. It saves the original connection-time
setting before changing it.

On every supported Portal target, privileged provisioning that removes the Meta
accounts or selects non-expiring ADB authorization installs UID-1000 boot
enforcement that restores `adb_enabled=1` if firmware changes it. This includes
`--persistent-wireless-adb`. Portal 10-inch and Portal
Mini Omni firmware also use the same helper to recover adbd itself after Meta's
late boot rules stop it.

This standalone action uses ordinary ADB authority and does not run the root
exploit or reboot the Portal.

`--persistent-wireless-adb` applies this setting automatically. To restore the
saved timeout, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-adb-auth-timeout
```

</details>
<p></p>



<a id="disable-hardware-echo-cancellation-and-noise-suppression"></a>
<details>
<summary>Disable hardware echo cancellation and noise suppression</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --audio
```

The Portal's microphone array passes through firmware-owned voice processing
before Android receives it. This action installs a native watchdog inside
Meta's AIService and selects the controls used by each hardware backend.

Portal Go and the other STAX/DBMD builds keep these private DSP parameters at
zero:

- `AEC_ENABLE` (`3001`)
- `NS_MODE` (`4001`), including residual-echo suppression

Portal Mini and second-generation 10-inch Portal (`omni`) use the MH Acoustics
MHA backend instead. On those devices the provisioner keeps the stereo capture
engine active and patches the firmware tuning profiles to disable
double-talk echo suppression, residual-echo suppression, and noise suppression
in both post-processing paths. It validates the exact shipped blob before
writing, preserves a byte-for-byte stock backup, and restores the vendor block
device's read-only state afterward. The restore action puts that stock blob
back.

The change is system-wide, so every Android application receives audio without
those processing stages. On STAX devices, the watchdog reapplies the values
after AIService starts and repairs later firmware-side changes. On MHA devices,
it reads the live hardware values and, if necessary, forces a temporary profile
transition so the tuning manager reloads the patched regular-capture profile.
It then verifies all nine suppression controls directly. The provisioner
requires real DSP readbacks on two boots. A later
`--audio` run first checks the persistent
installation marker and the running watchdog. If both are healthy, an
audio-only command exits successfully without rebuilding, exploiting, or
rebooting; when combined with other actions, only the audio installation is
skipped.

Restore Meta's original AIService loader, remove the watchdog, and restore the
firmware's AEC and NS parameter defaults with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-audio
```

The restore uses the original loader saved during the first installation and
refuses to replace an unrelated file.

</details>







<a id="disable-automatic-meta-firmware-updates"></a>
<details>
<summary>Disable automatic Meta firmware updates</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --disable-updates
```

This disables Meta's two OTA user-interface packages and installs a local
MobileConfig override setting `firmware_ota_update_enable=false`. Shared update
infrastructure remains installed, but the native OTA daemon stays idle and
does not discover or install firmware.

The provisioner verifies the disabled packages and requires Meta's own service
to report the value from the local override on two boots. It refuses to replace
an unrelated existing override. The original file state is recorded under
`/data/local/tmp/portal-ota-backup`.

Restore that exact override state and re-enable both OTA packages with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --enable-updates
```

</details>

<a id="block-metas-known-remote-wipe-receivers"></a>
<details>
<summary>Block Meta's known remote-wipe receivers</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --block-remote-wipe
```

Meta's privileged `com.facebook.alohaservices.deviceadmin` package contains a
factory-reset receiver and a cloud-notification remote-wipe receiver. This
action disables only those two components. The rest of the package remains
enabled, and hardware or recovery-menu factory resets remain available.

The provisioner records the original state of each receiver, applies the
change through Android's Package Manager, and verifies that both receivers
remain disabled across two boots. It does not claim to block every possible
privileged Android reset path; it blocks the two known Meta remote-wipe entry
points present in the supported firmware.

Restore both receivers to their individually saved states with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-remote-wipe
```

</details>

<a id="disable-unused-meta-applications"></a>
<details>
<summary>Disable unused Meta applications</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat
```

The conservative debloat profile disables these packages for user 0:

- Meta Analytics
- Messenger
- WhatsApp
- Portal Feed
- Superframe
- Meta Contacts

It also disables the matching cloud and background components inside retained
Meta packages. The exact inventories for every supported model are listed
below: 196 are disabled on the tested Portal Go, Portal Mini,
second-generation Portal 10-inch and second-generation Portal+ firmware, and
194 are disabled on the original first-generation Portal. The tested
first-generation Portal+ has a smaller installed package set and disables 39.
Portal TV uses its own conservative 14-component profile.
Component-level targeting removes unused
work without disabling the camera, audio, presence, media, app-management,
identity, launcher, or WebView packages that the Portal
still needs.

On every tested model, two firmware-owned MQTT entry points are deliberately
retained because each self-enables before use; disabling either caused a
service restart loop during testing: `RegisteredMqttSystemBroadcastReceiver` in
`com.facebook.aloha.system.device` and `MqttService` in
`com.facebook.alohaservices.alohausers`. The remaining MQTT components are
disabled. To stop the retained core client from reaching Meta, apply a
source-specific router rule for the Portal or block `mqtt-mini.facebook.com`,
`graph.facebook.com`, and `facebook.com` with the only DNS resolver advertised
to the device. Android's opportunistic Private DNS can use any advertised
resolver that accepts DNS over TLS, so a public fallback resolver can bypass a
local DNS block list. Fixed-IP rules are brittle because Meta rotates these
names across its address space. The component list is maintained in
`tools/meta_debloat_components.py`.

<details>
<summary>Meta Portal Go, original Portal 10-inch, Portal Mini, Portal 10-inch (2nd generation) and Portal+ (2nd generation): up to 196 disabled components</summary>
<p></p>

On Portal Go firmware `5051355900018050`, Portal Mini and Portal 10-inch
firmware `3051355900018050`, and Portal+ firmware `4051355900018050`, the
provisioner disables the same 196 components. The two intentionally retained
MQTT components are excluded from this inventory.

The original 10-inch Portal uses this inventory too. Its tested factory image
contains 194 of the entries; the two CNS health-monitor components are absent,
so the provisioner records them as absent instead of trying to disable them.

**Background workers (143)**

- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.services/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.aloha.system.services/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.aloha.system.services/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.services/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkGuardReceiver`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkAlarmReceiver`
- `com.facebook.alohaappmanager/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkJobService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.downloadmanager.impl.DownloadIdleService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.appmanager.scheduler.background.SchedulerJobService`
- `com.facebook.alohaappmanager/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaappmanager/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaappmanager/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.bugreporter/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.launcher/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.launcher/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.player2/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.player2/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.player2/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.player2/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.portal.aiservice/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`

**Bug reporting (16)**

- `com.facebook.aloha.system.services/com.facebook.aloha.system.services.bugreporter.PillViewService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.MannerModeBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.BugReportSystemBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.BugReportNonSystemBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.PortalTVReportScreenLauncherReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.TraceBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.SmartCameraBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.bugreporter.core.scheduler.AlarmsBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.gui.BugReporterGuiService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.PushNotificationReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.core.ReportIntentService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.core.UploadStreamService`
- `com.facebook.alohaapps.bugreporter/com.facebook.bugreporter.core.scheduler.LollipopBugReportService`
- `com.facebook.alohaapps.bugreporter/com.facebook.alohacommon.bugreporterlib.AppLogsService`
- `com.facebook.alohaapps.bugreporter/androidx.work.impl.background.systemjob.SystemJobService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.bishop.BishopSupportService`

**Diagnostics (15)**

- `com.facebook.aloha.app.cameraeditor/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.cnshealthmonitor/com.facebook.aloha.cnshealthmonitor.CNSHealthMonitorBroadcastReceiver`
- `com.facebook.aloha.cnshealthmonitor/com.facebook.aloha.cnshealthmonitor.CNSHealthMonitorService`
- `com.facebook.aloha.system.device/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.system.services/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.wifidiagnostic/com.facebook.aloha.wifidiagnostic.WifiDiagnosticBootReceiver`
- `com.facebook.aloha.wifidiagnostic/com.facebook.aloha.wifidiagnostic.WifiDiagnosticService`
- `com.facebook.alohaappmanager/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.bugreporter/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.launcher/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.settings/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.abilitymanager/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.alohausers/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.player2/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.portal.aiservice/androidx.work.impl.diagnostics.DiagnosticsReceiver`

**Firebase (12)**

- `com.facebook.aloha.app.cameraeditor/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.provider.FirebaseInitProvider`
- `com.facebook.aloha.system.device/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.system.device/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.system.device/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.system.device/com.google.firebase.provider.FirebaseInitProvider`
- `com.facebook.alohaservices.alohausers/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.alohaservices.alohausers/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.alohaservices.alohausers/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.alohaservices.alohausers/com.google.firebase.provider.FirebaseInitProvider`

**MQTT (8)**

- `com.facebook.aloha.app.cameraeditor/com.facebook.push.mqtt.service.MqttPushHelperService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.multiusermqtt.MultiuserMqttService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.mqtt.service.MqttServiceV2`
- `com.facebook.aloha.app.cameraeditor/com.facebook.mqttlite.MqttService`
- `com.facebook.alohaservices.alohausers/com.facebook.push.mqtt.receiver.BootCompleteBroadcastReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.mqtt.service.MqttServiceV2`
- `com.facebook.alohaservices.alohausers/com.facebook.multiusermqtt.MultiuserMqttService`
- `com.facebook.alohaservices.alohausers/com.facebook.push.mqtt.service.MqttPushHelperService`

**Push notifications (2)**

- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationBootReceiver`
- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationService`

</details>
<p></p>
<details>
<summary>Meta Portal+ (1st generation): 39 disabled components</summary>
<p></p>

On firmware `1041515800015050`, the provisioner disables 39 components.

**Background workers (30)**

- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.portal.aiservice/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`

**Diagnostics (3)**

- `com.facebook.aloha.system.device/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.settings/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.portal.aiservice/androidx.work.impl.diagnostics.DiagnosticsReceiver`

**Firebase (4)**

- `com.facebook.aloha.system.device/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.system.device/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.system.device/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.system.device/com.google.firebase.provider.FirebaseInitProvider`

**Push notifications (2)**

- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationBootReceiver`
- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationService`

</details>
<p></p>
<details>
<summary>Meta Portal TV: 14 disabled components</summary>
<p></p>

On firmware `2041515800015050`, the provisioner disables only the following
components confirmed present on Portal TV. Its smaller application inventory
does not use the broader touchscreen Portal profile.

**Background workers (8)**

- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerService`

**Diagnostics (3)**

- `com.facebook.aloha.system.device/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.settings/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.portal.aiservice/androidx.work.impl.diagnostics.DiagnosticsReceiver`

**Firebase (3)**

- `com.facebook.aloha.system.device/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.system.device/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.system.device/com.google.firebase.provider.FirebaseInitProvider`

</details>
<p></p>
Before changing package state, the provisioner saves the exact enabled,
disabled, or absent state of every package in
`/data/local/tmp/portal-debloat-backup-v1.tsv` and every targeted component in
`/data/local/tmp/portal-debloat-components-backup-v1.tsv`. Restore those saved
states with:
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-bloat
```

Both commands verify the retained camera, AIService, launcher, and WebView
paths across two reboots.

</details>

<a id="remove-local-meta-accounts"></a>
<details>
<summary>Remove local Meta accounts</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-meta-accounts
```

This removes the Portal-specific proxy SSO, platform-login, and private-owner
accounts from Android AccountManager and Meta's local identity databases. It
then disables their three user-account authenticator components so firmware
cannot immediately recreate the accounts. The hardware-identity authenticator
and shared `alohausers` package stay enabled because camera startup,
MobileConfig, and other Portal services depend on them.

The original account type and name inventory is saved at
`/data/local/tmp/portal-meta-accounts-before-v1.tsv` and copied into the host
log directory. Tokens and full database contents are not backed up, so this
action has no automated restore. Repeated runs are safe: once the accounts are
gone and the authenticators are disabled, the tool only verifies the state.

Removing the final Meta owner account can make Portal firmware select its
obsolete invalid-owner HOME screen, which can take focus until a HOME app
is configured.

Meta's production Debug page also builds its ADB row from the signed-in owner
profile. After the local Meta accounts are removed, that page may appear empty
even though ADB remains enabled and wireless ADB remains available. Before
removing the accounts, the provisioner verifies Android's ADB framework is
enabled so future host keys can still produce the normal confirmation dialog.
To open the firmware's full Debug page from an authorized ADB computer, run:

```sh
adb -s "$PORTAL_IP:5555" shell am start \
  -a com.facebook.aloha.system.settings.DEBUG_TAB
```

</details>

<a id="reduce-aiservice-cpu-use-while-preserving-presence-detection"></a>
<details>
<summary>Reduce AIService CPU use while preserving presence detection</summary>
<p></p>

Run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --optimize-presence
```

Applications can read AIService's `Notify people presence` log to use the
Portal's person detector without activating an application camera and its
on-screen camera LED. This profile keeps that detector, AIService's camera
client, tracking, and pose estimation active while disabling four downstream
Smart Camera workloads:

- background segmentation
- liveness scoring
- color-based re-identification
- face-recognition-based re-identification

Disabling Meta's background detector by itself lets Smart Camera leave the
pose pipeline on a narrow region of interest, which severely reduces presence
coverage. The profile also sets `enable_hardware_cropping=false`. AIService
then processes the uncropped camera source, preserving the Portal's full field
of view without running the background-detector worker.

Open the Portal's physical camera cover and make sure its camera/microphone
privacy control is off before running this action. Meta intentionally stops
the AIService camera client while either hardware privacy control disables the
camera, so presence verification cannot pass in that state.

The provisioner requires an active AIService camera client, an allowed CAMERA
AppOp, live analysis and region-of-interest frame delivery, a loaded frame
processor, populated pose-estimator metrics, all five settings loaded as
false, and hardware cropping absent from the active camera request on every
verification boot. Those checks cover the same retained path
that updates AIService's world model and emits `Notify people presence`, so the
two-reboot verification can run unattended. An actual presence event is
reported as additional evidence when one occurs, but it is not required for a
successful run. On the tested Portal Go, the original cropped optimization
averaged 22.1% of one core but reduced the usable field of view. The corrected
full-scene profile measured 35.5% in a five-minute sample, compared with 47.8%
before optimization. Workload affects these figures, so treat them as a guide
rather than a fixed saving.

The original settings-file state is stored under
`/data/local/tmp/portal-presence-backup`. Restore it with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-presence-profile
```

The installer and restore action use atomic file replacement, preserve the
app's ownership and SELinux label, and refuse to overwrite an unrelated edit.

</details>

<a id="allow-third-party-app-updates"></a>
<details>
<summary>Allow third-party app updates</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --allow-app-updates
```

Meta registers `com.facebook.appverifier` as Android's package-verification
agent. It rejects APKs whose certificates are outside Meta's private allowlist,
including correctly signed third-party releases, with
`INSTALL_FAILED_VERIFICATION_FAILURE`. This action saves the existing Android
setting and verifier-package state, sets `package_verifier_enable=0`, and
disables Meta's verifier package for user 0. The package state is the durable
control if Meta later rewrites the Android setting. The provisioner verifies
both states on two separate boots.

This action is independent of Shizuku. It allows updates installed through the
normal Android confirmation screen, a Device Owner app, the optional
update helper, or Shizuku. Android continues to require a matching application
signature for updates and continues to reject version downgrades. Meta's
verifier package remains installed and can be restored to its saved state.

Restore the saved Android setting and verifier-package state with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-app-verifier
```

</details>

<a id="optional-presence-analysis-frame-rate-cap"></a>
<details>
<summary><strong>Optional add-on:</strong> Presence-analysis frame-rate cap</summary>
<p></p>

The full-scene profile keeps Meta's analysis pipeline busy at its firmware
rate. To reduce that remaining load, cap only its pose-analysis callback. Two
frames per second is the tested balance for room-presence detection:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --presence-fps-cap 2
```

Valid values are 1 through 10. This option automatically includes the tested
full-scene presence profile. It writes Meta's own analysis-throttle settings
and installs a small local boot helper that applies them after each reboot,
then stops. Applying the setting briefly opens Meta's hidden AI settings
activity and immediately returns to the configured Home app.

Android blocks an ordinary background app from opening that activity. The
provisioner therefore adds the one-shot activation to its narrowly scoped UID
1000 boot helper. That helper waits for Android and AIService to settle, opens
the hidden activity, returns to Home, and exits when no persistent helper task
remains. It does not depend on Shizuku, ADB, another computer, or network access
after installation. Both presence rollback commands remove the activation
configuration; the shared helper remains only if another feature still uses
it.

The cap is downstream of camera capture. Tests on Portal Go retained the
camera's normal `[8, 30]` target range while Meta logged a 2 FPS analysis rate.
A first-generation Portal+ also retained its full field of view and live pose
pipeline at 2 FPS across two reboots. RTSP streaming uses a separate
Camera2 capture and encoder path, so it remains free to stream at its configured
frame rate. A live Portal Go test decoded 56 RTSP frames over 9.98 seconds,
about 5.5 FPS from the configured roughly 6 FPS stream, while Meta analysis
remained at 2 FPS. The provisioner verifies the applied analysis rate, full
field of view, camera request, pose pipeline, and helper activation on two
boots.

Remove only the cap and helper while keeping the full-scene optimization:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-presence-fps
```

`--restore-presence-profile` also removes the cap and helper before restoring
the complete original presence configuration.

</details>

<a id="configure-dns"></a>
<details>
<summary><strong>Optional add-on:</strong> Configure local or filtering DNS</summary>
<p></p>

To resolve private LAN zones through the DNS servers advertised by the active
network, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --dhcp-dns
```

This disables Android's opportunistic Private DNS mode. Android then uses the
DNS servers and search domain supplied by DHCP and IPv6 router advertisements.
It does not force a particular server address, so the router must advertise
the intended local resolver. In `dumpsys connectivity`, `defaultIPv4DNS` is
only the firmware's fallback when a network supplies no resolver; the
`DnsAddresses` field in the connected network's `LinkProperties` is the active
server list. `--status` reports both lists separately.

Alternatively, configure a specific DNS-over-TLS resolver:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --privacy-dns dns.example.net
```

Replace `dns.example.net` with the DNS-over-TLS hostname of a resolver you
control or trust. The provisioner configures Android's strict Private DNS mode;
the resolver supplies the block list. This can reduce connections to unwanted
Meta endpoints without modifying system certificates or installing a broad
root firewall. Confirm that the resolver permits the services your
apps need before applying it fleet-wide.

The first DNS action saves both original Android settings. Restore them with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-privacy-dns
```

</details>

<a id="control-the-runtime-system-theme"></a>
<details>
<summary><strong>Optional add-on:</strong> Control the runtime system theme</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --system-theme-control dark
```

Use `light` instead of `dark` to switch back. On the locked Android 10 builds,
the first run installs a fixed-purpose controller through the provisioner's
UID-1000 boot-helper mechanism. Later provisioner runs reuse it and switch the
live theme without another exploit or reboot. Android 9 builds already allow
the normal shell `cmd uimode` operation, so the provisioner uses that directly.

The UID-1000 controller does not expose an elevated command shell. It watches
the `debug.portal.system_theme` Android property and accepts only the exact
values `light` and `dark`; each maps to a hardcoded `cmd uimode night no` or
`cmd uimode night yes` invocation. Invalid and empty values are ignored.

Set the props from ADB like this:

```sh
setprop debug.portal.system_theme dark
setprop debug.portal.system_theme light
```


The trigger property is intentionally non-persistent, while Android's selected
night mode persists normally. The root-owned enable marker and UID-1000 helper
survive reboots. `--status` reports the effective mode, any current runtime
request, whether the UID-1000 controller is installed, and whether its helper
is running.

</details>

<a id="install-shizuku-with-automatic-startup"></a>
<details>
<summary><strong>Optional add-on:</strong> Install Shizuku with automatic startup</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku
```

This downloads the pinned official Shizuku release on the host computer,
verifies its SHA-256 digest, and installs it with a small Portal boot helper.
The Portal itself does not need internet access for this step. Meta's required
APK certificate verifier accepts only Meta-approved signing certificates, so
the provisioner temporarily disables the verifier package around the two
local installs, restores the package's original enabled state, waits for
Package Manager to save it, and checks the result after reboot. The separate
`--allow-app-updates` action controls whether later third-party updates are
accepted.

Supported Portals run Android 9 or 10, where upstream Shizuku cannot
automatically start ADB mode after boot. The helper solves that limitation
entirely on the device:
it receives Android's normal boot broadcast, connects to the Portal's existing
ADB daemon at `127.0.0.1:5555`, authenticates with a key generated for that
Portal, and runs Shizuku's own starter. The temporary-root action authorizes
only that public key. The host's ADB private key is never copied to the Portal.

Shizuku runs as Android user `shell` (UID 2000), which is the normal Shizuku
ADB privilege level; it is not a persistent UID-0 root service. Once
installation completes, no host computer or network connection is needed for
startup. Wireless ADB must remain enabled locally because the helper uses its
loopback listener. The two-boot verifier requires `shizuku_server` to run as
`shell` after both ordinary reboots.

To use a Shizuku APK you downloaded yourself, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku --shizuku-apk ./shizuku.apk
```

Remove the manager, boot helper, running server, and the helper's authorized
ADB key with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-shizuku
```

</details>

<a id="per-boot-root-daemon"></a>
<details>
<summary><strong>Optional add-on:</strong> Per-boot root daemon (custom payload)</summary>
<p></p>

```sh
make -C root-daemon
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku \
  --custom-payload root-daemon/portal-root-daemon
```

Instead of ending the privileged window with a reboot, this mode starts a
small root daemon as a UID-0 delegated child of the exploit process, after
repairing the kernel lock state the race leaves behind (see
[How the root exploit works](#how-the-root-exploit-works)). The daemon
answers a line-based protocol on `127.0.0.1:37373` — `ID`, `EXEC <command>`
and `STOP`; see `root-daemon/README.md` for the details. It is per-boot
only: it dies with the boot and is not restarted unless the provisioner
runs again or autoroot is enabled. The daemon is a bridge, not a standing
service: when root-mode Shizuku is enabled, the provisioner stops it as
soon as Shizuku is verified running as UID 0 (`PAYLOAD_DAEMON_STOPPED`),
because Shizuku is the root interface apps use from then on. It stays
running only when root-mode Shizuku is not in play — a plain
`--custom-payload` run, or `--skip-shizuku-root`.

> [!WARNING]
> The daemon has **no authentication**. Any app on the Portal that can open
> a loopback TCP connection can run commands as UID 0. It binds loopback
> only and lives for one boot — and with root-mode Shizuku enabled it is
> stopped after the handoff, so the exposure lasts minutes — but enable
> this mode only on devices where that trade-off is acceptable.

The payload binary is operator-supplied: `--custom-payload` accepts any
executable, and `root-daemon/` builds the reference one. Post-payload
steps that need the daemon (root-mode Shizuku, autoroot staging) run only
after it answers an `ID` check as UID 0.

</details>

<a id="run-shizuku-as-root"></a>
<details>
<summary><strong>Optional add-on:</strong> Run Shizuku as root</summary>
<p></p>

With `--shizuku` and a running root daemon, the provisioner restarts
Shizuku as UID 0: it stops the shell instance from the shell context (the
daemon's SELinux domain cannot signal it), re-runs Shizuku's official
starter through the daemon, and requires the new `shizuku_server` process
to report UID 0 in its `/proc` status before printing `SHIZUKU_ROOT_OK`.
Apps using Shizuku then get root-level rather than shell-level access.

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku \
  --custom-payload root-daemon/portal-root-daemon \
  --skip-shizuku-root
```

Add `--skip-shizuku-root` to keep Shizuku at its normal shell privilege
level while still using the daemon for other steps.

</details>

<a id="automatic-re-rooting-with-autoroot"></a>
<details>
<summary><strong>Optional add-on:</strong> Automatic re-rooting after reboot (autoroot)</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku \
  --custom-payload root-daemon/portal-root-daemon --autoroot
```

`--autoroot` stages an on-device runner and a boot helper app so a reboot
needs no host. After every boot the helper checks whether Shizuku is
already running as UID 0; if it is, the boot is done. Otherwise the
helper redoes the per-boot address discovery on the device (bugreport
plus the staged `simpleperf`), then re-runs the exploit with the same
environment the host provisioner would generate, in both attempt
geometries. A session allows up to 8 attempts in a 60-minute window; a
failed attempt reboots the Portal for a clean retry, and a session that
exhausts its budget retries after the window. On success the helper
restarts Shizuku as root through the daemon, stops the daemon, and
records the boot as done.

The helper app shows the live session state and provides three controls:
**Stop autoroot & reboot** (stops any in-flight attempt, disables autoroot
and reboots to a clean state), **Disable/Enable autoroot**, and **Run
now** (starts a fresh session immediately). The exploit sentinel app stays
installed because every attempt needs it. The Shizuku boot helper is
removed at staging time: the autoroot helper holds its own copy of the
already-authorized ADB keypair, so the deployed set is the sentinel,
Shizuku and the autoroot helper.

Autoroot attempts carry the same race risks as host-driven attempts,
without anyone watching: a failed attempt reboots the Portal, and an
attempt can occasionally leave it unresponsive until it is power-cycled.
This mode is validated end-to-end on the Portal+ (`aloha`) build
`1041515800015050`; other supported models have not been validated for it.

</details>

## Inspection, backups and recovery

### Status report

Print a read-only JSON report without exploiting or rebooting the Portal:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --status
```

The report includes exact target support, boot and SELinux state, audio
and OTA markers,
remote-wipe protection, debloat and account status, the live presence pipeline,
Private DNS, system-theme control, Shizuku package and server state, and the
last provisioning manifest.

### Dry-run planning

Preview an action set without changing the device:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat --dry-run
```

The plan identifies required build outputs, host tools, exploit use, estimated
minimum reboots, and the current state.

### Backup bundles

Create a private diagnostic and configuration archive before making changes:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --backup ./backups
```

`--backup` may also accompany a provisioning command. The resulting mode-0600
archive contains status, relevant Android service dumps, reversible device
snapshots, and a SHA-256 manifest. It can contain account names and device
configuration, so store it as sensitive data.

### Interrupted-run recovery

Every mutating run writes a state manifest at
`/data/local/tmp/portal-provision-state-v1.json`. It records the exact target,
firmware fingerprint, selected actions, Git revision, artifact hashes, state,
and verification boot IDs. If power or the host fails during a run, reconnect
ADB and resume the pending action set with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --recover
```

Recovery first removes stale staged files. It resumes only a validated pending
manifest; for a completed run or a device with no manifest, it prints status
and exits without changing the configuration.

## Technical details and troubleshooting

<a id="how-the-root-exploit-works"></a>
<details>
<summary><strong>How the root exploit works</strong></summary>
<p></p>

The project adapts GhostLock,
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), to a
specific Portal kernel. The provisioner confirms the complete device identity,
reboots into a clean state, derives randomized kernel addresses and starts the
exploit through a staged native library. Temporary kernel read/write access
gives only that process the credentials needed to perform the selected work.

The device then reboots normally with SELinux enforcing. In the default flow
the exploit does not install `su`, a root shell or a root daemon. Features
that must survive reboot use narrow configuration changes or dedicated
helpers with only the privileges they need. The provisioner verifies the
requested state on two normal boots.

The `--custom-payload` mode is the deliberate exception: it starts the root
daemon inside the privileged window instead of returning straight to a
normal boot. Because the race leaves the kernel's `proc_uid` lock waiter
tree damaged — the reason the stock flow reboots immediately — the payload
path first repairs that tree to its canonical empty state. The repair is
pattern-gated: it writes only when the current state matches the exact
expected damage shape, and it verifies the result by read-back. On any
mismatch it writes nothing and the attempt counts as a miss.

Kernel exploitation is race-sensitive, so a missed attempt can reboot or
briefly freeze the Portal. The provisioner retries from a clean boot. Exact
model and firmware checks prevent it from using one build's kernel layout on
another device.

</details>

<a id="running-and-troubleshooting"></a>
<details>
<summary><strong>Running and troubleshooting</strong></summary>
<p></p>

The default maximum is 12 exploit attempts. Change it with `--attempts N`,
where `N` is between 1 and 100. A failed race normally causes a clean reboot
and another attempt. Before `WIRELESS_ADB_OK` has appeared, re-enable ADB in
the Portal's Debug menu and run `adb -d tcpip 5555` after every reboot. If the
Portal remains unresponsive, power-cycle it, restore USB and wireless ADB, and
rerun the same command; completed provisioning actions are designed to be
repeatable.

Use `--skip-build` only when the required outputs have already been built and
have not changed. Every root-backed action requires both the selected exploit
library and `exploit-sentinel/build/portal-exploit-sentinel.apk`. The
provisioner installs that no-permission package temporarily, confirms that
`run-as` accepts it, and removes it automatically. Display every available
option with:

```sh
python3 tools/provision_portal.py --help
```

Each successful run verifies the requested state on two distinct boots by
default. `--verify-boots 1` verifies on a single boot instead, skipping the
second verification reboot. Read
the final `PROVISION_OK` line and keep the attempt directory when diagnosing a
failure.

</details>

## Support the project

If this project breathed new life into your Meta Portal, consider supporting
my work through [Buy Me a Coffee](https://buymeacoffee.com/jxlarrea). Your
support helps me obtain more Portal models, test additional firmware and keep
improving the tools that make these devices useful again.

<p align="center">
  <a href="https://buymeacoffee.com/jxlarrea"><img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee"></a>
</p>
