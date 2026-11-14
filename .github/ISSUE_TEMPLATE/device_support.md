---
name: Device / firmware support request
about: Ask for a model or firmware build that is not yet supported
labels: device-support
---

Support is exact-build specific: a new target needs its own verified
kernel layout, which requires hardware access or a volunteer with the
device. Requests are best-effort.

**Retail model:**

**Output of:**
```sh
adb shell getprop ro.build.fingerprint
adb shell uname -a
adb shell getprop ro.product.model
```

<!-- Do not publish an ADB address, pairing code, or account
information. -->
