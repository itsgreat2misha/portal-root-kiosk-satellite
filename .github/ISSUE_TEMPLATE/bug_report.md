---
name: Bug report
about: Something the provisioner did wrong, or failed to do
labels: bug
---

**What happened**
<!-- The exact output, including the final PROVISION_* line and any
error. Paste from the attempt log directory (--log-dir). Do not
include your Portal's IP address, adb serial, pairing code, or any
account information. -->

**What you expected**

**Device**
- Model:
- Firmware fingerprint (`adb shell getprop ro.build.fingerprint`):

**Host**
- OS:
- Provisioner version (`python3 tools/provision_portal.py --version`):
- Command line used (remove the `--serial` value):

**Was the device previously provisioned (by this tool or upstream)?**
