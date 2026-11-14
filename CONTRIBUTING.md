# Contributing

Thanks for helping. This project provisions and roots Meta Portal
devices with an exact-build kernel exploit, so correctness bars are
higher than for typical tooling: a wrong constant can reboot-loop a
device. Please read the ground rules before sending changes.

## Ground rules

- **Exact-build discipline.** Targets are keyed to exact model +
  firmware fingerprints in `tools/portal_targets.py`. Never widen a
  guard, guess a kernel offset, or copy constants between builds.
- **No device-specific data.** Never commit LAN addresses, adb
  serials, pairing codes, account data, or device logs containing
  them. `--serial` has no default on purpose.
- **Payloads are frozen unless re-validated.** Do not modify the
  native exploit sources, helper binaries' behavior, or the
  (currently unreachable) device-owner branch in
  `exploit/src/fops.c` without a full live validation run; payload
  changes require rebuilding and re-validating on real hardware.
- **Keep credit intact.** This is a fork of jxlarrea's original
  project (see NOTICE). New files need the SPDX header used by the
  neighboring files; modified upstream files keep the
  "Originally by Xavier Larrea" header.

## Development setup

Host side (Python 3.11+, standard library only):

```sh
python3 -m unittest discover -s tests
```

The suite is hermetic: it must pass on a machine with **no `adb`
binary installed**, and CI runs it that way. Fake device interaction
at the `adb_run`/`run` boundary instead of shelling out.

Native and Android builds need the pinned toolchain from
`tools/provision_portal.py` (NDK 28.2.13676358, build-tools 37.0.0,
platform android-36), resolved through `android-env.mk`.

## Live validation

Any change to the provisioning flow, the exploit invocation, or the
on-device components needs a live run on a real device before it is
mergeable, and the PR description must say what was run: a full
provision plus two host-free recovery reboots with the final state
verified (root Shizuku up, daemon stopped after handoff, sentinel
retained). Documentation-only and test-only changes are exempt.

## Pull requests

- One topic per PR; keep commits focused and messages descriptive.
- The full test suite must pass; describe the test result in the PR.
- Update README.md, FORK.md, and CHANGELOG.md when behavior, flags,
  or supported targets change.
- Substantial changes should be discussed in an issue first.

## A note on AI assistance

Parts of this codebase were written with AI assistance, and
AI-assisted contributions are welcome here. The rule is ownership:
whoever submits a change must be able to explain it, must have
reviewed it line by line, and must have run the required tests and
live validation themselves. Say in the PR description if AI tools
materially helped, and never submit AI-generated device constants,
offsets, or target data — those come from real hardware or not at
all.
