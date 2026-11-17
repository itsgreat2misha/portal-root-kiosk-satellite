# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/itsgreat2misha/portal-root-kiosk-satellite/security/advisories/new)
for this repository instead of opening a public issue. Include the
affected version or commit, the device model and firmware build, and
the steps to reproduce. You should get an acknowledgement within a
few days; fixes for confirmed issues are prepared privately and
disclosed together with the release that contains them.

## Scope and expectations

This tool deliberately uses a kernel exploit (GhostLock,
CVE-2026-43499) against devices its operator owns, inside a short,
guarded provisioning window. Reports that amount to "the tool roots
the device" are restating its purpose, not vulnerabilities. Reports
that do matter:

- the provisioner acting on a device, model, or firmware build it did
  not positively identify;
- a provisioning action changing state outside its documented scope;
- credentials, keys, or personal data being written to logs, state
  files, or this repository;
- the on-device components (root daemon, autoroot helper) being
  reachable or triggerable by anything other than the local operator.

## Known, documented risks

- The custom-payload control channel listens on 127.0.0.1:37373 on
  the device without authentication. It is loopback-only, but any
  local process can talk to it while the daemon runs. The daemon only
  runs in the explicit `--custom-payload` / `--autoroot` modes; see
  FORK.md for the design discussion.
- Wireless ADB persistence intentionally keeps TCP 5555 reachable on
  the local network. Only enable it on networks you trust.
- Helper APKs built from this repository are signed with the project
  debug key committed at the repository root (`debug.keystore`); the
  build verifies the keystore's certificate fingerprint and refuses
  to sign with any other key, because devices reject
  signature-mismatched updates.

## Supported versions

Only the latest release (and the current `main`) receives fixes.
There are no backported security releases for older states of the
fork.
