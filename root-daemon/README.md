# portal-root-daemon

A minimal per-boot root helper for Meta Portal devices, used by this fork's
`--custom-payload` flow and staged on-device by `--autoroot`.

The provisioner starts the daemon exactly once per boot, as a uid-0 delegated
child inside the exploit's privileged window (after the lock repair). It is
not persistent: it dies with the boot. On an `--autoroot` install the
autoroot helper re-establishes it after each reboot; otherwise the
provisioner must be re-run.

## Protocol

TCP on **127.0.0.1:37373 only**, line-based, one command per line; `EXEC`
may be repeated on the same connection. Every response ends with an `END`
line.

| Command      | Response                                            |
| ------------ | --------------------------------------------------- |
| `ID`         | `ID uid=.. euid=.. gid=.. egid=.. capeff=.. ctx=..` |
| `EXEC <cmd>` | raw stdout+stderr of `/bin/sh -c <cmd>`, then `EXIT <code>` |
| `STOP`       | `BYE`, then the daemon exits                        |
| anything else | `ERR unknown-command`                              |

At startup the daemon appends one identity line (pid, uid/euid/gid/egid,
capabilities, SELinux context, boot id) to
`/data/local/tmp/portal-root-daemon-identity.log`, so its uid-0 identity can
be verified from `/data` alone.

## Security note

The daemon has **no authentication**: any app on the device that can open a
loopback TCP connection can run commands as uid 0. It binds loopback only
and lives only for one boot, but treat any device running it as fully open
to local apps. This is a deliberate trade-off of the fork's root flow and is
called out in FORK.md as well.

## Build

Requires the Android NDK (r28.2, as resolved by `../android-env.mk`):

```
make        # produces ./portal-root-daemon (aarch64, API 28)
```

Then pass the binary to the provisioner:

```
tools/provision_portal.py --serial <device> --custom-payload root-daemon/portal-root-daemon
```

License: Apache-2.0, as part of this repository. No third-party code; libc
only.
