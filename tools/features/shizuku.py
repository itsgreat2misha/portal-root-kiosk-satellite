# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Shizuku feature cluster: APK download, install, key staging,
root-mode start.

Extracted from provision_portal.py in the M3.4 monolith-split phase.
Mechanical move only, preserving call-for-call the ordering relative
to install-race wins (the Nov 3/4 test-log lessons): the race action
set and the sequence download -> install -> key staging -> root start
are unchanged. Test-patched seams (resolve_shizuku_apk,
install_apk_preserving_verifier, verify_package_verifier_state) and
cross-cluster seams (adb transport, daemon exec, package sets,
logcat helpers) are late-bound callables supplied by
PortalProvisioner. ShizukuFeature owns
package_verifier_before_install_disabled; shizuku_apk and
shizuku_public_key are shared with the orchestrator (stage /
artifact selection read them) and are synced by the provisioner
wrappers after resolve/install.
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import shlex
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from typing import Callable

from device_session import ProvisionError
from portal_targets import PortalTarget

ROOT = pathlib.Path(__file__).resolve().parents[2]

SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
SHIZUKU_HELPER_PACKAGE = "dev.portal.shizukuhelper"
# The autoroot helper holds its own copy of this same keypair (staged
# from the Shizuku helper's pair, which the install loop authorized).
# When the Shizuku helper has no pair, install seeds it from the
# autoroot helper's copy before generating a fresh one, so the pair
# converges on the already-authorized key instead of rotating to a
# key no race has authorized. The package name is pinned to
# features.payload's AUTOROOT_HELPER_PACKAGE by a test, like the
# other names in SIGNATURE_MISMATCH_RETRY_PACKAGES below.
AUTOROOT_HELPER_PACKAGE = "dev.portal.autoroothelper"
# Packages this project builds and signs itself whose installed copy can
# predate the current build host's keystore (a device provisioned by an
# older build). Android refuses signature-changing updates, so for these
# — and only these — install_apk_preserving_verifier replaces a stale
# copy on INSTALL_FAILED_UPDATE_INCOMPATIBLE instead of failing. The
# sentinel and autoroot-helper names are pinned to features.payload's
# constants, and the presence-helper name to features.presence's, by a
# test. The Shizuku app itself is a third-party package and is never
# replaced.
SIGNATURE_MISMATCH_RETRY_PACKAGES = frozenset(
    {
        SHIZUKU_HELPER_PACKAGE,
        "dev.portal.exploitsentinel",
        AUTOROOT_HELPER_PACKAGE,
        "dev.portal.presencehelper",
    }
)
SHIZUKU_HELPER_LOCAL = ROOT / "shizuku-helper/build/portal-shizuku-helper.apk"
SHIZUKU_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey.pub"
SHIZUKU_SAVED_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey-v1.pub"
SHIZUKU_VERSION = "13.6.0.r1086.2650830c"
SHIZUKU_APK_NAME = "shizuku-v13.6.0.r1086.2650830c-release.apk"
SHIZUKU_APK_URL = (
    "https://github.com/RikkaApps/Shizuku/releases/download/v13.6.0/"
    + SHIZUKU_APK_NAME
)
SHIZUKU_APK_SHA256 = (
    "6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f"
)


class ShizukuFeature:
    """Shizuku download / install / key staging / root-mode start."""

    def __init__(
        self,
        *,
        adb_run: Callable[..., "subprocess.CompletedProcess[str]"],
        run: Callable[..., "subprocess.CompletedProcess[str]"],
        target: Callable[[], "PortalTarget | None"],
        log_dir: Callable[[], pathlib.Path],
        settle_package_state: Callable[..., None],
        package_sets: Callable[..., "tuple[set[str], set[str]]"],
        logcat_watermark: Callable[..., object],
        logcat_poll: Callable[..., str],
        daemon_exec: Callable[..., object],
        resolve_shizuku_apk: Callable[..., pathlib.Path],
        install_apk_preserving_verifier: Callable[..., None],
        verify_package_verifier_state: Callable[..., None],
        authorized_shizuku_key: Callable[[], str | None],
        authorized_shizuku_key_already: Callable[[], bool],
        shizuku_apk: pathlib.Path | None,
    ):
        self._adb_run = adb_run
        self._run = run
        self._target = target
        self._log_dir = log_dir
        self._settle_package_state = settle_package_state
        self._package_sets = package_sets
        self._logcat_watermark = logcat_watermark
        self._logcat_poll = logcat_poll
        self._daemon_exec = daemon_exec
        self._resolve_shizuku_apk = resolve_shizuku_apk
        self._install_apk_preserving_verifier = install_apk_preserving_verifier
        self._verify_package_verifier_state = verify_package_verifier_state
        self._authorized_shizuku_key = authorized_shizuku_key
        self._authorized_shizuku_key_already = authorized_shizuku_key_already
        self.shizuku_apk = shizuku_apk
        self.shizuku_public_key: pathlib.Path | None = None
        # Where the pair install_shizuku_payload ended up with came
        # from: "existing" (the helper already held it), "autoroot-seed"
        # (copied from the autoroot helper's already-authorized pair),
        # or "keygen" (freshly generated; no race has authorized it
        # yet). The channel apply path refuses to stage a "keygen"
        # pair, or one that is not the recorded authorized key: it
        # cannot authorize one, and staging it would strand autoroot
        # recovery on a key adb_keys does not hold.
        self.shizuku_key_source: str | None = None
        self.package_verifier_before_install_disabled: bool | None = None


    def resolve_shizuku_apk(self) -> pathlib.Path:
        if self.shizuku_apk is not None:
            path = self.shizuku_apk.expanduser().resolve()
            if not path.is_file():
                raise ProvisionError(f"Shizuku APK does not exist: {path}")
        else:
            cache = pathlib.Path.home() / ".cache" / "portal-root"
            cache.mkdir(parents=True, exist_ok=True)
            path = cache / SHIZUKU_APK_NAME
            valid = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == (
                SHIZUKU_APK_SHA256
            )
            if not valid:
                temporary = path.with_suffix(path.suffix + ".tmp")
                temporary.unlink(missing_ok=True)
                print(
                    f"SHIZUKU_DOWNLOAD version={SHIZUKU_VERSION} "
                    f"source={SHIZUKU_APK_URL}",
                    flush=True,
                )
                try:
                    urllib.request.urlretrieve(SHIZUKU_APK_URL, temporary)
                except OSError as exc:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(
                        "Shizuku APK download failed on the host computer: "
                        f"{exc}. Connect the host to the internet or download "
                        "the pinned APK separately and pass --shizuku-apk PATH"
                    ) from exc
                digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
                if digest != SHIZUKU_APK_SHA256:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(
                        "official Shizuku APK checksum mismatch: "
                        f"{digest} != {SHIZUKU_APK_SHA256}"
                    )
                temporary.replace(path)
            self.shizuku_apk = path
        try:
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    raise ProvisionError(f"invalid Shizuku APK: {path}")
                bad = archive.testzip()
                if bad:
                    raise ProvisionError(f"corrupt Shizuku APK member: {bad}")
        except zipfile.BadZipFile as exc:
            raise ProvisionError(f"invalid Shizuku APK: {path}") from exc
        return path

    def _read_helper_keypair(
        self, package: str
    ) -> tuple[str, str] | None:
        """The ADB keypair a helper app holds, or None when it holds
        no complete, well-formed pair."""
        private_key = self._adb_run(
            ["exec-out", "run-as", package, "cat", "files/adbkey"],
            timeout=10,
        ).stdout
        public_key = self._adb_run(
            ["exec-out", "run-as", package, "cat", "files/adbkey.pub"],
            timeout=10,
        ).stdout.strip()
        if (
            "-----BEGIN PRIVATE KEY-----" in private_key
            and "-----END PRIVATE KEY-----" in private_key
            and re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public_key)
            is not None
        ):
            return private_key, public_key
        return None

    def _push_keypair_into_shizuku_helper(
        self, private_path: pathlib.Path, public_path: pathlib.Path
    ) -> None:
        for source, remote, destination in (
            (private_path, "/data/local/tmp/portal-shizuku-key.tmp", "files/adbkey"),
            (
                public_path,
                "/data/local/tmp/portal-shizuku-key.pub.tmp",
                "files/adbkey.pub",
            ),
        ):
            self._adb_run(["push", str(source), remote], timeout=15, check=True)
            self._adb_run(["shell", "chmod", "0644", remote], timeout=5, check=True)
            self._adb_run(
                ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "mkdir", "-p", "files"],
                timeout=10,
                check=True,
            )
            self._adb_run(
                ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "cp", remote, destination],
                timeout=10,
                check=True,
            )
            self._adb_run(
                ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "chmod", "0600", destination],
                timeout=10,
                check=True,
            )
            self._adb_run(["shell", "rm", "-f", remote], timeout=5)

    def install_shizuku_payload(self) -> None:
        apk = self._resolve_shizuku_apk()
        self._install_apk_preserving_verifier(apk, "shizuku", SHIZUKU_PACKAGE)
        self._install_apk_preserving_verifier(
            SHIZUKU_HELPER_LOCAL, "shizuku-helper", SHIZUKU_HELPER_PACKAGE
        )
        self._settle_package_state()
        self._verify_package_verifier_state()
        package_dump = self._adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_PACKAGE],
            timeout=20,
            check=True,
        ).stdout
        if f"versionName={SHIZUKU_VERSION}" not in package_dump and (
            self.shizuku_apk.name == SHIZUKU_APK_NAME
        ):
            raise ProvisionError(
                f"installed Shizuku version is not {SHIZUKU_VERSION}"
            )

        key_exists = (
            self._read_helper_keypair(SHIZUKU_HELPER_PACKAGE) is not None
        )
        if key_exists:
            self.shizuku_key_source = "existing"
        else:
            # The helper holds no pair — the normal state after
            # autoroot staging removed the helper app. Before
            # generating a fresh pair (which no race has authorized,
            # and which a channel apply cannot authorize), seed the
            # helper from the autoroot helper's copy: that pair is
            # the one already authorized in adb_keys, so the run
            # converges on the authorized key instead of rotating
            # away from it.
            seeded = self._read_helper_keypair(AUTOROOT_HELPER_PACKAGE)
            with tempfile.TemporaryDirectory(prefix="portal-shizuku-key-") as temp:
                key = pathlib.Path(temp) / "adbkey"
                public_path = pathlib.Path(str(key) + ".pub")
                if seeded is not None:
                    key.write_text(seeded[0], encoding="utf-8", newline="")
                    public_path.write_text(
                        seeded[1] + "\n", encoding="utf-8", newline=""
                    )
                    self.shizuku_key_source = "autoroot-seed"
                else:
                    self._run(
                        ["adb", "keygen", str(key)], timeout=30, check=True
                    )
                    self.shizuku_key_source = "keygen"
                self._push_keypair_into_shizuku_helper(key, public_path)
            if seeded is not None:
                print(
                    "SHIZUKU_KEY_SEEDED source=autoroot-helper "
                    "reason=already-authorized",
                    flush=True,
                )

        public = self._adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
            check=True,
        ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public):
            raise ProvisionError("Portal Shizuku helper returned an invalid ADB public key")
        self._log_dir().mkdir(parents=True, exist_ok=True)
        self.shizuku_public_key = self._log_dir() / "portal-shizuku-adbkey.pub"
        self.shizuku_public_key.write_text(
            public + "\n", encoding="ascii", newline=""
        )
        self.shizuku_public_key.chmod(0o600)
        print(
            f"SHIZUKU_PAYLOAD_OK version={SHIZUKU_VERSION} "
            f"helper={SHIZUKU_HELPER_PACKAGE} key_reused={int(key_exists)}"
        )

    def installed_apk_matches(
        self, apk: pathlib.Path, package: str, tag: str
    ) -> bool:
        """True when the installed base APK is byte-identical to apk.

        Compares by hash: pulling the installed base APK back is far
        cheaper than a push + reinstall + settle of the same bytes, and
        needs no per-package version table that could drift from the
        built artifacts.
        """
        path_result = self._adb_run(
            ["shell", "pm", "path", package], timeout=15
        )
        if path_result.returncode != 0:
            return False
        match = re.search(
            r"^package:(.+\.apk)$", path_result.stdout, re.MULTILINE
        )
        if not match:
            return False
        pulled = self._log_dir() / f"portal-{tag}-installed.apk"
        self._log_dir().mkdir(parents=True, exist_ok=True)
        try:
            pull = self._adb_run(
                ["pull", match.group(1), str(pulled)], timeout=300
            )
            if pull.returncode != 0 or not pulled.is_file():
                return False
            return hashlib.sha256(pulled.read_bytes()).hexdigest() == (
                hashlib.sha256(apk.read_bytes()).hexdigest()
            )
        finally:
            pulled.unlink(missing_ok=True)

    def install_apk_preserving_verifier(
        self,
        apk: pathlib.Path,
        tag: str,
        package: str | None = None,
        *,
        skip_if_identical: bool = True,
    ) -> None:
        """Install an APK while restoring Meta's certificate verifier state.

        skip_if_identical=False (the provisioner's --force) bypasses
        only the byte-identical skip below. The package still gates
        the signature-mismatch retry further down, which must stay
        armed in every run: a stale copy signed by an older build
        host can be present no matter how the run was invoked.
        """
        if (
            package is not None
            and skip_if_identical
            and self.installed_apk_matches(apk, package, tag)
        ):
            print(
                f"APK_INSTALL_SKIP package={package} reason=identical",
                flush=True,
            )
            return
        remote = f"/data/local/tmp/portal-{tag}-install.apk"
        # Remote support tunnels can sustain far less throughput than a local
        # USB or LAN ADB connection. Allow at least 32 KiB/s plus two minutes
        # of protocol/setup overhead so large APK releases are not
        # killed near the end of an otherwise healthy transfer.
        push_timeout = max(
            600,
            (apk.stat().st_size + 32 * 1024 - 1) // (32 * 1024) + 120,
        )
        print(
            f"APK_PUSH package_source={apk.name} "
            f"bytes={apk.stat().st_size} timeout={push_timeout}",
            flush=True,
        )
        self._adb_run(["push", str(apk), remote], timeout=push_timeout, check=True)
        disabled = self._adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
        ).stdout
        verifier_was_disabled = "package:com.facebook.appverifier" in disabled
        # Record the state for this installation transaction. A profile can
        # intentionally change the durable verifier state between APKs (for
        # example, install an APK and then apply --allow-app-updates)
        # so an earlier transaction's baseline must not be reused here.
        self.package_verifier_before_install_disabled = verifier_was_disabled
        if verifier_was_disabled:
            command = f"pm install -r {shlex.quote(remote)}; rc=$?; " \
                f"rm -f {shlex.quote(remote)}; exit $rc"
        else:
            command = (
                "cleanup() { pm enable --user 0 com.facebook.appverifier "
                f">/dev/null; rm -f {shlex.quote(remote)}; }}; "
                "trap cleanup EXIT HUP INT TERM; "
                "pm disable-user --user 0 com.facebook.appverifier >/dev/null || exit 1; "
                f"pm install -r {shlex.quote(remote)}"
            )
        result = self._adb_run(["shell", command], timeout=300)
        if result.returncode != 0 or "Success" not in result.stdout:
            if (
                package in SIGNATURE_MISMATCH_RETRY_PACKAGES
                and "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in result.stdout
            ):
                # A copy installed by an older build host is signed with
                # a different keystore, and Android refuses signature-
                # changing updates, so the stale copy can never be
                # updated in place. Replace it instead: nothing
                # irreplaceable is lost — no key authorization for the
                # helper has happened yet at this point in a run (the
                # install race later authorizes the installed helper's
                # key), the sentinel is a marker app this step
                # recreates, the autoroot helper receives its
                # staged files after install, and the presence helper's
                # keypair and FPS config are staged by its own prepare
                # and activate steps after install.
                print(
                    f"APK_INSTALL_RETRY package={package} "
                    "reason=signature-mismatch action=uninstall-reinstall",
                    flush=True,
                )
                uninstall = self._adb_run(["uninstall", package], timeout=60)
                if uninstall.returncode != 0 or "Success" not in uninstall.stdout:
                    raise ProvisionError(
                        f"failed to uninstall stale {package}: "
                        f"{uninstall.stdout.strip()}"
                    )
                # The failed attempt's command removed the pushed APK
                # (both variants delete it), so push it again.
                self._adb_run(
                    ["push", str(apk), remote], timeout=push_timeout, check=True
                )
                result = self._adb_run(["shell", command], timeout=300)
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    f"APK installation failed for {apk}: {result.stdout.strip()}"
                )
        print(
            f"APK_INSTALL_OK package_source={apk.name} "
            f"verifier_state={'disabled' if verifier_was_disabled else 'enabled'}"
        )

    def verify_package_verifier_state(self) -> None:
        if self.package_verifier_before_install_disabled is None:
            return
        disabled = self._adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
        ).stdout
        actual = "package:com.facebook.appverifier" in disabled
        if actual != self.package_verifier_before_install_disabled:
            raise ProvisionError(
                "Meta package verifier state was not restored: "
                f"disabled={int(actual)} expected="
                f"{int(self.package_verifier_before_install_disabled)}"
            )
        print(
            "PACKAGE_VERIFIER_OK state="
            + ("disabled" if actual else "enabled")
        )

    def uninstall_shizuku_payload(self) -> None:
        self._adb_run(["shell", "pkill", "-f", "shizuku_server"], timeout=10)
        installed, _ = self._package_sets()
        for package in (SHIZUKU_HELPER_PACKAGE, SHIZUKU_PACKAGE):
            if package not in installed:
                continue
            result = self._adb_run(["uninstall", package], timeout=60)
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    f"failed to uninstall {package}: {result.stdout.strip()}"
                )
        if self._target() and self._target().buffer_root_staged_sources:
            self._adb_run(
                ["shell", "rm", "-f", SHIZUKU_SAVED_KEY_REMOTE],
                timeout=5,
                check=True,
            )
        print("SHIZUKU_REMOVE_APPS_OK")

    def finalize_buffered_shizuku_key(self) -> None:
        if not self._target() or not self._target().buffer_root_staged_sources:
            return
        if self.shizuku_public_key is None:
            raise ProvisionError("Shizuku helper key was not prepared")
        self._adb_run(
            ["push", str(self.shizuku_public_key), SHIZUKU_SAVED_KEY_REMOTE],
            timeout=30,
            check=True,
        )
        self._adb_run(
            ["shell", "chmod", "0600", SHIZUKU_SAVED_KEY_REMOTE],
            timeout=5,
            check=True,
        )
        print("SHIZUKU_KEY_MARKER_OK source=post-reboot")

    def refresh_shizuku_key_marker(self) -> None:
        """Converge the on-device saved marker onto the reused pair.

        Non-buffered targets only (buffered targets' marker is the
        host-pushed finalize above). The marker is written by the
        native authorize from the staged scratch file at a win, so
        in the reuse path it can lag the helper's live pair by a
        generation: a run that rotated the helper's pair and aborted
        before its staging could leave the marker naming a key that
        matches no surviving record (Nov 18, 2026 Mini abort). When
        a win in THIS run proved the pair install read from the
        helper was already authorized (already=1), the marker is
        simply stale: rewrite it from the same host copy install
        staged, so helper, staged file, and marker end the install
        phase on one generation. Every other case leaves the marker
        untouched — a fresh append (already=0) is the native
        authorize's own save to make, and a seeded or keygen'd pair
        has no already-authorized reuse to converge.
        """
        target = self._target()
        if target is None or target.buffer_root_staged_sources:
            return
        if self.shizuku_key_source != "existing":
            return
        recorded = self._authorized_shizuku_key()
        if recorded is None or not self._authorized_shizuku_key_already():
            return
        if self.shizuku_public_key is None:
            return
        staged = self.shizuku_public_key.read_text(
            encoding="ascii"
        ).strip()
        if recorded != staged:
            return
        self._adb_run(
            ["shell", "rm", "-f", SHIZUKU_SAVED_KEY_REMOTE], timeout=5
        )
        self._adb_run(
            ["push", str(self.shizuku_public_key), SHIZUKU_SAVED_KEY_REMOTE],
            timeout=30,
            check=True,
        )
        self._adb_run(
            ["shell", "chmod", "0600", SHIZUKU_SAVED_KEY_REMOTE],
            timeout=5,
            check=True,
        )
        print(
            "SHIZUKU_KEY_MARKER_REFRESHED source=reuse-convergence",
            flush=True,
        )

    def verify_shizuku(self, wait_seconds: int = 120) -> None:
        self._verify_package_verifier_state()
        package_state = self._adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_HELPER_PACKAGE],
            timeout=15,
            check=True,
        ).stdout
        if re.search(r"\bstopped=true\b", package_state):
            try:
                self._adb_run(
                    [
                        "shell",
                        "am",
                        "broadcast",
                        "-f",
                        "0x20",
                        "-a",
                        "dev.portal.shizukuhelper.START",
                        "-p",
                        SHIZUKU_HELPER_PACKAGE,
                    ],
                    timeout=15,
                    check=True,
                )
            except ProvisionError:
                # Portal's activity manager can finish delivery but leave the
                # host-side broadcast command waiting during early boot. The
                # process/log polling below is the authoritative check.
                print("SHIZUKU_HELPER_ACTIVATION_PENDING early_boot=1")
            print("SHIZUKU_HELPER_ACTIVATED first_install=1")
        deadline = time.monotonic() + wait_seconds
        since = self._logcat_watermark()
        process = ""
        logs = ""
        while time.monotonic() < deadline:
            packages = self._adb_run(
                ["shell", "pm", "list", "packages"], timeout=15, check=True
            ).stdout
            process = self._adb_run(
                ["shell", "ps", "-A"], timeout=10, check=True
            ).stdout
            logs = self._logcat_poll("PortalShizuku", since, timeout=15)
            process_line = next(
                (line for line in process.splitlines() if "shizuku_server" in line),
                "",
            )
            if (
                f"package:{SHIZUKU_PACKAGE}" in packages
                and f"package:{SHIZUKU_HELPER_PACKAGE}" in packages
                and process_line
                and process_line.split()[0] == "shell"
            ):
                print(
                    "SHIZUKU_OK privilege=shell startup=device-local "
                    f"process={process_line.strip()!r} "
                    f"helper_log={int('Shizuku started through loopback ADB' in logs)}"
                )
                return
            time.sleep(3)
        raise ProvisionError(
            "Shizuku did not start as Android shell after boot; "
            f"process_observed={int('shizuku_server' in process)} "
            f"helper_log={logs[-500:]!r}"
        )

    def verify_shizuku_channel(self) -> None:
        """End-state Shizuku verification for the root-channel path.

        verify_shizuku() above is an install-phase startup check: it
        requires the standalone helper package present and a
        shizuku_server running as the shell user, because in its
        original context (the verify boot before autoroot staging)
        the helper has just started the server through loopback ADB.
        The finished autoroot state legitimately differs on both
        points — the flow removes the standalone helper once its
        keypair is merged into the autoroot helper, and the server
        runs as uid 0 — so on the channel path that check can never
        pass (Run 33 gate re-run). This variant asserts the same
        underlying guarantee against the finished state: the
        install-time package-verifier manipulation was reverted,
        the Shizuku package is installed, and its server is live as
        uid 0 (the mode the autoroot handoff maintains)."""
        self._verify_package_verifier_state()
        package_path = self._adb_run(
            ["shell", "pm", "path", SHIZUKU_PACKAGE],
            timeout=10,
            check=True,
        ).stdout
        if not package_path.startswith("package:"):
            raise ProvisionError(
                "Shizuku package is not installed on the channel path"
            )
        pid = self._adb_run(
            ["shell", "pidof", "shizuku_server"], timeout=5
        ).stdout.strip()
        uid = ""
        if pid:
            status = self._adb_run(
                ["shell", "cat", f"/proc/{pid.split()[0]}/status"],
                timeout=5,
            ).stdout
            match = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
            uid = match.group(1) if match else ""
        if not pid or uid != "0":
            raise ProvisionError(
                "root-mode Shizuku is not live on the channel path: "
                f"pid={pid.split()[0] if pid else 'none'} uid={uid!r}"
            )
        print(
            "SHIZUKU_OK privilege=root startup=autoroot "
            f"process=pid={pid.split()[0]} uid=0"
        )

    def verify_shizuku_removed(self) -> None:
        packages = self._adb_run(
            ["shell", "pm", "list", "packages"], timeout=15, check=True
        ).stdout
        process = self._adb_run(["shell", "ps", "-A"], timeout=10, check=True).stdout
        remaining = [
            package
            for package in (SHIZUKU_PACKAGE, SHIZUKU_HELPER_PACKAGE)
            if f"package:{package}" in packages
        ]
        if remaining or "shizuku_server" in process:
            raise ProvisionError(
                "Shizuku removal did not persist: "
                f"packages={','.join(remaining) or 'none'} "
                f"server={int('shizuku_server' in process)}"
            )
        print("SHIZUKU_REMOVED_OK packages=absent server=absent")

    def start_shizuku_as_root(self) -> None:
        """Restart shizuku_server as uid 0 through the root payload.

        The boot helper starts Shizuku with shell privileges through
        loopback ADB. With the root payload serving on this boot, kill
        that instance and re-run the official starter from the payload's
        uid-0 context instead, then require the new server process to
        report uid 0 in its /proc status.
        """
        dump = self._adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_PACKAGE],
            timeout=15,
            check=True,
        ).stdout
        native_match = re.search(r"nativeLibraryDir=(\S+)", dump)
        if native_match is not None:
            starter = f"{native_match.group(1)}/libshizuku.so"
        else:
            # Android 9 package dumps carry only legacyNativeLibraryDir,
            # which points at the extraction root; the libraries live in
            # its per-ABI subdirectory (lib/<abi-dir>/libshizuku.so).
            legacy_match = re.search(r"legacyNativeLibraryDir=(\S+)", dump)
            abi_match = re.search(r"primaryCpuAbi=(\S+)", dump)
            abi_dirs = {
                "arm64-v8a": "arm64",
                "armeabi-v7a": "arm",
                "armeabi": "arm",
                "x86_64": "x86_64",
                "x86": "x86",
            }
            abi_dir = abi_dirs.get(abi_match.group(1)) if abi_match else None
            if legacy_match is None or abi_dir is None:
                raise ProvisionError(
                    "could not resolve Shizuku nativeLibraryDir for root start"
                )
            starter = f"{legacy_match.group(1)}/{abi_dir}/libshizuku.so"
        pm_path = self._adb_run(
            ["shell", "pm", "path", SHIZUKU_PACKAGE],
            timeout=10,
            check=True,
        ).stdout.strip()
        apk_match = re.search(r"package:(.+)", pm_path)
        if apk_match is None:
            raise ProvisionError("could not resolve Shizuku APK path")
        apk = apk_match.group(1).strip()
        # Kill any shell-mode server from THIS shell context first.
        # The helper-started server runs as uid 2000; the payload
        # daemon is uid 0 but sits in the shell SELinux domain, and
        # signaling the helper's server from there returns EPERM, so
        # neither the daemon-side kill loop nor the starter can stop
        # it (run 13, 2026-11-04: starter aborted "can't kill 4105",
        # PROVISION_ERROR pid=4105 uid=2000). A same-uid shell kill
        # works — proven manually on that boot: adb shell kill, then
        # the root starter came up clean (pid 13288, Uid 0).
        self._adb_run(
            [
                "shell",
                "for p in $(pidof shizuku_server); do kill $p; done; true",
            ],
            timeout=10,
        )
        kill_deadline = time.monotonic() + 10
        while time.monotonic() < kill_deadline:
            remaining = self._adb_run(
                ["shell", "pidof", "shizuku_server"], timeout=5
            ).stdout.strip()
            if not remaining:
                break
            time.sleep(0.5)
        # Kill via pidof, never "pkill -f shizuku_server": this EXEC
        # shell's own command line contains that pattern, so pkill -f
        # matches the shell itself and kills it before the starter
        # runs (run 10, 2026-11-03: SHIZUKU_ROOT_START output empty).
        # pidof matches the process name only, so it cannot self-match.
        command = (
            "for p in $(pidof shizuku_server); do kill $p; done; sleep 1; "
            f"{shlex.quote(starter)} --apk={shlex.quote(apk)}; "
            "sleep 1; pidof shizuku_server"
        )
        code, output = self._daemon_exec(command)
        print(
            f"SHIZUKU_ROOT_START exit={code} output={output.strip()!r}",
            flush=True,
        )
        deadline = time.monotonic() + 30
        last = ""
        while time.monotonic() < deadline:
            pid = self._adb_run(
                ["shell", "pidof", "shizuku_server"], timeout=5
            ).stdout.strip()
            if pid:
                status = self._adb_run(
                    ["shell", "cat", f"/proc/{pid.split()[0]}/status"],
                    timeout=5,
                ).stdout
                uid_match = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
                if uid_match is not None:
                    last = f"pid={pid.split()[0]} uid={uid_match.group(1)}"
                    if uid_match.group(1) == "0":
                        print(f"SHIZUKU_ROOT_OK {last}", flush=True)
                        return
            time.sleep(2)
        raise ProvisionError(
            f"shizuku_server did not come up as uid 0: {last or 'not running'}"
        )
