# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Prebuilt release bundles: hash-manifest verification and artifact
installation.

A release bundle is produced by tools/build_release_bundle.py: one
exploit payload per supported target plus the model-independent APK
set, a pinned Shizuku APK copy and the NDK simpleperf binary, all
listed with SHA-256 hashes in bundle-manifest.json. At runtime the
provisioner verifies the manifest against the device's selected
target and installs the artifacts into the repository's standard
build-output locations, so the run needs no Android toolchain on the
host (Python + adb only) and falls back to nothing: any mismatch —
an unknown manifest format, a target the bundle does not carry, a
fingerprint that disagrees with the device's, a missing or altered
file, an invalid release signature — refuses the run before any
device change.

Release bundles built by CI additionally carry a detached openssl
signature over the manifest (bundle-manifest.json.sig), made with
the project release signing key. The key itself lives only in CI
secrets; its certificate is committed at the repository root
(release-signing-cert.pem) and the runtime pins the certificate's
SHA-256 fingerprint below, so a bundle whose signature was made by
any other key is refused. A bundle without a signature (a locally
built one) is accepted on its hashes alone, the same trust a local
from-source build has always had.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from device_session import ProvisionError
from portal_targets import PortalTarget

BUNDLE_FORMAT_VERSION = 1
BUNDLE_MANIFEST_NAME = "bundle-manifest.json"
BUNDLE_SIGNATURE_NAME = "bundle-manifest.json.sig"
RELEASE_CERT_NAME = "release-signing-cert.pem"
# SHA-256 fingerprint of the release signing certificate committed
# next to this module's repository root. The private key is held in
# CI secrets only; rotating the key means committing the new
# certificate and updating this pin in the same change.
RELEASE_SIGNING_CERT_SHA256 = (
    "2F:9E:13:DD:24:CF:21:7A:AA:74:42:85:50:DA:E0:CA:59:1E:7A:79:8A:"
    "58:18:ED:27:64:44:71:21:7A:6C:42"
)
SHIZUKU_BUNDLE_DIR = "shizuku"
SIMPLEPERF_BUNDLE_PATH = "simpleperf/simpleperf"


class Bundle:
    """A loaded bundle: its root directory and parsed manifest."""

    def __init__(self, root: pathlib.Path, manifest: dict) -> None:
        self.root = root
        self.manifest = manifest

    @property
    def files(self) -> dict:
        files = self.manifest.get("files")
        if not isinstance(files, dict):
            raise ProvisionError("bundle manifest has no files table")
        return files

    @property
    def targets(self) -> list:
        targets = self.manifest.get("targets")
        if not isinstance(targets, list):
            raise ProvisionError("bundle manifest has no targets table")
        return targets


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check_relpath(relpath: str) -> None:
    path = pathlib.PurePosixPath(relpath)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ProvisionError(f"bundle manifest lists an unsafe path: {relpath!r}")


def _find_manifest_root(directory: pathlib.Path) -> pathlib.Path:
    if (directory / BUNDLE_MANIFEST_NAME).is_file():
        return directory
    children = [child for child in directory.iterdir() if child.is_dir()]
    if len(children) == 1 and (children[0] / BUNDLE_MANIFEST_NAME).is_file():
        return children[0]
    raise ProvisionError(
        f"no {BUNDLE_MANIFEST_NAME} found in bundle at {directory}"
    )


def load_bundle(path: pathlib.Path) -> Bundle:
    """Load a bundle from a directory, a .tar.gz archive, or a .zip
    archive (the zip is the same bundle, packaged for hosts whose
    stock tooling has no tar)."""
    path = path.expanduser()
    if path.is_file():
        is_tarball = path.name.endswith(".tar.gz") or path.name.endswith(
            ".tgz"
        )
        is_zip = path.name.endswith(".zip")
        if not (is_tarball or is_zip):
            raise ProvisionError(
                f"bundle file must be a .tar.gz or .zip archive: {path}"
            )
        extract_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="portal-bundle-")
        )
        if is_zip:
            # zipfile.extractall strips absolute paths and ".."
            # components from member names; the manifest hash
            # verification in verify_files() is the integrity gate
            # for whatever was extracted.
            with zipfile.ZipFile(path) as archive:
                archive.extractall(extract_dir)
        else:
            with tarfile.open(path, "r:gz") as archive:
                try:
                    archive.extractall(extract_dir, filter="data")
                except TypeError:  # older Python without PEP 706 filters
                    archive.extractall(extract_dir)
        root = _find_manifest_root(extract_dir)
    elif path.is_dir():
        root = _find_manifest_root(path)
    else:
        raise ProvisionError(f"bundle path does not exist: {path}")
    try:
        manifest = json.loads(
            (root / BUNDLE_MANIFEST_NAME).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"bundle manifest is unreadable: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ProvisionError("bundle manifest is not a JSON object")
    if manifest.get("format") != BUNDLE_FORMAT_VERSION:
        raise ProvisionError(
            "unsupported bundle manifest format: "
            f"{manifest.get('format')!r} (expected {BUNDLE_FORMAT_VERSION})"
        )
    return Bundle(root=root, manifest=manifest)


def verify_signature(bundle: Bundle, repository: pathlib.Path) -> bool:
    """Verify the detached release signature over the manifest.

    Returns True when a signature is present and valid, False when
    the bundle carries none. A present-but-invalid signature, or a
    signing certificate that is not the pinned release certificate,
    refuses the bundle.
    """
    signature = bundle.root / BUNDLE_SIGNATURE_NAME
    if not signature.is_file():
        return False
    certificate = repository / RELEASE_CERT_NAME
    if not certificate.is_file():
        raise ProvisionError(
            f"bundle is signed but {RELEASE_CERT_NAME} is missing from "
            "this checkout; refusing to trust the signature"
        )
    fingerprint = subprocess.run(
        [
            "openssl", "x509", "-in", str(certificate),
            "-noout", "-fingerprint", "-sha256",
        ],
        capture_output=True, text=True, check=False,
    )
    if fingerprint.returncode != 0 or "=" not in fingerprint.stdout:
        raise ProvisionError(
            "could not read the release signing certificate fingerprint"
        )
    actual = fingerprint.stdout.strip().split("=", 1)[1].upper()
    if actual != RELEASE_SIGNING_CERT_SHA256:
        raise ProvisionError(
            "release signing certificate fingerprint mismatch: "
            f"{actual} (pinned {RELEASE_SIGNING_CERT_SHA256}); "
            "refusing the bundle"
        )
    public_key = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        capture_output=True, text=True, check=False,
    )
    if public_key.returncode != 0:
        raise ProvisionError(
            "could not extract the release signing public key"
        )
    with tempfile.NamedTemporaryFile(
        "w", suffix=".pem", delete=False
    ) as handle:
        handle.write(public_key.stdout)
        public_key_path = handle.name
    try:
        result = subprocess.run(
            [
                "openssl", "dgst", "-sha256", "-verify", public_key_path,
                "-signature", str(signature),
                str(bundle.root / BUNDLE_MANIFEST_NAME),
            ],
            capture_output=True, text=True, check=False,
        )
    finally:
        pathlib.Path(public_key_path).unlink(missing_ok=True)
    if result.returncode != 0:
        raise ProvisionError(
            "bundle manifest signature does not verify against the "
            "pinned release certificate; refusing the bundle"
        )
    return True


def verify_files(bundle: Bundle) -> dict[str, str]:
    """Verify every manifest file exists with its recorded hash.

    Returns the relpath -> sha256 table on success; raises
    ProvisionError on the first missing or altered file.
    """
    verified: dict[str, str] = {}
    for relpath, entry in bundle.files.items():
        _check_relpath(relpath)
        if not isinstance(entry, dict) or not isinstance(
            entry.get("sha256"), str
        ):
            raise ProvisionError(
                f"bundle manifest entry for {relpath} has no sha256"
            )
        candidate = bundle.root / relpath
        if not candidate.is_file():
            raise ProvisionError(f"bundle file is missing: {relpath}")
        if candidate.stat().st_size != entry.get("size"):
            raise ProvisionError(f"bundle file size mismatch: {relpath}")
        digest = sha256_file(candidate)
        if digest != entry["sha256"]:
            raise ProvisionError(f"bundle file hash mismatch: {relpath}")
        verified[relpath] = digest
    if not verified:
        raise ProvisionError("bundle manifest lists no files")
    return verified


def select_target_entry(bundle: Bundle, target: PortalTarget) -> dict:
    """The manifest's entry for the device's selected target.

    Fail-closed: the bundle must carry the target key, and the
    recorded fingerprint and preload must match the target the
    device itself selected.
    """
    for entry in bundle.targets:
        if isinstance(entry, dict) and entry.get("key") == target.key:
            if entry.get("fingerprint") != target.fingerprint:
                raise ProvisionError(
                    f"bundle fingerprint for {target.key} disagrees "
                    "with the device target: "
                    f"{entry.get('fingerprint')!r} != {target.fingerprint!r}"
                )
            preload_relpath = f"exploit/build/{target.preload_name}"
            if entry.get("preload") != preload_relpath:
                raise ProvisionError(
                    f"bundle preload for {target.key} is "
                    f"{entry.get('preload')!r}, expected {preload_relpath!r}"
                )
            if preload_relpath not in bundle.files:
                raise ProvisionError(
                    f"bundle does not carry the payload for {target.key}"
                )
            return entry
    raise ProvisionError(
        f"bundle does not carry a payload for target {target.key}; "
        "build from source for this device instead"
    )


def install_artifacts(bundle: Bundle, repository: pathlib.Path) -> list[str]:
    """Copy every verified bundle artifact into the repository tree.

    Only paths listed in the (already verified) manifest are copied,
    each to the same relative location a local build would produce.
    """
    installed: list[str] = []
    for relpath in bundle.files:
        _check_relpath(relpath)
        destination = repository / relpath
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(bundle.root / relpath, destination)
        installed.append(relpath)
    return installed


def bundled_simpleperf(bundle: Bundle) -> pathlib.Path | None:
    candidate = bundle.root / SIMPLEPERF_BUNDLE_PATH
    return candidate if candidate.is_file() else None


def bundled_shizuku_apk(bundle: Bundle, apk_name: str) -> pathlib.Path | None:
    candidate = bundle.root / SHIZUKU_BUNDLE_DIR / apk_name
    return candidate if candidate.is_file() else None
