#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Pins for the prebuilt release bundle (Phase E).

The bundle path replaces the local Android build, so its selection
logic is fail-closed by contract: a bundle that does not carry the
device's target, whose recorded fingerprint disagrees with the
target, or whose files do not hash to the manifest must refuse
before anything is installed. These tests build synthetic bundles
in a temp directory; no device or toolchain is involved.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "tools"))

import prebuilt_bundle  # noqa: E402
from device_session import ProvisionError  # noqa: E402
from portal_targets import TARGETS  # noqa: E402


TARGET = next(t for t in TARGETS if t.key == "portal-plus-aloha-1041515800015050")
OTHER = next(t for t in TARGETS if t.key != TARGET.key)


def write_bundle(
    root: pathlib.Path,
    *,
    targets=(TARGET,),
    tamper: str | None = None,
    drop_file: str | None = None,
) -> pathlib.Path:
    """Assemble a minimal synthetic bundle directory at root."""
    files: dict[str, dict[str, object]] = {}
    payloads = {
        f"exploit/build/{t.preload_name}": f"payload for {t.key}".encode()
        for t in targets
    }
    payloads["helper/build/libportal_audio_persist.so"] = b"shared helper"
    for relpath, content in payloads.items():
        files[relpath] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        if relpath == drop_file:
            continue
        destination = root / relpath
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    if tamper is not None:
        (root / tamper).write_bytes(b"tampered contents")
    manifest = {
        "format": prebuilt_bundle.BUNDLE_FORMAT_VERSION,
        "provisioner_version": "0.9.0-test",
        "targets": [
            {
                "key": t.key,
                "device": t.device,
                "fingerprint": t.fingerprint,
                "preload": f"exploit/build/{t.preload_name}",
            }
            for t in targets
        ],
        "files": files,
    }
    (root / prebuilt_bundle.BUNDLE_MANIFEST_NAME).write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return root


class PrebuiltBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)

    def load(self, root: pathlib.Path) -> prebuilt_bundle.Bundle:
        return prebuilt_bundle.load_bundle(root)

    def test_matching_bundle_verifies_and_installs(self) -> None:
        root = write_bundle(self.base / "bundle")
        bundle = self.load(root)
        entry = prebuilt_bundle.select_target_entry(bundle, TARGET)
        self.assertEqual(entry["key"], TARGET.key)
        verified = prebuilt_bundle.verify_files(bundle)
        self.assertIn(f"exploit/build/{TARGET.preload_name}", verified)
        repository = self.base / "repo"
        installed = prebuilt_bundle.install_artifacts(bundle, repository)
        self.assertEqual(sorted(installed), sorted(verified))
        installed_preload = repository / "exploit/build" / TARGET.preload_name
        self.assertEqual(
            installed_preload.read_bytes(),
            f"payload for {TARGET.key}".encode(),
        )

    def test_tarball_bundle_loads(self) -> None:
        root = write_bundle(self.base / "portal-provisioner-bundle-test")
        tarball = self.base / "bundle.tar.gz"
        with tarfile.open(tarball, "w:gz") as archive:
            archive.add(root, arcname=root.name)
        bundle = self.load(tarball)
        entry = prebuilt_bundle.select_target_entry(bundle, TARGET)
        self.assertEqual(entry["key"], TARGET.key)
        prebuilt_bundle.verify_files(bundle)

    def test_missing_target_fails_closed(self) -> None:
        root = write_bundle(self.base / "bundle", targets=(OTHER,))
        bundle = self.load(root)
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.select_target_entry(bundle, TARGET)

    def test_fingerprint_mismatch_fails_closed(self) -> None:
        root = write_bundle(self.base / "bundle")
        manifest_path = root / prebuilt_bundle.BUNDLE_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["targets"][0]["fingerprint"] = "Facebook/other/build:10/x"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        bundle = self.load(root)
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.select_target_entry(bundle, TARGET)

    def test_tampered_file_fails_hash_verification(self) -> None:
        preload = f"exploit/build/{TARGET.preload_name}"
        root = write_bundle(self.base / "bundle", tamper=preload)
        bundle = self.load(root)
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.verify_files(bundle)

    def test_missing_file_fails_hash_verification(self) -> None:
        preload = f"exploit/build/{TARGET.preload_name}"
        root = write_bundle(self.base / "bundle", drop_file=preload)
        bundle = self.load(root)
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.verify_files(bundle)

    def test_unknown_format_fails_closed(self) -> None:
        root = write_bundle(self.base / "bundle")
        manifest_path = root / prebuilt_bundle.BUNDLE_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["format"] = 999
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ProvisionError):
            self.load(root)

    def test_unsafe_manifest_path_fails_closed(self) -> None:
        root = write_bundle(self.base / "bundle")
        manifest_path = root / prebuilt_bundle.BUNDLE_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["../escape.so"] = {"sha256": "0" * 64, "size": 1}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        bundle = self.load(root)
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.verify_files(bundle)

    def test_builder_ships_the_release_signing_certificate(self) -> None:
        # A bundle run standalone is its own running tree, and the
        # runtime looks for the pinned release certificate there;
        # if the builder stops shipping it, every signed bundle
        # refuses to verify (the v0.9.0 live proof, Nov 20, 2026).
        import build_release_bundle

        self.assertIn(
            prebuilt_bundle.RELEASE_CERT_NAME, build_release_bundle.ROOT_FILES
        )
        self.assertTrue(
            (REPOSITORY / prebuilt_bundle.RELEASE_CERT_NAME).is_file()
        )

    def test_unsigned_bundle_reports_no_signature(self) -> None:
        root = write_bundle(self.base / "bundle")
        bundle = self.load(root)
        self.assertFalse(prebuilt_bundle.verify_signature(bundle, REPOSITORY))

    @unittest.skipUnless(
        subprocess.run(
            ["openssl", "version"], capture_output=True, check=False
        ).returncode
        == 0,
        "openssl is required for the signature pins",
    )
    def test_signed_bundle_verifies_and_tampered_manifest_fails(self) -> None:
        root = write_bundle(self.base / "bundle")
        key = self.base / "key.pem"
        cert = self.base / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "1", "-nodes", "-subj", "/CN=bundle test",
            ],
            capture_output=True, check=True,
        )
        manifest = root / prebuilt_bundle.BUNDLE_MANIFEST_NAME
        signature = root / prebuilt_bundle.BUNDLE_SIGNATURE_NAME
        subprocess.run(
            [
                "openssl", "dgst", "-sha256", "-sign", str(key),
                "-out", str(signature), str(manifest),
            ],
            capture_output=True, check=True,
        )
        bundle = self.load(root)
        repository = self.base / "repo"
        repository.mkdir()
        (repository / prebuilt_bundle.RELEASE_CERT_NAME).write_bytes(
            cert.read_bytes()
        )
        # The test key is not the pinned release key, so the pin
        # itself must refuse it before signature verification.
        with self.assertRaises(ProvisionError):
            prebuilt_bundle.verify_signature(bundle, repository)
        # With the pin pointed at the test certificate, the same
        # signature verifies, and a tampered manifest then fails.
        fingerprint = subprocess.run(
            [
                "openssl", "x509", "-in", str(cert),
                "-noout", "-fingerprint", "-sha256",
            ],
            capture_output=True, text=True, check=True,
        ).stdout.strip().split("=", 1)[1].upper()
        original = prebuilt_bundle.RELEASE_SIGNING_CERT_SHA256
        prebuilt_bundle.RELEASE_SIGNING_CERT_SHA256 = fingerprint
        try:
            self.assertTrue(
                prebuilt_bundle.verify_signature(bundle, repository)
            )
            manifest.write_text(
                manifest.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ProvisionError):
                prebuilt_bundle.verify_signature(bundle, repository)
        finally:
            prebuilt_bundle.RELEASE_SIGNING_CERT_SHA256 = original


if __name__ == "__main__":
    unittest.main()
