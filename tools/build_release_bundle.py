# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Build the prebuilt release bundle (Phase E).

Builds every supported target with every component on (through the
provisioner's own build(), exactly as a local run builds), then
assembles one bundle directory:

    portal-provisioner-bundle-<version>/
      bundle-manifest.json     format, version, target table, and a
                               SHA-256 + size entry for every file
      bundle-manifest.json.sig detached release signature (only
                               with --sign-key)
      exploit/build/…          the five target payloads + ctl jars
      helper/build/…           the audio persistence libraries
      *-helper/build/…         the model-independent APK set
      uid1000-helper/build/…   the per-target uid1000 artifacts
      root-daemon/…            the custom-payload root daemon
      shizuku/…                the pinned Shizuku APK (hash-verified
                               against the constant in the source)
      simpleperf/simpleperf    the NDK arm64 simpleperf binary the
                               aloha targets stage for KASLR discovery
      tools/…                  the provisioner sources, so the bundle
                               alone is a runnable checkout
      README.md / FORK.md / CHANGELOG.md / LICENSE / NOTICE /
      release-signing-cert.pem

Usage:
    python3 tools/build_release_bundle.py --output dist
        [--sign-key release-key.pem] [--tarball]

The release workflow runs this on a tag; the signing key comes from
CI secrets and never touches the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from features.shizuku import SHIZUKU_APK_NAME, SHIZUKU_APK_SHA256, SHIZUKU_APK_URL
from portal_targets import TARGETS
import prebuilt_bundle
import provision_portal


# Root-level files copied into the bundle. The release signing
# certificate must ride along: the runtime looks for it in the
# running tree (its fingerprint is pinned in code), and a bundle
# run standalone IS the running tree, so without the certificate
# every signed bundle refuses to verify. Found by the v0.9.0 live
# bundle proof, Nov 20, 2026.
ROOT_FILES = (
    "README.md",
    "FORK.md",
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    prebuilt_bundle.RELEASE_CERT_NAME,
)


def expected_artifact_relpaths() -> list[str]:
    """Every file the bundle must carry, repo-relative: the build
    outputs, plus the autoroot runner script. run.sh is a source
    file, not a build output, but the runtime stages it on-device
    from the tree, so a bundle without it cannot stage autoroot
    (the channel path fell back to a full install in the v0.9.0
    live proof, Nov 20, 2026)."""
    relpaths = {
        "autoroot-helper/run.sh",
        "helper/build/libportal_audio_persist.so",
        "helper/build/libportal_audio_persist_java.so",
        "exploit/build/portal-audio-ctl.jar",
        "exploit/build/portal-account-ctl.jar",
        "exploit/build/portal-component-ctl.jar",
        "shizuku-helper/build/portal-shizuku-helper.apk",
        "autoroot-helper/build/portal-autoroot-helper.apk",
        "presence-helper/build/portal-presence-helper.apk",
        "exploit-sentinel/build/portal-exploit-sentinel.apk",
        "uid1000-helper/build/portal-uid1000-runtime.apk",
        "root-daemon/portal-root-daemon",
    }
    for target in TARGETS:
        relpaths.add(f"exploit/build/{target.preload_name}")
        relpaths.add(f"uid1000-helper/build/{target.uid1000_helper_artifact}")
        relpaths.add(f"uid1000-helper/build/{target.uid1000_hook_artifact}")
    return sorted(relpaths)


def build_all_targets() -> None:
    seen: set[str] = set()
    for target in TARGETS:
        if target.key in seen:
            continue
        seen.add(target.key)
        provision_portal.build(
            target,
            build_audio=True,
            build_account=True,
            build_components=True,
            build_shizuku=True,
            build_autoroot=True,
            build_presence=True,
            build_uid1000=True,
            build_sentinel=True,
            build_daemon=True,
        )
    print(f"built {len(seen)} targets", flush=True)


def fetch_shizuku_apk(destination: pathlib.Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    urllib.request.urlretrieve(SHIZUKU_APK_URL, temporary)
    digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
    if digest != SHIZUKU_APK_SHA256:
        temporary.unlink(missing_ok=True)
        raise SystemExit(
            f"downloaded Shizuku APK hash mismatch: {digest} "
            f"(pinned {SHIZUKU_APK_SHA256})"
        )
    temporary.replace(destination)


def assemble(output_dir: pathlib.Path, version: str) -> pathlib.Path:
    bundle_name = f"portal-provisioner-bundle-{version}"
    bundle_dir = output_dir / bundle_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)

    files: dict[str, dict[str, object]] = {}

    def add(source: pathlib.Path, relpath: str) -> None:
        if not source.is_file():
            raise SystemExit(f"expected build output is missing: {relpath}")
        destination = bundle_dir / relpath
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        files[relpath] = {
            "sha256": prebuilt_bundle.sha256_file(destination),
            "size": destination.stat().st_size,
        }

    for relpath in expected_artifact_relpaths():
        add(ROOT / relpath, relpath)

    environment = provision_portal.android_build_environment()
    simpleperf = (
        pathlib.Path(environment["NDK"])
        / "simpleperf/bin/android/arm64/simpleperf"
    )
    add(simpleperf, prebuilt_bundle.SIMPLEPERF_BUNDLE_PATH)

    shizuku_relpath = (
        f"{prebuilt_bundle.SHIZUKU_BUNDLE_DIR}/{SHIZUKU_APK_NAME}"
    )
    shizuku_source = bundle_dir / shizuku_relpath
    shizuku_source.parent.mkdir(parents=True, exist_ok=True)
    fetch_shizuku_apk(shizuku_source)
    files[shizuku_relpath] = {
        "sha256": prebuilt_bundle.sha256_file(shizuku_source),
        "size": shizuku_source.stat().st_size,
    }

    # The provisioner sources ride along (not hash-listed: they are
    # the code that verifies the manifest, not payload artifacts).
    shutil.copytree(
        ROOT / "tools",
        bundle_dir / "tools",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    for name in ROOT_FILES:
        shutil.copyfile(ROOT / name, bundle_dir / name)

    manifest = {
        "format": prebuilt_bundle.BUNDLE_FORMAT_VERSION,
        "provisioner_version": version,
        "targets": [
            {
                "key": target.key,
                "device": target.device,
                "fingerprint": target.fingerprint,
                "preload": f"exploit/build/{target.preload_name}",
            }
            for target in TARGETS
        ],
        "files": files,
    }
    (bundle_dir / prebuilt_bundle.BUNDLE_MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"bundle assembled: {bundle_dir} ({len(files)} hashed files)")
    return bundle_dir


def sign_bundle(bundle_dir: pathlib.Path, key_pem: pathlib.Path) -> None:
    manifest = bundle_dir / prebuilt_bundle.BUNDLE_MANIFEST_NAME
    signature = bundle_dir / prebuilt_bundle.BUNDLE_SIGNATURE_NAME
    result = subprocess.run(
        [
            "openssl", "dgst", "-sha256", "-sign", str(key_pem),
            "-out", str(signature), str(manifest),
        ],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"manifest signing failed: {result.stderr.strip()}")
    print(f"manifest signed: {signature}")


def make_tarball(bundle_dir: pathlib.Path) -> pathlib.Path:
    tarball = bundle_dir.parent / (bundle_dir.name + ".tar.gz")
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(bundle_dir, arcname=bundle_dir.name)
    print(f"tarball written: {tarball}")
    return tarball


def make_zip(bundle_dir: pathlib.Path) -> pathlib.Path:
    """The same bundle as a .zip, for hosts whose stock tooling has
    no tar (notably Windows Explorer / Expand-Archive)."""
    archive_path = bundle_dir.parent / (bundle_dir.name + ".zip")
    with zipfile.ZipFile(
        archive_path, "w", zipfile.ZIP_DEFLATED
    ) as archive:
        for path in sorted(bundle_dir.rglob("*")):
            if path.is_file():
                archive.write(
                    path,
                    arcname=path.relative_to(bundle_dir.parent).as_posix(),
                )
    print(f"zip written: {archive_path}")
    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=pathlib.Path, required=True,
        help="directory the bundle directory is assembled under",
    )
    parser.add_argument(
        "--version", default=provision_portal.PROVISIONER_VERSION,
        help="version string for the bundle name and manifest",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="package the build outputs already present in the tree",
    )
    parser.add_argument(
        "--sign-key", type=pathlib.Path, default=None,
        help="PEM private key signing the manifest (release CI only)",
    )
    parser.add_argument(
        "--tarball", action="store_true",
        help="also write the .tar.gz next to the bundle directory",
    )
    parser.add_argument(
        "--zip", action="store_true",
        help="also write the .zip next to the bundle directory",
    )
    args = parser.parse_args()

    if not args.skip_build:
        build_all_targets()
    bundle_dir = assemble(args.output, args.version)
    if args.sign_key is not None:
        sign_bundle(bundle_dir, args.sign_key)
    if args.tarball:
        make_tarball(bundle_dir)
    if args.zip:
        make_zip(bundle_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
