# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

import io
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout


TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from device_session import ProvisionError  # noqa: E402
from features.audio import (  # noqa: E402
    MHA_TUNING_BACKUP_REMOTE,
    AudioFeature,
    mha_tuning_path_for_board,
)
from mha_tuning import patch_omni_tuning, sha256  # noqa: E402


INT32 = 6
FLOAT32 = 9


def parameter(number: int, value_type: int, value: int | float) -> bytes:
    value_format = "<i" if value_type == INT32 else "<f"
    return struct.pack("<BBBI", 0xFF, value_type, 1, number) + struct.pack(
        value_format, value
    )


def tuning_fixture() -> bytes:
    parameters = {
        3: ((202, INT32, 3), (203, INT32, 1), (204, FLOAT32, 45.0)),
        5: ((301, INT32, 1), (303, INT32, 1), (304, FLOAT32, 18.0)),
        6: ((351, INT32, 1), (353, INT32, 1), (354, FLOAT32, 3.0)),
        8: ((202, INT32, 3), (203, INT32, 1), (204, FLOAT32, 35.0)),
        9: ((202, INT32, 3), (203, INT32, 1), (204, FLOAT32, 25.0)),
        12: ((301, INT32, 1), (303, INT32, 1), (304, FLOAT32, 40.0)),
    }
    blobs = bytearray()
    for blob_id in range(1, 13):
        records = b"".join(
            parameter(number, value_type, value)
            for number, value_type, value in parameters.get(blob_id, ())
        )
        name = f"fixture-{blob_id}".encode("ascii").ljust(32, b"\0")
        blobs += struct.pack(
            "<BBH", blob_id, len(parameters.get(blob_id, ())), len(records)
        )
        blobs += name + records
    return struct.pack("<IHHIH", 1, 1, 0x9090, len(blobs), 12) + blobs


class MhaTuningPatchTest(unittest.TestCase):
    def test_patch_is_same_size_complete_and_idempotent(self) -> None:
        stock = tuning_fixture()
        patched, changes = patch_omni_tuning(stock)
        patched_again, second_changes = patch_omni_tuning(patched)

        self.assertEqual(len(stock), len(patched))
        self.assertNotEqual(stock, patched)
        self.assertEqual(patched, patched_again)
        self.assertEqual(len(changes), 18)
        self.assertEqual(len(second_changes), 18)
        self.assertTrue(all(change.new_value == 0 for change in changes))

    def test_rejects_truncated_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "size|truncated"):
            patch_omni_tuning(tuning_fixture()[:-1])

    def test_rejects_missing_required_parameter(self) -> None:
        fixture = bytearray(tuning_fixture())
        # Rename parameter 202 in blob 3 without changing any length fields.
        needle = struct.pack("<BBBI", 0xFF, INT32, 1, 202)
        offset = fixture.find(needle)
        self.assertGreater(offset, 0)
        struct.pack_into("<I", fixture, offset + 3, 999)
        with self.assertRaisesRegex(ValueError, "required MHA parameters"):
            patch_omni_tuning(bytes(fixture))


class MhaTuningBoardPathTest(unittest.TestCase):
    def test_omni_board_resolves_the_omni_path(self) -> None:
        self.assertEqual(
            mha_tuning_path_for_board("omni"),
            "/vendor/etc/audio/omni/mha_tuning_blobs.tub",
        )

    def test_atlas_board_resolves_the_atlas_path(self) -> None:
        self.assertEqual(
            mha_tuning_path_for_board("atlas"),
            "/vendor/etc/audio/atlas/mha_tuning_blobs.tub",
        )

    def test_arbitrary_board_resolves_its_own_path(self) -> None:
        self.assertEqual(
            mha_tuning_path_for_board("someboard"),
            "/vendor/etc/audio/someboard/mha_tuning_blobs.tub",
        )

    def test_unusable_board_values_are_refused(self) -> None:
        for board in ("", " ", ".", "..", "a/b", "/omni", "omni "):
            with self.subTest(board=board):
                with self.assertRaises(ProvisionError):
                    mha_tuning_path_for_board(board)


class FakeAudioDevice:
    """AudioFeature device fakes: answers the board getprop and
    serves recorded contents for pulls."""

    def __init__(self, board: str, files: dict[str, bytes]) -> None:
        self._board = board
        self._files = files
        self.getprop_calls = 0
        self.pulled: list[str] = []

    def adb_run(self, args, timeout=None, check=False):
        if list(args) == ["shell", "getprop", "ro.boot.hardware"]:
            self.getprop_calls += 1
            return subprocess.CompletedProcess(args, 0, self._board + "\n", "")
        raise AssertionError(f"unexpected adb call: {args}")

    def pull_file(self, remote: str, local: pathlib.Path) -> bytes:
        self.pulled.append(remote)
        return self._files[remote]


def make_audio_feature(
    device: FakeAudioDevice, log_dir: pathlib.Path
) -> AudioFeature:
    return AudioFeature(
        adb_run=device.adb_run,
        pull_file=device.pull_file,
        logcat_watermark=lambda: None,
        logcat_poll=lambda tag, since, timeout=10: "",
        log_dir=log_dir,
        target=lambda: None,
        restore_audio=lambda: False,
    )


class MhaTuningPrepareBoardTest(unittest.TestCase):
    """prepare_mha_tuning_payloads must pull, gate, and record the
    tuning file for the device's own board. The stock-hash gate is
    pointed at the synthetic fixture so the gate itself, not the
    fixture, decides each case."""

    def prepare(self, board: str, files: dict[str, bytes]):
        device = FakeAudioDevice(board, files)
        with tempfile.TemporaryDirectory() as temporary:
            feature = make_audio_feature(device, pathlib.Path(temporary))
            output = io.StringIO()
            with (
                unittest.mock.patch(
                    "features.audio.OMNI_STOCK_SHA256",
                    sha256(tuning_fixture()),
                ),
                redirect_stdout(output),
            ):
                stock_path, patched_path = feature.prepare_mha_tuning_payloads()
                stock = stock_path.read_bytes()
                patched = patched_path.read_bytes()
        return device, feature, output.getvalue(), stock, patched

    def test_atlas_board_pulls_and_prepares_the_atlas_file(self) -> None:
        atlas_path = "/vendor/etc/audio/atlas/mha_tuning_blobs.tub"
        device, feature, output, stock, patched = self.prepare(
            "atlas", {atlas_path: tuning_fixture()}
        )
        self.assertEqual(device.pulled, [atlas_path])
        self.assertEqual(feature.mha_tuning_device_path(), atlas_path)
        self.assertEqual(device.getprop_calls, 1)
        self.assertIn(f"path={atlas_path}", output)
        self.assertEqual(stock, tuning_fixture())
        self.assertNotEqual(patched, stock)
        self.assertEqual(len(patched), len(stock))

    def test_omni_board_keeps_the_omni_file(self) -> None:
        omni_path = "/vendor/etc/audio/omni/mha_tuning_blobs.tub"
        device, feature, output, stock, patched = self.prepare(
            "omni", {omni_path: tuning_fixture()}
        )
        self.assertEqual(device.pulled, [omni_path])
        self.assertEqual(feature.mha_tuning_device_path(), omni_path)
        self.assertIn(f"path={omni_path}", output)

    def test_unknown_board_file_still_fails_the_hash_gate(self) -> None:
        atlas_path = "/vendor/etc/audio/atlas/mha_tuning_blobs.tub"
        device = FakeAudioDevice(
            "atlas",
            {
                atlas_path: b"unknown contents",
                MHA_TUNING_BACKUP_REMOTE: b"also unknown",
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            feature = make_audio_feature(device, pathlib.Path(temporary))
            with (
                unittest.mock.patch(
                    "features.audio.OMNI_STOCK_SHA256",
                    sha256(tuning_fixture()),
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(ProvisionError):
                    feature.prepare_mha_tuning_payloads()
        self.assertEqual(
            device.pulled, [atlas_path, MHA_TUNING_BACKUP_REMOTE]
        )


if __name__ == "__main__":
    unittest.main()

