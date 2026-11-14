# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

import pathlib
import struct
import sys
import unittest


TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from mha_tuning import patch_omni_tuning  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()

