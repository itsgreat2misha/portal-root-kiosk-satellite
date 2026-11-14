#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Validate and patch Omni dynamic MHA tuning blobs."""

from __future__ import annotations

import dataclasses
import hashlib
import struct


OMNI_STOCK_SHA256 = (
    "b1af517240bffcc69739cb57c906e422f3b5c3c69e6bf2ed16f70e0fe6ec7bde"
)
_FILE_HEADER_SIZE = 14
_BLOB_NAME_SIZE = 32
_INT32 = 6
_FLOAT32 = 9


@dataclasses.dataclass(frozen=True)
class Change:
    blob_id: int
    blob_name: str
    parameter: int
    old_value: int | float
    new_value: int | float


# Keep the core stereo processing mode active.  The controls below are the
# actual double-talk/echo suppressors and uplink noise suppressors that mute
# Omni's microphones while the speakers are playing.
_DISABLED_PARAMETERS: dict[int, dict[int, tuple[int, int | float]]] = {
    3: {202: (_INT32, 0), 203: (_INT32, 0), 204: (_FLOAT32, 0.0)},
    5: {301: (_INT32, 0), 303: (_INT32, 0), 304: (_FLOAT32, 0.0)},
    6: {351: (_INT32, 0), 353: (_INT32, 0), 354: (_FLOAT32, 0.0)},
    8: {202: (_INT32, 0), 203: (_INT32, 0), 204: (_FLOAT32, 0.0)},
    9: {202: (_INT32, 0), 203: (_INT32, 0), 204: (_FLOAT32, 0.0)},
    12: {301: (_INT32, 0), 303: (_INT32, 0), 304: (_FLOAT32, 0.0)},
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_omni_tuning(data: bytes) -> tuple[bytes, tuple[Change, ...]]:
    """Return a validated same-size Omni blob with suppression disabled."""
    if len(data) < _FILE_HEADER_SIZE:
        raise ValueError("MHA tuning file is truncated")
    version, mha_version, marker, payload_size, blob_count = struct.unpack_from(
        "<IHHIH", data, 0
    )
    if version != 1 or mha_version != 1 or marker != 0x9090:
        raise ValueError(
            "unsupported MHA tuning header "
            f"version={version} mha_version={mha_version} marker={marker:#x}"
        )
    if payload_size != len(data) - _FILE_HEADER_SIZE:
        raise ValueError("MHA tuning payload size does not match the file")

    output = bytearray(data)
    offset = _FILE_HEADER_SIZE
    seen_blobs: set[int] = set()
    seen_parameters: set[tuple[int, int]] = set()
    changes: list[Change] = []
    for _ in range(blob_count):
        if offset + 4 + _BLOB_NAME_SIZE > len(data):
            raise ValueError("MHA blob header is truncated")
        blob_id, parameter_count, blob_size = struct.unpack_from(
            "<BBH", data, offset
        )
        offset += 4
        raw_name = data[offset : offset + _BLOB_NAME_SIZE]
        offset += _BLOB_NAME_SIZE
        blob_name = raw_name.split(b"\0", 1)[0].decode("ascii", "strict")
        blob_end = offset + blob_size
        if blob_end > len(data):
            raise ValueError(f"MHA blob {blob_id} extends past the file")
        if blob_id in seen_blobs:
            raise ValueError(f"duplicate MHA blob id {blob_id}")
        seen_blobs.add(blob_id)

        for _ in range(parameter_count):
            if offset + 7 > blob_end:
                raise ValueError(f"MHA blob {blob_id} parameter is truncated")
            _channel, value_type, value_count, parameter = struct.unpack_from(
                "<BBBI", data, offset
            )
            value_offset = offset + 7
            value_size = value_count * 4
            offset = value_offset + value_size
            if offset > blob_end:
                raise ValueError(
                    f"MHA blob {blob_id} parameter {parameter} is truncated"
                )
            requested = _DISABLED_PARAMETERS.get(blob_id, {}).get(parameter)
            if requested is None:
                continue
            expected_type, new_value = requested
            if value_type != expected_type or value_count != 1:
                raise ValueError(
                    f"unexpected encoding for blob {blob_id} parameter {parameter}"
                )
            value_format = "<i" if value_type == _INT32 else "<f"
            old_value = struct.unpack_from(value_format, data, value_offset)[0]
            struct.pack_into(value_format, output, value_offset, new_value)
            seen_parameters.add((blob_id, parameter))
            changes.append(
                Change(blob_id, blob_name, parameter, old_value, new_value)
            )
        if offset != blob_end:
            raise ValueError(
                f"MHA blob {blob_id} parsed to {offset:#x}, expected {blob_end:#x}"
            )

    if offset != len(data):
        raise ValueError("trailing bytes after the final MHA blob")
    expected_parameters = {
        (blob_id, parameter)
        for blob_id, parameters in _DISABLED_PARAMETERS.items()
        for parameter in parameters
    }
    missing = sorted(expected_parameters - seen_parameters)
    if missing:
        raise ValueError(f"required MHA parameters are missing: {missing}")
    if len(output) != len(data):
        raise AssertionError("MHA patch unexpectedly changed the file size")
    return bytes(output), tuple(changes)

