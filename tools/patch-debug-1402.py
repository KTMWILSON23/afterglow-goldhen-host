#!/usr/bin/env python3
"""Patch the 14.02 SETLOGIN LEA operand in the published Akatsuki debug.bin.

This is an offline byte patch only. It does not establish that the remaining
HEN payload is compatible with PS4 firmware 14.02.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_R10, X86_REG_RAX


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "debug.bin"
DEFAULT_OUTPUT = ROOT / "debug-1402-fixed.bin"

SOURCE_REPOSITORY = "https://github.com/Jfkkfjzkz/ps4-akatsuki-jailbreak"
SOURCE_COMMIT = "689446d47fe1f3057923db7d7580efef3f182d87"
INPUT_SIZE = 498_720
INPUT_SHA256 = "19939e83d0dc57c1172a156503461a333129ebd3f9db704f0dbc3f249ecfcbd5"
OUTPUT_SHA256 = "5862bf202a7c5f146820fd6354330dd07b1c6bdbe6e7f939ba71692b5410d083"
OLD_RVA = 0x394ABC
NEW_RVA = 0x394E2C
OLD_INSTRUCTION = bytes.fromhex("4c8d90bc4a3900")
NEW_INSTRUCTION = bytes.fromhex("4c8d902c4e3900")

# Both copies are present in the exact published image. The second belongs to
# the 14.00 branch and must remain untouched. No signature scan is used as a
# substitute for a known file offset.
EXPECTED_OCCURRENCES = (0x18D3, 0x25D2)
PATCHES = (
    (0x18D3, "SETLOGIN LEA 14.02 branch"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_lea(image: bytes | bytearray, offset: int, expected: bytes, rva: int) -> None:
    actual = bytes(image[offset : offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"instruction at file offset 0x{offset:x} differs: "
            f"expected {expected.hex()}, got {actual.hex()}"
        )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(actual, offset))
    if len(instructions) != 1 or instructions[0].size != len(expected):
        raise ValueError(f"0x{offset:x} is not exactly one decoded instruction")
    instruction = instructions[0]
    operands = instruction.operands
    if (
        instruction.mnemonic != "lea"
        or len(operands) != 2
        or operands[0].type != X86_OP_REG
        or operands[0].reg != X86_REG_R10
        or operands[1].type != X86_OP_MEM
        or operands[1].mem.base != X86_REG_RAX
        or operands[1].mem.index != 0
        or operands[1].mem.disp != rva
    ):
        raise ValueError(
            f"unexpected instruction at 0x{offset:x}: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )


def patch_image(original: bytes) -> tuple[bytes, list[dict[str, object]]]:
    if len(original) != INPUT_SIZE or sha256(original) != INPUT_SHA256:
        raise ValueError("input is not the exact published Akatsuki debug.bin")
    if original[0] != 0xE9:
        raise ValueError("raw payload entry header is missing")
    observed = [i for i in range(len(original)) if original.startswith(OLD_INSTRUCTION, i)]
    if observed != list(EXPECTED_OCCURRENCES):
        raise ValueError(f"SETLOGIN LEA occurrence set differs: {observed!r}")
    verify_lea(original, EXPECTED_OCCURRENCES[1], OLD_INSTRUCTION, OLD_RVA)

    changed = bytearray(original)
    manifest_patches: list[dict[str, object]] = []
    for offset, label in PATCHES:
        verify_lea(original, offset, OLD_INSTRUCTION, OLD_RVA)
        changed[offset : offset + len(OLD_INSTRUCTION)] = NEW_INSTRUCTION
        verify_lea(changed, offset, NEW_INSTRUCTION, NEW_RVA)
        manifest_patches.append(
            {
                "label": label,
                "instruction_file_offset": f"0x{offset:x}",
                "displacement_file_offset": f"0x{offset + 3:x}",
                "old_instruction_hex": OLD_INSTRUCTION.hex(),
                "new_instruction_hex": NEW_INSTRUCTION.hex(),
                "old_rva": f"0x{OLD_RVA:x}",
                "new_rva": f"0x{NEW_RVA:x}",
            }
        )

    result = bytes(changed)
    verify_lea(result, EXPECTED_OCCURRENCES[1], OLD_INSTRUCTION, OLD_RVA)
    if len(result) != INPUT_SIZE or sha256(result) != OUTPUT_SHA256:
        raise ValueError("patched output does not match its pinned SHA-256")
    expected_changed = {0x18D6, 0x18D7}
    actual_changed = {i for i, (a, b) in enumerate(zip(original, result)) if a != b}
    if actual_changed != expected_changed:
        raise ValueError(f"unexpected changed byte positions: {sorted(actual_changed)!r}")
    return result, manifest_patches


def create_or_verify(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        action = "created"
    except FileExistsError:
        if path.read_bytes() != data:
            raise ValueError(f"existing output differs; refusing to overwrite {path}")
        action = "verified-existing"
    if path.read_bytes() != data:
        raise ValueError(f"output readback failed for {path}")
    return action


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    manifest_path = (args.manifest or output_path.with_suffix(".manifest.json")).resolve()
    if len({input_path, output_path, manifest_path}) != 3:
        raise ValueError("input, output, and manifest must use distinct paths")

    original = input_path.read_bytes()
    patched, patches = patch_image(original)
    manifest = {
        "purpose": "offline SETLOGIN LEA displacement correction only",
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "input": {"path": input_path.name, "size": len(original), "sha256": INPUT_SHA256},
        "output": {"path": output_path.name, "size": len(patched), "sha256": OUTPUT_SHA256},
        "decoder": {"name": "Capstone", "version": capstone_version, "architecture": "x86_64"},
        "patches": patches,
        "changed_byte_offsets": ["0x18d6", "0x18d7"],
        "preserved_1400_instruction_file_offset": "0x25d2",
        "scope_limit": "No other firmware offsets or HEN kernel writes are validated by this patch.",
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if args.check_only:
        sys.stdout.buffer.write(manifest_bytes)
        return
    output_action = create_or_verify(output_path, patched)
    manifest_action = create_or_verify(manifest_path, manifest_bytes)
    print(f"{output_action}: {output_path} ({OUTPUT_SHA256})")
    print(f"{manifest_action}: {manifest_path}")


if __name__ == "__main__":
    main()
