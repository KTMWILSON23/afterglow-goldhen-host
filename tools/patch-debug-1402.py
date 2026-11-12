#!/usr/bin/env python3
"""Patch the published Akatsuki debug.bin for a core 14.02 HEN launch.

This is an offline, exact-image byte patch. It corrects the SETLOGIN target
and two embedded kernel function addresses whose 14.02 counterparts were
verified against the decrypted kernel. It replaces compiler-emitted AVX
configuration copies in both the user wrapper and the syscall-11 kernel
callback, and replaces the callback's imported libc buffer operations with
scalar loops. This removes vector/FPU and userland-library execution from the
install-payload kernel path. It retains the FSELF/FPKG kernel hooks, but
bypasses unsupported optional installer actions, the unported 14.00-derived
userland patch table, plugin hooks, optional ShellCore plugin-loader injection,
and deliberate ShellUI restart. Those paths are the first known unsafe writes
on 14.02. It does not prove the remaining HEN runtime on hardware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_R10,
    X86_REG_RAX,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "debug.bin"
DEFAULT_OUTPUT = ROOT / "hen-1402-core.bin"

SOURCE_REPOSITORY = "https://github.com/Jfkkfjzkz/ps4-akatsuki-jailbreak"
SOURCE_COMMIT = "689446d47fe1f3057923db7d7580efef3f182d87"
HEN_SOURCE_ARCHIVE = "ps4-hen-main (1).zip"
HEN_SOURCE_ARCHIVE_SHA256 = (
    "bf418e981c40b8aa5aaf4874170eed98ba0b6c93228ba8e233542031739f3fac"
)
INPUT_SIZE = 498_720
INPUT_SHA256 = "19939e83d0dc57c1172a156503461a333129ebd3f9db704f0dbc3f249ecfcbd5"
OUTPUT_SHA256 = "525867736cfefad7a946dc006a09c3764440b88fc38384b81ab28e727ccdd489"
OLD_LEA_DISP = 0x394ABC
NEW_LEA_DISP = 0x394E2C
LSTAR_RVA = 0x1C0
OLD_SETLOGIN_RVA = OLD_LEA_DISP + LSTAR_RVA
NEW_SETLOGIN_RVA = NEW_LEA_DISP + LSTAR_RVA
OLD_INSTRUCTION = bytes.fromhex("4c8d90bc4a3900")
NEW_INSTRUCTION = bytes.fromhex("4c8d902c4e3900")

# Both copies are present in the exact published image. The second belongs to
# the 14.00 branch and must remain untouched. No signature scan is used as a
# substitute for a known file offset.
EXPECTED_OCCURRENCES = (0x18D3, 0x25D2)
PATCHES = (
    (0x18D3, "SETLOGIN LEA 14.02 branch"),
)

# The table begins at file offset 0x10c00 and mirrors struct fw_offsets.
# Each correction is pinned to an exact field, old value, and 14.02 value.
TABLE_PATCHES = (
    (0x10C6C, "sceSblACMgrGetPathId_addr", 0x003B3BC0, 0x003B3C50),
    (0x10C84, "RsaesPkcs1v15Dec2048CRT_addr", 0x0021C3E0, 0x0021C3D0),
)

PRESERVED_TABLE_VALUES = (
    # The hook already calls SmStart, so this underlying body target is kept.
    (0x10C80, "sceSblAuthMgrVerifyHeader_addr", 0x00640930),
    # This is the full 14.02 function entry; +0x40 would be mid-function.
    (0x10C98, "sceSblPfsSetKeys_addr", 0x006276F0),
)

# GCC vectorised both copies of the 44-byte configuration structure in
# kpayload_install_payload because the installer is built with
# -march=btver2. These instructions run in ring 0 through syscall 11 without
# fpu_kern_enter(), unlike the payload's explicit kernel crypto paths. Use
# scalar copies while preserving the exact source, destination, layout and
# firmware dispatch flags.
KERNEL_CONFIG_COPY_IN_OFFSET = 0x3A09
KERNEL_CONFIG_COPY_IN = bytes.fromhex(
    "c4c17e6f4304c4c17a6f4b20458b0b664181f95203"
    "c5fe7f45a4c5fa7f4dc0"
)
KERNEL_CONFIG_COPY_IN_SCALAR = bytes.fromhex(
    "458b0b498d7304488d7da4b92c000000fcf3a4"
    "664181f95203909090909090"
)

KERNEL_CONFIG_COPY_OUT_OFFSET = 0x4279
KERNEL_CONFIG_COPY_OUT = bytes.fromhex(
    "c5fe6f55a44883ec30448b8d6cffffff4d037708410fb7f9"
    "c5fe7f1424c5fa6f5dc0c5fa7f5c241c41ffd6"
)
KERNEL_CONFIG_COPY_OUT_SCALAR = bytes.fromhex(
    "4883ec30488d75a44889e7b92c000000fcf3a4"
    "448b8d6cffffff4d037708410fb7f941ffd6"
    "909090909090"
)

# Do not call userland libc while syscall 11 is executing this callback in
# ring 0. Even after removing explicit AVX, the imported memset/memcpy bodies
# may select SIMD implementations. These exact-length scalar loops preserve
# the 0x4000-byte clear and payload_size-byte copy without leaving the callback.
KERNEL_PAYLOAD_ZERO_OFFSET = 0x4217
KERNEL_PAYLOAD_ZERO = bytes.fromhex("31f64c89f7ba00400000ff15a15d0700")
KERNEL_PAYLOAD_ZERO_SCALAR = bytes.fromhex("4c89f731c0b900400000fcf3aa909090")
KERNEL_PAYLOAD_COPY_OFFSET = 0x4227
KERNEL_PAYLOAD_COPY = bytes.fromhex("488b9578ffffff4c89fe4c89f7ff15865d0700")
KERNEL_PAYLOAD_COPY_SCALAR = bytes.fromhex(
    "488b8d78ffffff4c89fe4c89f7fcf3a4909090"
)
KERNEL_LIBC_PATCHES = (
    (
        KERNEL_PAYLOAD_ZERO_OFFSET,
        KERNEL_PAYLOAD_ZERO,
        KERNEL_PAYLOAD_ZERO_SCALAR,
        ("mov", "xor", "mov", "cld", "rep stosb", "nop", "nop", "nop"),
    ),
    (
        KERNEL_PAYLOAD_COPY_OFFSET,
        KERNEL_PAYLOAD_COPY,
        KERNEL_PAYLOAD_COPY_SCALAR,
        ("mov", "mov", "mov", "cld", "rep movsb", "nop", "nop", "nop"),
    ),
)
KERNEL_LIBC_CHANGED_OFFSETS = frozenset(
    offset + index
    for offset, old_bytes, new_bytes, _ in KERNEL_LIBC_PATCHES
    for index, (old_byte, new_byte) in enumerate(zip(old_bytes, new_bytes))
    if old_byte != new_byte
)

# Remove the same compiler-generated vector copy from the user-side wrapper
# immediately before syscall 11. This constructs the identical payload-info
# object on the existing 0x48-byte stack frame, then calls the same callback
# through the same kexec wrapper.
USER_CONFIG_WRAPPER_OFFSET = 0x42FF
USER_CONFIG_WRAPPER = bytes.fromhex(
    "c5fe6f03c5fa6f4b1c668904244889e6488d054a770000"
    "488d3dd1f6ffff488944243048c744243808800000"
    "c5fe7f442404c5fa7f4c2420e8f2220000"
)
USER_CONFIG_WRAPPER_SCALAR = bytes.fromhex(
    "668904244889de488d7c2404b92c000000fcf3a4"
    "488d0546770000488944243048c744243808800000"
    "4889e6488d3dbcf6ffffe8f72200009090909090"
)

# The 14.02 source archive copied its userland process-patch RVAs from 14.00.
# Skip that block and plugin syscall installation while retaining the FSELF and
# FPKG kernel hooks that execute immediately before these branches.
INNER_USERLAND_PATCH_GATE_OFFSET = 0xBD8E
INNER_USERLAND_PATCH_GATE = bytes.fromhex("7505")
INNER_USERLAND_PATCH_BYPASS = bytes.fromhex("eb05")
INNER_PLUGIN_HOOK_GATE_OFFSET = 0xBD9C
INNER_PLUGIN_HOOK_GATE = bytes.fromhex("7427")
INNER_PLUGIN_HOOK_BYPASS = bytes.fromhex("eb27")

# The 14.02 callers keep their SELF context in registers rather than at the
# 14.00-derived caller frame slot used by these two mailbox hooks. Recover it
# from the live R14/R15 values saved by each hook's own prologue.
FSELF_SEGMENT_CONTEXT_OFFSET = 0xD686
FSELF_SEGMENT_CONTEXT = bytes.fromhex("488b78f8")
FSELF_SEGMENT_CONTEXT_FIX = bytes.fromhex("4c89f790")
FSELF_BLOCK_CONTEXT_OFFSET = 0xD8AA
FSELF_BLOCK_CONTEXT = bytes.fromhex("488b78f8")
FSELF_BLOCK_CONTEXT_FIX = bytes.fromhex("488b7df8")

# Use the existing in-memory default initializer without touching /data/hen,
# and change its defaults so every non-core installer/plugin option is off.
SAFE_DEFAULT_PATCHES = (
    (0x7C6, "disable exploit-fix helper by default", bytes.fromhex("01"), bytes.fromhex("00")),
    (0x7CE, "disable ASLR helper by default", bytes.fromhex("01"), bytes.fromhex("00")),
    (0x7D8, "zero mmap, update-blocker, PRX and plugin defaults", bytes.fromhex("02"), bytes.fromhex("03")),
)
CONFIG_INIT_CALL_OFFSET = 0x468C
CONFIG_INIT_CALL = bytes.fromhex("e820caffff")
CONFIG_DEFAULTS_CALL = bytes.fromhex("e81ec1ffff")
CONFIG_DEFAULTS_TARGET = 0x7AF

# The first-run config refresh is cosmetic after init_config has already
# populated the in-memory defaults. Skip its notification and five-second
# sleep. The config remains loaded, so this does not leave the structure
# uninitialised.
CONFIG_REFRESH_GATE_OFFSET = 0x46BB
CONFIG_REFRESH_GATE = bytes.fromhex("0f842e040000")
CONFIG_REFRESH_BYPASS = bytes.fromhex("e92f04000090")
CONFIG_REFRESH_TARGET = 0x4AEF

# These installer helpers are optional and the linked payload SDK has no
# 14.02 entries for mmap or ASLR. Skip the entire optional block, including
# exploit-fix, update-blocker and NoBD helpers, before entering the real HEN
# kernel payload at 0x4f0e.
OUTER_OPTIONAL_BLOCK_OFFSET = 0x4AEF
OUTER_OPTIONAL_BLOCK = bytes.fromhex("837c242800")
OUTER_OPTIONAL_BYPASS = bytes.fromhex("e91a040000")
OUTER_OPTIONAL_TARGET = 0x4F0E

# Wrap the outer install_payload call with two versioned /user/temp markers.
# If WebProcess is replaced during the handoff, the reloaded host can report
# whether the wrapper was entered and whether it returned. The trampoline lives
# in the optional-helper block that is bypassed above; it does not touch kernel
# text or alter the install_payload ABI.
OUTER_STAGE_CALL_OFFSET = 0x4F13
OUTER_STAGE_CALL = bytes.fromhex("e8d0f3ffff")
OUTER_STAGE_CALL_PATCH = bytes.fromhex("e868fcffff")
OUTER_STAGE_TRAMPOLINE_OFFSET = 0x4B80
OUTER_STAGE_TRAMPOLINE = bytes.fromhex(
    "550000be00020000f3ab4889efff15b553070031c9"
    "bf590200004189c44889ea31c0be07"
)
OUTER_STAGE_TRAMPOLINE_PATCH = bytes.fromhex(
    "57488d3d38000000e862180000488b3c24e852f7ffff"
    "488d3d43000000e84d1800005fc3"
)
OUTER_STAGE_PRE_OFFSET = 0x4BC0
OUTER_STAGE_PRE = bytes.fromhex("0031c0e87bf7ffff837c242c000f84c7000000488b")
OUTER_STAGE_PRE_PATCH = b"/user/temp/h14r9.pre\0"
OUTER_STAGE_POST_OFFSET = 0x4BE0
OUTER_STAGE_POST = bytes.fromhex("ac245003000041b9a00000004c8d0573f00000488d15")
OUTER_STAGE_POST_PATCH = b"/user/temp/h14r9.post\0"
OUTER_STAGE_PATCHES = (
    (OUTER_STAGE_CALL_OFFSET, OUTER_STAGE_CALL, OUTER_STAGE_CALL_PATCH),
    (
        OUTER_STAGE_TRAMPOLINE_OFFSET,
        OUTER_STAGE_TRAMPOLINE,
        OUTER_STAGE_TRAMPOLINE_PATCH,
    ),
    (OUTER_STAGE_PRE_OFFSET, OUTER_STAGE_PRE, OUTER_STAGE_PRE_PATCH),
    (OUTER_STAGE_POST_OFFSET, OUTER_STAGE_POST, OUTER_STAGE_POST_PATCH),
)
OUTER_STAGE_CHANGED_OFFSETS = frozenset(
    offset + index
    for offset, old_bytes, new_bytes in OUTER_STAGE_PATCHES
    for index, (old_byte, new_byte) in enumerate(zip(old_bytes, new_bytes))
    if old_byte != new_byte
)

# Plugin loading is already disabled below. Avoid writing the unused PRX
# bundle to /data/hen as well; the core FSELF/FPKG hooks do not need it.
PRX_UPLOAD_GATE_OFFSET = 0x52DA
PRX_UPLOAD_GATE = bytes.fromhex("0f84c5000000")
PRX_UPLOAD_BYPASS = bytes.fromhex("e9c600000090")
PRX_UPLOAD_TARGET = 0x53A5

# These outer changes remove the optional ShellCore code-cave/plugin-loader
# write and the following sleeps/process kills that restart PartyDaemon and
# SceShellUI. The core HEN installer and Welcome notification remain.
PLUGIN_LOADER_CALL_OFFSET = 0x53AC
PLUGIN_LOADER_CALL = bytes.fromhex("e817070000")
PLUGIN_LOADER_BYPASS = bytes.fromhex("9090909090")
UI_RESTART_BLOCK_OFFSET = 0x5519
UI_RESTART_BLOCK = bytes.fromhex("4585f60f8467010000")
UI_RESTART_BYPASS = bytes.fromhex("e99601000090909090")
MAIN_EPILOGUE_OFFSET = 0x56B4


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


def verify_epilogue_jump(image: bytes | bytearray) -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(
        decoder.disasm(
            bytes(image[UI_RESTART_BLOCK_OFFSET : UI_RESTART_BLOCK_OFFSET + 5]),
            UI_RESTART_BLOCK_OFFSET,
        )
    )
    if len(instructions) != 1 or instructions[0].size != 5:
        raise ValueError("UI restart bypass is not exactly one instruction")
    instruction = instructions[0]
    if (
        instruction.mnemonic != "jmp"
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
        or instruction.operands[0].imm != MAIN_EPILOGUE_OFFSET
    ):
        raise ValueError(
            "UI restart bypass does not jump to the main epilogue: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )


def verify_short_jump(image: bytes | bytearray, offset: int, target: int) -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes(image[offset : offset + 2]), offset))
    if len(instructions) != 1 or instructions[0].size != 2:
        raise ValueError(f"0x{offset:x} is not exactly one short instruction")
    instruction = instructions[0]
    if (
        instruction.mnemonic != "jmp"
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
        or instruction.operands[0].imm != target
    ):
        raise ValueError(
            f"short jump at 0x{offset:x} does not target 0x{target:x}: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )


def verify_near_jump(image: bytes | bytearray, offset: int, target: int) -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes(image[offset : offset + 5]), offset))
    if len(instructions) != 1 or instructions[0].size != 5:
        raise ValueError(f"0x{offset:x} is not exactly one near jump")
    instruction = instructions[0]
    if (
        instruction.mnemonic != "jmp"
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
        or instruction.operands[0].imm != target
    ):
        raise ValueError(
            f"near jump at 0x{offset:x} does not target 0x{target:x}: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )


def verify_near_call(image: bytes | bytearray, offset: int, target: int) -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes(image[offset : offset + 5]), offset))
    if len(instructions) != 1 or instructions[0].size != 5:
        raise ValueError(f"0x{offset:x} is not exactly one near call")
    instruction = instructions[0]
    if (
        instruction.mnemonic != "call"
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
        or instruction.operands[0].imm != target
    ):
        raise ValueError(
            f"near call at 0x{offset:x} does not target 0x{target:x}: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )


def verify_scalar_kernel_copy(
    image: bytes | bytearray,
    offset: int,
    expected: bytes,
    required_mnemonics: tuple[str, ...],
) -> None:
    actual = bytes(image[offset : offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"scalar kernel copy at 0x{offset:x} differs: "
            f"expected {expected.hex()}, got {actual.hex()}"
        )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(decoder.disasm(actual, offset))
    if sum(instruction.size for instruction in instructions) != len(expected):
        raise ValueError(f"scalar kernel copy at 0x{offset:x} does not decode fully")
    mnemonics = tuple(instruction.mnemonic for instruction in instructions)
    if mnemonics[: len(required_mnemonics)] != required_mnemonics:
        raise ValueError(
            f"scalar kernel copy at 0x{offset:x} decoded unexpectedly: {mnemonics!r}"
        )
    if any(instruction.mnemonic.startswith("v") for instruction in instructions):
        raise ValueError(f"vector instruction remains at 0x{offset:x}")


def verify_outer_stage_trampoline(image: bytes | bytearray) -> None:
    actual = bytes(
        image[
            OUTER_STAGE_TRAMPOLINE_OFFSET :
            OUTER_STAGE_TRAMPOLINE_OFFSET + len(OUTER_STAGE_TRAMPOLINE_PATCH)
        ]
    )
    if actual != OUTER_STAGE_TRAMPOLINE_PATCH:
        raise ValueError("outer install-payload stage trampoline differs")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(decoder.disasm(actual, OUTER_STAGE_TRAMPOLINE_OFFSET))
    if sum(instruction.size for instruction in instructions) != len(actual):
        raise ValueError("outer install-payload stage trampoline does not decode fully")
    if tuple(instruction.mnemonic for instruction in instructions) != (
        "push", "lea", "call", "mov", "call", "lea", "call", "pop", "ret",
    ):
        raise ValueError("outer install-payload stage trampoline decoded unexpectedly")
    verify_near_call(image, OUTER_STAGE_CALL_OFFSET, OUTER_STAGE_TRAMPOLINE_OFFSET)
    verify_near_call(image, 0x4B88, 0x63EF)
    verify_near_call(image, 0x4B91, 0x42E8)
    verify_near_call(image, 0x4B9D, 0x63EF)
    if bytes(image[OUTER_STAGE_PRE_OFFSET : OUTER_STAGE_PRE_OFFSET + 21]) != (
        OUTER_STAGE_PRE_PATCH
    ):
        raise ValueError("outer install-payload pre marker path differs")
    if bytes(image[OUTER_STAGE_POST_OFFSET : OUTER_STAGE_POST_OFFSET + 22]) != (
        OUTER_STAGE_POST_PATCH
    ):
        raise ValueError("outer install-payload post marker path differs")


def patch_image(original: bytes) -> tuple[bytes, list[dict[str, object]]]:
    if len(original) != INPUT_SIZE or sha256(original) != INPUT_SHA256:
        raise ValueError("input is not the exact published Akatsuki debug.bin")
    if original[0] != 0xE9:
        raise ValueError("raw payload entry header is missing")
    observed = [i for i in range(len(original)) if original.startswith(OLD_INSTRUCTION, i)]
    if observed != list(EXPECTED_OCCURRENCES):
        raise ValueError(f"SETLOGIN LEA occurrence set differs: {observed!r}")
    verify_lea(original, EXPECTED_OCCURRENCES[1], OLD_INSTRUCTION, OLD_LEA_DISP)
    for offset, label, expected in PRESERVED_TABLE_VALUES:
        actual = struct.unpack_from("<I", original, offset)[0]
        if actual != expected:
            raise ValueError(
                f"preserved {label} at 0x{offset:x} differs: "
                f"expected 0x{expected:08x}, got 0x{actual:08x}"
            )

    changed = bytearray(original)
    manifest_patches: list[dict[str, object]] = []

    actual_user_wrapper = bytes(
        original[
            USER_CONFIG_WRAPPER_OFFSET :
            USER_CONFIG_WRAPPER_OFFSET + len(USER_CONFIG_WRAPPER)
        ]
    )
    if actual_user_wrapper != USER_CONFIG_WRAPPER:
        raise ValueError(
            f"user install-payload wrapper differs at 0x{USER_CONFIG_WRAPPER_OFFSET:x}: "
            f"expected {USER_CONFIG_WRAPPER.hex()}, got {actual_user_wrapper.hex()}"
        )
    changed[
        USER_CONFIG_WRAPPER_OFFSET :
        USER_CONFIG_WRAPPER_OFFSET + len(USER_CONFIG_WRAPPER)
    ] = USER_CONFIG_WRAPPER_SCALAR
    verify_scalar_kernel_copy(
        changed,
        USER_CONFIG_WRAPPER_OFFSET,
        USER_CONFIG_WRAPPER_SCALAR,
        (
            "mov", "mov", "lea", "mov", "cld", "rep movsb", "lea", "mov",
            "mov", "mov", "lea", "call",
        ),
    )
    manifest_patches.append(
        {
            "label": "replace user install-payload AVX copy with scalar copy",
            "kind": "x86_64_userland_scalar_copy",
            "file_offset": f"0x{USER_CONFIG_WRAPPER_OFFSET:x}",
            "length": len(USER_CONFIG_WRAPPER_SCALAR),
            "old_hex": USER_CONFIG_WRAPPER.hex(),
            "new_hex": USER_CONFIG_WRAPPER_SCALAR.hex(),
            "copy_size": 44,
            "reason": "remove the final vector operations from the install-payload path",
        }
    )

    for offset, old_bytes, new_bytes in OUTER_STAGE_PATCHES:
        if len(old_bytes) != len(new_bytes):
            raise ValueError("outer stage marker patch changes the exact-image size")
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"outer stage marker source differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
    verify_outer_stage_trampoline(changed)
    manifest_patches.append(
        {
            "label": "record outer install-payload entry and return",
            "kind": "x86_64_userland_stage_trampoline",
            "call_file_offset": f"0x{OUTER_STAGE_CALL_OFFSET:x}",
            "trampoline_file_offset": f"0x{OUTER_STAGE_TRAMPOLINE_OFFSET:x}",
            "pre_marker": OUTER_STAGE_PRE_PATCH[:-1].decode("ascii"),
            "post_marker": OUTER_STAGE_POST_PATCH[:-1].decode("ascii"),
            "reason": (
                "make a WebProcess replacement report whether install_payload "
                "was entered and whether it returned"
            ),
        }
    )

    scalar_kernel_copies = (
        (
            KERNEL_CONFIG_COPY_IN_OFFSET,
            "replace ring-0 AVX configuration capture with scalar copy",
            KERNEL_CONFIG_COPY_IN,
            KERNEL_CONFIG_COPY_IN_SCALAR,
            ("mov", "lea", "lea", "mov", "cld", "rep movsb", "cmp"),
        ),
        (
            KERNEL_CONFIG_COPY_OUT_OFFSET,
            "replace ring-0 AVX payload argument copy with scalar copy",
            KERNEL_CONFIG_COPY_OUT,
            KERNEL_CONFIG_COPY_OUT_SCALAR,
            (
                "sub", "lea", "mov", "mov", "cld", "rep movsb", "mov",
                "add", "movzx", "call",
            ),
        ),
    )
    for offset, label, old_bytes, new_bytes, mnemonics in scalar_kernel_copies:
        if len(old_bytes) != len(new_bytes):
            raise ValueError(f"{label} changes the exact-image size")
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        verify_scalar_kernel_copy(changed, offset, new_bytes, mnemonics)
        manifest_patches.append(
            {
                "label": label,
                "kind": "x86_64_ring0_scalar_copy",
                "file_offset": f"0x{offset:x}",
                "length": len(new_bytes),
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
                "copy_size": 44,
                "reason": "avoid AVX use in syscall-11 kernel context without fpu_kern_enter",
            }
        )

    for offset, old_bytes, new_bytes, mnemonics in KERNEL_LIBC_PATCHES:
        if len(old_bytes) != len(new_bytes):
            raise ValueError("scalar kernel buffer operation changes the exact-image size")
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"kernel libc buffer operation differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        verify_scalar_kernel_copy(changed, offset, new_bytes, mnemonics)
        manifest_patches.append(
            {
                "label": (
                    "replace ring-0 imported memset with scalar clear"
                    if offset == KERNEL_PAYLOAD_ZERO_OFFSET
                    else "replace ring-0 imported memcpy with scalar copy"
                ),
                "kind": "x86_64_ring0_scalar_buffer_operation",
                "file_offset": f"0x{offset:x}",
                "length": len(new_bytes),
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
                "reason": "avoid calling userland libc from the syscall-11 kernel callback",
            }
        )

    for offset, label in PATCHES:
        verify_lea(original, offset, OLD_INSTRUCTION, OLD_LEA_DISP)
        changed[offset : offset + len(OLD_INSTRUCTION)] = NEW_INSTRUCTION
        verify_lea(changed, offset, NEW_INSTRUCTION, NEW_LEA_DISP)
        manifest_patches.append(
            {
                "label": label,
                "kind": "x86_64_lea_displacement",
                "instruction_file_offset": f"0x{offset:x}",
                "displacement_file_offset": f"0x{offset + 3:x}",
                "old_instruction_hex": OLD_INSTRUCTION.hex(),
                "new_instruction_hex": NEW_INSTRUCTION.hex(),
                "base": "IA32_LSTAR",
                "base_rva": f"0x{LSTAR_RVA:x}",
                "old_displacement": f"0x{OLD_LEA_DISP:x}",
                "new_displacement": f"0x{NEW_LEA_DISP:x}",
                "old_target_rva": f"0x{OLD_SETLOGIN_RVA:x}",
                "new_target_rva": f"0x{NEW_SETLOGIN_RVA:x}",
            }
        )

    for offset, label, old_rva, new_rva in TABLE_PATCHES:
        actual = struct.unpack_from("<I", original, offset)[0]
        if actual != old_rva:
            raise ValueError(
                f"{label} at 0x{offset:x} differs: "
                f"expected 0x{old_rva:08x}, got 0x{actual:08x}"
            )
        struct.pack_into("<I", changed, offset, new_rva)
        if struct.unpack_from("<I", changed, offset)[0] != new_rva:
            raise ValueError(f"failed to patch {label} at 0x{offset:x}")
        manifest_patches.append(
            {
                "label": label,
                "kind": "embedded_fw_offsets_u32",
                "file_offset": f"0x{offset:x}",
                "old_rva": f"0x{old_rva:08x}",
                "new_rva": f"0x{new_rva:08x}",
                "old_hex_le": struct.pack("<I", old_rva).hex(),
                "new_hex_le": struct.pack("<I", new_rva).hex(),
            }
        )

    for offset, label, old_bytes, new_bytes in SAFE_DEFAULT_PATCHES:
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        manifest_patches.append(
            {
                "label": label,
                "kind": "safe_in_memory_default",
                "file_offset": f"0x{offset:x}",
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
            }
        )

    actual_config_call = bytes(
        original[
            CONFIG_INIT_CALL_OFFSET : CONFIG_INIT_CALL_OFFSET + len(CONFIG_INIT_CALL)
        ]
    )
    if actual_config_call != CONFIG_INIT_CALL:
        raise ValueError(
            f"config init call differs at 0x{CONFIG_INIT_CALL_OFFSET:x}: "
            f"expected {CONFIG_INIT_CALL.hex()}, got {actual_config_call.hex()}"
        )
    changed[
        CONFIG_INIT_CALL_OFFSET : CONFIG_INIT_CALL_OFFSET + len(CONFIG_INIT_CALL)
    ] = CONFIG_DEFAULTS_CALL
    verify_near_call(changed, CONFIG_INIT_CALL_OFFSET, CONFIG_DEFAULTS_TARGET)
    manifest_patches.append(
        {
            "label": "use safe in-memory HEN defaults without HDD config I/O",
            "kind": "x86_64_near_call",
            "file_offset": f"0x{CONFIG_INIT_CALL_OFFSET:x}",
            "target_file_offset": f"0x{CONFIG_DEFAULTS_TARGET:x}",
            "old_hex": CONFIG_INIT_CALL.hex(),
            "new_hex": CONFIG_DEFAULTS_CALL.hex(),
        }
    )

    inner_branches = (
        (
            INNER_USERLAND_PATCH_GATE_OFFSET,
            "skip unported 14.00-derived userland process patches",
            INNER_USERLAND_PATCH_GATE,
            INNER_USERLAND_PATCH_BYPASS,
            0xBD95,
        ),
        (
            INNER_PLUGIN_HOOK_GATE_OFFSET,
            "skip plugin syscall hooks",
            INNER_PLUGIN_HOOK_GATE,
            INNER_PLUGIN_HOOK_BYPASS,
            0xBDC5,
        ),
    )
    for offset, label, old_bytes, new_bytes, target in inner_branches:
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} gate differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        verify_short_jump(changed, offset, target)
        manifest_patches.append(
            {
                "label": label,
                "kind": "x86_64_short_jump",
                "file_offset": f"0x{offset:x}",
                "target_file_offset": f"0x{target:x}",
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
            }
        )

    outer_bypasses = (
        (
            CONFIG_REFRESH_GATE_OFFSET,
            "skip first-run config notification and delay",
            CONFIG_REFRESH_GATE,
            CONFIG_REFRESH_BYPASS,
            CONFIG_REFRESH_TARGET,
        ),
        (
            OUTER_OPTIONAL_BLOCK_OFFSET,
            "skip unsupported optional 14.02 installer helpers",
            OUTER_OPTIONAL_BLOCK,
            OUTER_OPTIONAL_BYPASS,
            OUTER_OPTIONAL_TARGET,
        ),
        (
            PRX_UPLOAD_GATE_OFFSET,
            "skip unused plugin PRX upload",
            PRX_UPLOAD_GATE,
            PRX_UPLOAD_BYPASS,
            PRX_UPLOAD_TARGET,
        ),
    )
    for offset, label, old_bytes, new_bytes, target in outer_bypasses:
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        verify_near_jump(changed, offset, target)
        manifest_patches.append(
            {
                "label": label,
                "kind": "x86_64_near_jump",
                "file_offset": f"0x{offset:x}",
                "target_file_offset": f"0x{target:x}",
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
            }
        )

    fself_context_fixes = (
        (
            FSELF_SEGMENT_CONTEXT_OFFSET,
            "recover 14.02 SELF segment context from caller R14",
            FSELF_SEGMENT_CONTEXT,
            FSELF_SEGMENT_CONTEXT_FIX,
            "mov rdi, r14; nop",
        ),
        (
            FSELF_BLOCK_CONTEXT_OFFSET,
            "recover 14.02 SELF block context from saved caller R15",
            FSELF_BLOCK_CONTEXT,
            FSELF_BLOCK_CONTEXT_FIX,
            "mov rdi, qword ptr [rbp - 8]",
        ),
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for offset, label, old_bytes, new_bytes, expected_asm in fself_context_fixes:
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
        decoded = list(decoder.disasm(new_bytes, offset))
        rendered = "; ".join(
            instruction.mnemonic
            + (" " + instruction.op_str if instruction.op_str else "")
            for instruction in decoded
        )
        if sum(instruction.size for instruction in decoded) != len(new_bytes):
            raise ValueError(f"{label} does not decode completely")
        if rendered != expected_asm:
            raise ValueError(
                f"{label} decoded unexpectedly: {rendered!r}, "
                f"expected {expected_asm!r}"
            )
        manifest_patches.append(
            {
                "label": label,
                "kind": "x86_64_context_recovery",
                "file_offset": f"0x{offset:x}",
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
                "new_assembly": rendered,
            }
        )

    actual_call = bytes(
        original[
            PLUGIN_LOADER_CALL_OFFSET : PLUGIN_LOADER_CALL_OFFSET
            + len(PLUGIN_LOADER_CALL)
        ]
    )
    if actual_call != PLUGIN_LOADER_CALL:
        raise ValueError(
            "ShellCore plugin-loader call differs at "
            f"0x{PLUGIN_LOADER_CALL_OFFSET:x}: {actual_call.hex()}"
        )
    changed[
        PLUGIN_LOADER_CALL_OFFSET : PLUGIN_LOADER_CALL_OFFSET
        + len(PLUGIN_LOADER_CALL)
    ] = PLUGIN_LOADER_BYPASS
    manifest_patches.append(
        {
            "label": "skip optional ShellCore plugin-loader injection",
            "kind": "x86_64_nop_call",
            "file_offset": f"0x{PLUGIN_LOADER_CALL_OFFSET:x}",
            "old_hex": PLUGIN_LOADER_CALL.hex(),
            "new_hex": PLUGIN_LOADER_BYPASS.hex(),
        }
    )

    actual_restart = bytes(
        original[
            UI_RESTART_BLOCK_OFFSET : UI_RESTART_BLOCK_OFFSET
            + len(UI_RESTART_BLOCK)
        ]
    )
    if actual_restart != UI_RESTART_BLOCK:
        raise ValueError(
            "ShellUI restart gate differs at "
            f"0x{UI_RESTART_BLOCK_OFFSET:x}: {actual_restart.hex()}"
        )
    changed[
        UI_RESTART_BLOCK_OFFSET : UI_RESTART_BLOCK_OFFSET
        + len(UI_RESTART_BLOCK)
    ] = UI_RESTART_BYPASS
    verify_epilogue_jump(changed)
    manifest_patches.append(
        {
            "label": "return after HEN Welcome instead of restarting ShellUI",
            "kind": "x86_64_epilogue_jump",
            "file_offset": f"0x{UI_RESTART_BLOCK_OFFSET:x}",
            "target_file_offset": f"0x{MAIN_EPILOGUE_OFFSET:x}",
            "old_hex": UI_RESTART_BLOCK.hex(),
            "new_hex": UI_RESTART_BYPASS.hex(),
        }
    )

    result = bytes(changed)
    verify_lea(result, EXPECTED_OCCURRENCES[1], OLD_INSTRUCTION, OLD_LEA_DISP)
    for offset, label, expected in PRESERVED_TABLE_VALUES:
        actual = struct.unpack_from("<I", result, offset)[0]
        if actual != expected:
            raise ValueError(f"preserved value changed for {label}")
    if len(result) != INPUT_SIZE or sha256(result) != OUTPUT_SHA256:
        raise ValueError("patched output does not match its pinned SHA-256")
    expected_changed = {
        0x7C6, 0x7CE, 0x7D8,
        0x18D6, 0x18D7,
        *range(0x3A09, 0x3A28),
        *KERNEL_LIBC_CHANGED_OFFSETS,
        *range(0x4279, 0x42A4),
        *range(0x42FF, 0x430A),
        *range(0x430B, 0x433C),
        *OUTER_STAGE_CHANGED_OFFSETS,
        0x468D, 0x468E,
        0x46BB, 0x46BC, 0x46BD, 0x46BE, 0x46C0,
        0x4AEF, 0x4AF0, 0x4AF1, 0x4AF2,
        0x52DA, 0x52DB, 0x52DC, 0x52DF,
        *range(0x53AC, 0x53B1),
        *range(0x5519, 0x5522),
        0xBD8E, 0xBD9C,
        0xD686, 0xD687, 0xD688, 0xD689, 0xD8AC,
        0x10C6C, 0x10C6D, 0x10C84,
    }
    actual_changed = {i for i, (a, b) in enumerate(zip(original, result)) if a != b}
    if actual_changed != expected_changed:
        raise ValueError(f"unexpected changed byte positions: {sorted(actual_changed)!r}")
    return result, manifest_patches


def write_or_verify(path: Path, data: bytes, replace: bool) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if replace and path.exists():
        if path.read_bytes() == data:
            return "verified-existing"
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
        if path.read_bytes() != data:
            raise ValueError(f"replacement readback failed for {path}")
        return "replaced"
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
    parser.add_argument(
        "--replace",
        action="store_true",
        help="atomically replace only the selected generated output and manifest",
    )
    args = parser.parse_args()
    if args.check_only and args.replace:
        parser.error("--check-only and --replace cannot be combined")
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    manifest_path = (args.manifest or output_path.with_suffix(".manifest.json")).resolve()
    if len({input_path, output_path, manifest_path}) != 3:
        raise ValueError("input, output, and manifest must use distinct paths")

    original = input_path.read_bytes()
    patched, patches = patch_image(original)
    manifest = {
        "purpose": (
            "offline correction of three proven 14.02 payload offsets and a "
            "core-HEN launch that removes AVX from the full install-payload "
            "path, replaces ring-0 imported libc buffer calls, records the "
            "outer handoff stage, and avoids unsupported optional and unported "
            "userland/plugin paths"
        ),
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "hen_source_archive": {
            "path": HEN_SOURCE_ARCHIVE,
            "sha256": HEN_SOURCE_ARCHIVE_SHA256,
            "unsafe_1402_table": "kpayload/source/offsets/1402.c",
            "gated_callsite": "kpayload/source/patch.c",
        },
        "input": {"path": input_path.name, "size": len(original), "sha256": INPUT_SHA256},
        "output": {"path": output_path.name, "size": len(patched), "sha256": OUTPUT_SHA256},
        "decoder": {"name": "Capstone", "version": capstone_version, "architecture": "x86_64"},
        "patches": patches,
        "changed_byte_offsets": [f"0x{offset:x}" for offset in sorted(
            {
                0x7C6, 0x7CE, 0x7D8,
                0x18D6, 0x18D7,
                *range(0x3A09, 0x3A28),
                *KERNEL_LIBC_CHANGED_OFFSETS,
                *range(0x4279, 0x42A4),
                *range(0x42FF, 0x430A),
                *range(0x430B, 0x433C),
                *OUTER_STAGE_CHANGED_OFFSETS,
                0x468D, 0x468E,
                0x46BB, 0x46BC, 0x46BD, 0x46BE, 0x46C0,
                0x4AEF, 0x4AF0, 0x4AF1, 0x4AF2,
                0x52DA, 0x52DB, 0x52DC, 0x52DF,
                *range(0x53AC, 0x53B1),
                *range(0x5519, 0x5522),
                0xBD8E, 0xBD9C,
                0xD686, 0xD687, 0xD688, 0xD689, 0xD8AC,
                0x10C6C, 0x10C6D, 0x10C84,
            }
        )],
        "preserved_1400_instruction_file_offset": "0x25d2",
        "preserved_table_values": [
            {
                "file_offset": f"0x{offset:x}",
                "label": label,
                "rva": f"0x{value:08x}",
            }
            for offset, label, value in PRESERVED_TABLE_VALUES
        ],
        "scope_limit": (
            "The SETLOGIN target, sceSblACMgrGetPathId, and "
            "RsaesPkcs1v15Dec2048CRT are corrected. The two 14.02 FSELF "
            "mailbox hooks recover their context from the caller's live "
            "registers. Compiler-emitted AVX configuration copies in the "
            "user wrapper and syscall-11 kernel callback are replaced with "
            "exact 44-byte scalar copies. Jailbreak plus FSELF/FPKG kernel "
            "hooks remain enabled. The callback's imported memset and memcpy "
            "calls are replaced with exact scalar clear/copy loops. "
            "Versioned userland markers bracket the outer install_payload call "
            "without writing diagnostic state into kernel text. "
            "HDD config I/O, unsupported optional installer helpers, unverified "
            "process/UI patches, plugin hooks and upload, and the "
            "ShellUI/PartyDaemon restart are skipped; hardware validation "
            "remains required."
        ),
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if args.check_only:
        sys.stdout.buffer.write(manifest_bytes)
        return
    output_action = write_or_verify(output_path, patched, args.replace)
    manifest_action = write_or_verify(manifest_path, manifest_bytes, args.replace)
    print(f"{output_action}: {output_path} ({OUTPUT_SHA256})")
    print(f"{manifest_action}: {manifest_path}")


if __name__ == "__main__":
    main()
