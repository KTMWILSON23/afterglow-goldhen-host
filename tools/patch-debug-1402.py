#!/usr/bin/env python3
"""Patch the published Akatsuki debug.bin for a core 14.02 HEN launch.

This is an offline, exact-image byte patch. It corrects the SETLOGIN target
and two embedded kernel function addresses whose 14.02 counterparts were
verified against the decrypted kernel. It replaces compiler-emitted AVX
configuration copies in both the user wrapper and the syscall-11 kernel
callback, replaces the callback's imported libc buffer operations with
scalar loops, clears the embedded payload's full file-plus-BSS span, removes
its diagnostic kernel printf, and bounds the SCE_RELA lookup to the verified
14.02 PT_DYNAMIC span instead of scanning from the kernel base. This removes
vector/FPU and userland-library execution from the install-payload kernel path. It retains
the FSELF/FPKG kernel hooks, but
  enters the core installer directly and bypasses the redundant outer program,
  jailbreak/kernel-patch callbacks, unsupported
optional installer actions, the unported 14.00-derived userland patch table,
plugin hooks, optional ShellCore plugin-loader injection, and deliberate
ShellUI restart. It does not prove the remaining HEN runtime on hardware.
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
    X86_REG_EAX,
    X86_REG_RAX,
    X86_REG_R8,
    X86_REG_R15D,
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
OUTPUT_SHA256 = "1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239"
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
# a full 0x8200-byte file-plus-BSS clear and payload_size-byte copy without
# leaving the callback. The embedded payload is 0x8008 bytes and its NOBITS
# globals extend through offset 0x81f8, so the original one-page clear was too
# short for this build.
KERNEL_PAYLOAD_ZERO_OFFSET = 0x4217
KERNEL_PAYLOAD_ZERO = bytes.fromhex("31f64c89f7ba00400000ff15a15d0700")
KERNEL_PAYLOAD_ZERO_SCALAR = bytes.fromhex("4c89f731c0b900820000fcf3aa909090")
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

# kpayload_install_payload searches byte by byte for DT_SCE_RELA. The 14.02
# ELF program headers place PT_DYNAMIC at kernel-base + 0x00cfe890 with a
# 0x110-byte span. Each matching tag is followed by an unconditional qword
# read at tag+8, so the final safe 16-byte entry starts at RVA+0x100. The
# existing post-increment `cmp rax,r15; jb` loop therefore needs the exclusive
# stop RVA+0x101. The patch also replaces the following `xor eax,eax`, which
# would discard the verified start.
KERNEL_DYNAMIC_SCAN_OFFSET = 0x417D
KERNEL_DYNAMIC_SCAN = bytes.fromhex(
    "4d85c00f84240100004d85ff0f841b01000031c0"
)
KERNEL_DYNAMIC_SCAN_PATCH = bytes.fromhex(
    "b890e8cf00"       # mov eax, 0x00cfe890
    "41bf91e9cf00"     # mov r15d, 0x00cfe991 (exclusive entry-start stop)
    "4d85c0"           # test r8, r8 (preserve the source null guard)
    "0f8419010000"     # je 0x42aa (existing failure path)
)
KERNEL_DYNAMIC_RVA = 0x00CFE890
KERNEL_DYNAMIC_SIZE = 0x110
KERNEL_DYNAMIC_SCAN_STOP = KERNEL_DYNAMIC_RVA + KERNEL_DYNAMIC_SIZE - 15
KERNEL_DYNAMIC_SCAN_CHANGED_OFFSETS = frozenset(
    KERNEL_DYNAMIC_SCAN_OFFSET + index
    for index, (old_byte, new_byte) in enumerate(
        zip(KERNEL_DYNAMIC_SCAN, KERNEL_DYNAMIC_SCAN_PATCH)
    )
    if old_byte != new_byte
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

# The only call-capable operation before the two FSELF/FPKG hook writers is a
# diagnostic kernel printf. It is not required for HEN and can block when the
# retail console's kernel log path is unavailable, so remove only that call.
INNER_KERNEL_PRINTF_OFFSET = 0xBD77
INNER_KERNEL_PRINTF_CALL = bytes.fromhex("ff152b7e0000")
INNER_KERNEL_PRINTF_BYPASS = bytes.fromhex("90" * 6)

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
OUTER_STAGE_CALL_PATCH = OUTER_STAGE_CALL
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

# Afterglow has already installed the verified 14.02 host patches and changed
# this WebProcess to uid 0 before starting the HEN thread. Re-entering HEN's
# older generic jailbreak and installer patch callbacks is redundant. Jump
# over the jailbreak plus installed-marker check, then skip install_patches,
# while retaining firmware validation, safe config and the core payload.
OUTER_JAILBREAK_CALL_OFFSET = 0x452C
OUTER_JAILBREAK_CALL = bytes.fromhex("e8ff540000")
OUTER_JAILBREAK_BYPASS = bytes.fromhex("e956010000")
OUTER_INSTALL_PATCHES_CALL_OFFSET = 0x4682
OUTER_INSTALL_PATCHES_CALL = bytes.fromhex("e837fcffff")
OUTER_INSTALL_PATCHES_BYPASS = bytes.fromhex("9090909090")
OUTER_PREINSTALL_BYPASSES = (
    (
        OUTER_JAILBREAK_CALL_OFFSET,
        "jump over redundant jailbreak and installed-marker check",
        OUTER_JAILBREAK_CALL,
        OUTER_JAILBREAK_BYPASS,
        0x9A30,
    ),
    (
        OUTER_INSTALL_PATCHES_CALL_OFFSET,
        "skip redundant outer HEN kernel patch callback",
        OUTER_INSTALL_PATCHES_CALL,
        OUTER_INSTALL_PATCHES_BYPASS,
        0x42BE,
    ),
)
OUTER_PREINSTALL_CHANGED_OFFSETS = frozenset(
    offset + index
    for offset, _, old_bytes, new_bytes, _ in OUTER_PREINSTALL_BYPASSES
    for index, (old_byte, new_byte) in enumerate(zip(old_bytes, new_bytes))
    if old_byte != new_byte
)

# Once the safe defaults are built, jump directly to the core installer.
# This removes both file-existence checks and all marker-file I/O while still
# retaining initKernel, initLibc, firmware validation, and the known config.
OUTER_FAST_LANE_OFFSET = 0x4691
OUTER_FAST_LANE = bytes.fromhex("448b742444")
OUTER_FAST_LANE_PATCH = bytes.fromhex("e978080000")
OUTER_FAST_LANE_TARGET = 0x4F0E
OUTER_FAST_LANE_CHANGED_OFFSETS = frozenset(
    OUTER_FAST_LANE_OFFSET + index
    for index, (old_byte, new_byte) in enumerate(
        zip(OUTER_FAST_LANE, OUTER_FAST_LANE_PATCH)
    )
    if old_byte != new_byte
)

# The outer HEN program still terminates WebProcess shortly after its pthread
# starts. Enter a compact start routine in the already-skipped optional block:
# it builds the same 44-byte safe config, calls only install_payload, creates
# the completion marker only when that call returns zero, and exits the thread
# cleanly while preserving a nonzero installer result.
DIRECT_ENTRY_OFFSET = 0x0000
DIRECT_ENTRY = bytes.fromhex("e968430000")
DIRECT_ENTRY_PATCH = bytes.fromhex("e9fb4b0000")
DIRECT_ENTRY_OLD_TARGET = 0x436D
DIRECT_ENTRY_TARGET = 0x4C00
DIRECT_FIRMWARE_CALL_OFFSET = 0x42FA
DIRECT_FIRMWARE_CALL = bytes.fromhex("e89e550000")
DIRECT_FIRMWARE_PATCH = bytes.fromhex("66b87a0590")
DIRECT_FIRMWARE_OLD_TARGET = 0x989D
DIRECT_INSTALL_STUB_OFFSET = 0x4C00
DIRECT_INSTALL_STUB = bytes.fromhex(
    "004c89f94889efff153b53070031c9bf590200004189c44889ea31c0"
    "be07000000e80a5000008b3df04f070085ff780b4489e24889eee8d724"
)
DIRECT_INSTALL_STUB_PATCH = bytes.fromhex(
    "f30f1efa4883ec384889e731c0b90b000000fcf3abc60424034889e7"
    "e8c7f6ffff85c0750e488d3d28540000e8be17000031c04883c438c390"
)
DIRECT_ENTRY_PATCHES = (
    (DIRECT_ENTRY_OFFSET, DIRECT_ENTRY, DIRECT_ENTRY_PATCH),
    (DIRECT_FIRMWARE_CALL_OFFSET, DIRECT_FIRMWARE_CALL, DIRECT_FIRMWARE_PATCH),
    (DIRECT_INSTALL_STUB_OFFSET, DIRECT_INSTALL_STUB, DIRECT_INSTALL_STUB_PATCH),
)
DIRECT_ENTRY_CHANGED_OFFSETS = frozenset(
    offset + index
    for offset, old_bytes, new_bytes in DIRECT_ENTRY_PATCHES
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


def verify_short_conditional_jump(
    image: bytes | bytearray, offset: int, mnemonic: str, target: int
) -> None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes(image[offset : offset + 2]), offset))
    if len(instructions) != 1 or instructions[0].size != 2:
        raise ValueError(f"0x{offset:x} is not exactly one short instruction")
    instruction = instructions[0]
    if (
        instruction.mnemonic != mnemonic
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
        or instruction.operands[0].imm != target
    ):
        raise ValueError(
            f"short {mnemonic} at 0x{offset:x} does not target 0x{target:x}: "
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


def verify_kernel_dynamic_scan_bounds(image: bytes | bytearray) -> None:
    actual = bytes(
        image[
            KERNEL_DYNAMIC_SCAN_OFFSET :
            KERNEL_DYNAMIC_SCAN_OFFSET + len(KERNEL_DYNAMIC_SCAN_PATCH)
        ]
    )
    if actual != KERNEL_DYNAMIC_SCAN_PATCH:
        raise ValueError("14.02 PT_DYNAMIC scan-bounds patch differs")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(actual, KERNEL_DYNAMIC_SCAN_OFFSET))
    if sum(instruction.size for instruction in instructions) != len(actual):
        raise ValueError("14.02 PT_DYNAMIC scan-bounds patch does not decode fully")
    first = instructions[0]
    second = instructions[1]
    third = instructions[2]
    fourth = instructions[3]
    if (
        first.mnemonic != "mov"
        or len(first.operands) != 2
        or first.operands[0].type != X86_OP_REG
        or first.operands[0].reg != X86_REG_EAX
        or first.operands[1].type != X86_OP_IMM
        or first.operands[1].imm != KERNEL_DYNAMIC_RVA
        or second.mnemonic != "mov"
        or len(second.operands) != 2
        or second.operands[0].type != X86_OP_REG
        or second.operands[0].reg != X86_REG_R15D
        or second.operands[1].type != X86_OP_IMM
        or second.operands[1].imm != KERNEL_DYNAMIC_SCAN_STOP
        or third.mnemonic != "test"
        or len(third.operands) != 2
        or third.operands[0].type != X86_OP_REG
        or third.operands[0].reg != X86_REG_R8
        or third.operands[1].type != X86_OP_REG
        or third.operands[1].reg != X86_REG_R8
        or fourth.mnemonic != "je"
        or len(fourth.operands) != 1
        or fourth.operands[0].type != X86_OP_IMM
        or fourth.operands[0].imm != 0x42AA
    ):
        raise ValueError("14.02 PT_DYNAMIC scan-bounds patch decoded unexpectedly")


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
    verify_near_call(image, OUTER_STAGE_CALL_OFFSET, 0x42E8)
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


def verify_direct_install_entry(image: bytes | bytearray) -> None:
    verify_near_jump(image, DIRECT_ENTRY_OFFSET, DIRECT_ENTRY_TARGET)
    actual_firmware = bytes(
        image[
            DIRECT_FIRMWARE_CALL_OFFSET :
            DIRECT_FIRMWARE_CALL_OFFSET + len(DIRECT_FIRMWARE_PATCH)
        ]
    )
    if actual_firmware != DIRECT_FIRMWARE_PATCH:
        raise ValueError("direct installer firmware constant differs")
    actual = bytes(
        image[
            DIRECT_INSTALL_STUB_OFFSET :
            DIRECT_INSTALL_STUB_OFFSET + len(DIRECT_INSTALL_STUB_PATCH)
        ]
    )
    if actual != DIRECT_INSTALL_STUB_PATCH:
        raise ValueError("direct install-payload entry stub differs")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(decoder.disasm(actual, DIRECT_INSTALL_STUB_OFFSET))
    if sum(instruction.size for instruction in instructions) != len(actual):
        raise ValueError("direct install-payload entry stub does not decode fully")
    if tuple(instruction.mnemonic for instruction in instructions) != (
        "endbr64", "sub", "mov", "xor", "mov", "cld", "rep stosd",
        "mov", "mov", "call", "test", "jne", "lea", "call", "xor",
        "add", "ret", "nop",
    ):
        raise ValueError("direct install-payload entry stub decoded unexpectedly")
    verify_near_call(image, DIRECT_INSTALL_STUB_OFFSET + 0x1C, 0x42E8)
    verify_short_conditional_jump(
        image, DIRECT_INSTALL_STUB_OFFSET + 0x23, "jne", 0x4C33
    )
    verify_near_call(image, DIRECT_INSTALL_STUB_OFFSET + 0x2C, 0x63EF)
    if bytes(image[0xA054 : 0xA054 + 25]) != b"/user/temp/hen.installed\0":
        raise ValueError("direct installer completion-marker path differs")


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
            "label": "call install_payload directly without marker-file I/O",
            "kind": "x86_64_userland_direct_install_call",
            "call_file_offset": f"0x{OUTER_STAGE_CALL_OFFSET:x}",
            "target_file_offset": "0x42e8",
            "trampoline_file_offset": f"0x{OUTER_STAGE_TRAMPOLINE_OFFSET:x}",
            "pre_marker": OUTER_STAGE_PRE_PATCH[:-1].decode("ascii"),
            "post_marker": OUTER_STAGE_POST_PATCH[:-1].decode("ascii"),
            "reason": (
                "the diagnostic helper remains dormant in the skipped optional "
                "block; the live path avoids its pre/post file writes"
            ),
        }
    )

    for offset, label, old_bytes, new_bytes, target in OUTER_PREINSTALL_BYPASSES:
        if len(old_bytes) != len(new_bytes):
            raise ValueError(f"{label} changes the exact-image size")
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"{label} differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        verify_near_call(original, offset, target)
        changed[offset : offset + len(old_bytes)] = new_bytes
        manifest_patches.append(
            {
                "label": label,
                "kind": (
                    "x86_64_outer_fast_lane"
                    if offset == OUTER_JAILBREAK_CALL_OFFSET
                    else "x86_64_nop_call"
                ),
                "file_offset": f"0x{offset:x}",
                "old_target_file_offset": f"0x{target:x}",
                "old_hex": old_bytes.hex(),
                "new_hex": new_bytes.hex(),
                "reason": (
                    "Afterglow already installed the verified 14.02 kernel "
                    "patches and jailbroke the WebProcess; the first jump also "
                    "avoids the outer installed-marker file check"
                ),
            }
        )

    actual = bytes(
        original[
            OUTER_FAST_LANE_OFFSET :
            OUTER_FAST_LANE_OFFSET + len(OUTER_FAST_LANE)
        ]
    )
    if actual != OUTER_FAST_LANE:
        raise ValueError(
            f"outer fast-lane source differs at 0x{OUTER_FAST_LANE_OFFSET:x}: "
            f"expected {OUTER_FAST_LANE.hex()}, got {actual.hex()}"
        )
    changed[
        OUTER_FAST_LANE_OFFSET :
        OUTER_FAST_LANE_OFFSET + len(OUTER_FAST_LANE)
    ] = OUTER_FAST_LANE_PATCH
    verify_near_jump(changed, OUTER_JAILBREAK_CALL_OFFSET, 0x4687)
    verify_near_jump(changed, OUTER_FAST_LANE_OFFSET, OUTER_FAST_LANE_TARGET)
    manifest_patches.append(
        {
            "label": "jump from safe defaults directly to the core installer",
            "kind": "x86_64_outer_fast_lane",
            "file_offset": f"0x{OUTER_FAST_LANE_OFFSET:x}",
            "target_file_offset": f"0x{OUTER_FAST_LANE_TARGET:x}",
            "old_hex": OUTER_FAST_LANE.hex(),
            "new_hex": OUTER_FAST_LANE_PATCH.hex(),
            "reason": (
                "avoid dead config loads and the remaining HDD file check "
                "after the safe in-memory configuration is initialized"
            ),
        }
    )

    verify_near_jump(original, DIRECT_ENTRY_OFFSET, DIRECT_ENTRY_OLD_TARGET)
    verify_near_call(
        original, DIRECT_FIRMWARE_CALL_OFFSET, DIRECT_FIRMWARE_OLD_TARGET
    )
    for offset, old_bytes, new_bytes in DIRECT_ENTRY_PATCHES:
        if len(old_bytes) != len(new_bytes):
            raise ValueError("direct install entry patch changes the exact-image size")
        actual = bytes(original[offset : offset + len(old_bytes)])
        if actual != old_bytes:
            raise ValueError(
                f"direct install entry source differs at 0x{offset:x}: "
                f"expected {old_bytes.hex()}, got {actual.hex()}"
            )
        changed[offset : offset + len(old_bytes)] = new_bytes
    verify_direct_install_entry(changed)
    manifest_patches.append(
        {
            "label": "run only the core installer from the HEN pthread",
            "kind": "x86_64_direct_install_entry",
            "entry_file_offset": f"0x{DIRECT_ENTRY_OFFSET:x}",
            "stub_file_offset": f"0x{DIRECT_INSTALL_STUB_OFFSET:x}",
            "firmware_file_offset": f"0x{DIRECT_FIRMWARE_CALL_OFFSET:x}",
            "install_target_file_offset": "0x42e8",
            "completion_marker": "/user/temp/hen.installed",
            "completion_marker_condition": "install_payload returned zero",
            "firmware": "14.02",
            "config_size": 44,
            "reason": (
                "return cleanly after the core installer, preserve its nonzero "
                "result, and create the marker only after a zero result instead "
                "of continuing through the outer HEN program that terminated WebProcess"
            ),
        }
    )

    actual_dynamic_scan = bytes(
        original[
            KERNEL_DYNAMIC_SCAN_OFFSET :
            KERNEL_DYNAMIC_SCAN_OFFSET + len(KERNEL_DYNAMIC_SCAN)
        ]
    )
    if actual_dynamic_scan != KERNEL_DYNAMIC_SCAN:
        raise ValueError(
            "kernel dynamic-table scan source differs at "
            f"0x{KERNEL_DYNAMIC_SCAN_OFFSET:x}: "
            f"expected {KERNEL_DYNAMIC_SCAN.hex()}, got {actual_dynamic_scan.hex()}"
        )
    changed[
        KERNEL_DYNAMIC_SCAN_OFFSET :
        KERNEL_DYNAMIC_SCAN_OFFSET + len(KERNEL_DYNAMIC_SCAN_PATCH)
    ] = KERNEL_DYNAMIC_SCAN_PATCH
    verify_kernel_dynamic_scan_bounds(changed)
    manifest_patches.append(
        {
            "label": "bound SCE_RELA lookup to the 14.02 PT_DYNAMIC span",
            "kind": "x86_64_kernel_dynamic_scan_bounds",
            "file_offset": f"0x{KERNEL_DYNAMIC_SCAN_OFFSET:x}",
            "length": len(KERNEL_DYNAMIC_SCAN_PATCH),
            "old_hex": KERNEL_DYNAMIC_SCAN.hex(),
            "new_hex": KERNEL_DYNAMIC_SCAN_PATCH.hex(),
            "dynamic_rva": f"0x{KERNEL_DYNAMIC_RVA:08x}",
            "dynamic_size": f"0x{KERNEL_DYNAMIC_SIZE:x}",
            "dynamic_end_exclusive": f"0x{KERNEL_DYNAMIC_RVA + KERNEL_DYNAMIC_SIZE:08x}",
            "entry_size": "0x10",
            "scan_stop_exclusive": f"0x{KERNEL_DYNAMIC_SCAN_STOP:08x}",
            "reason": (
                "search only complete entries in the verified 14.02 PT_DYNAMIC span while "
                "retaining the existing DT_SCE_RELA signature and failure path"
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

    actual_inner_printf = bytes(
        original[
            INNER_KERNEL_PRINTF_OFFSET :
            INNER_KERNEL_PRINTF_OFFSET + len(INNER_KERNEL_PRINTF_CALL)
        ]
    )
    if actual_inner_printf != INNER_KERNEL_PRINTF_CALL:
        raise ValueError(
            f"inner kernel printf call differs at 0x{INNER_KERNEL_PRINTF_OFFSET:x}: "
            f"expected {INNER_KERNEL_PRINTF_CALL.hex()}, got {actual_inner_printf.hex()}"
        )
    changed[
        INNER_KERNEL_PRINTF_OFFSET :
        INNER_KERNEL_PRINTF_OFFSET + len(INNER_KERNEL_PRINTF_BYPASS)
    ] = INNER_KERNEL_PRINTF_BYPASS
    manifest_patches.append(
        {
            "label": "remove diagnostic printf from the inner kernel entry",
            "kind": "x86_64_nop_indirect_call",
            "file_offset": f"0x{INNER_KERNEL_PRINTF_OFFSET:x}",
            "old_hex": INNER_KERNEL_PRINTF_CALL.hex(),
            "new_hex": INNER_KERNEL_PRINTF_BYPASS.hex(),
            "reason": "the retail kernel log path is not required for HEN installation",
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
        *KERNEL_DYNAMIC_SCAN_CHANGED_OFFSETS,
        *KERNEL_LIBC_CHANGED_OFFSETS,
        *range(0x4279, 0x42A4),
        *range(0x42FF, 0x430A),
        *range(0x430B, 0x433C),
        *OUTER_STAGE_CHANGED_OFFSETS,
        *OUTER_PREINSTALL_CHANGED_OFFSETS,
        *OUTER_FAST_LANE_CHANGED_OFFSETS,
        *DIRECT_ENTRY_CHANGED_OFFSETS,
        0x468D, 0x468E,
        0x46BB, 0x46BC, 0x46BD, 0x46BE, 0x46C0,
        0x4AEF, 0x4AF0, 0x4AF1, 0x4AF2,
        0x52DA, 0x52DB, 0x52DC, 0x52DF,
        *range(0x53AC, 0x53B1),
        *range(0x5519, 0x5522),
        *range(0xBD77, 0xBD7D),
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
            "path, replaces ring-0 imported libc buffer calls, bounds the "
            "SCE_RELA lookup to the verified 14.02 PT_DYNAMIC span, clears the "
            "embedded payload's full BSS span, removes its diagnostic kernel printf, "
            "uses a compact "
            "direct core-installer entry, skips redundant outer jailbreak/patch callbacks, "
            "and avoids unsupported optional and unported userland/plugin paths"
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
                *KERNEL_DYNAMIC_SCAN_CHANGED_OFFSETS,
                *KERNEL_LIBC_CHANGED_OFFSETS,
                *range(0x4279, 0x42A4),
                *range(0x42FF, 0x430A),
                *range(0x430B, 0x433C),
                *OUTER_STAGE_CHANGED_OFFSETS,
                *OUTER_PREINSTALL_CHANGED_OFFSETS,
                *OUTER_FAST_LANE_CHANGED_OFFSETS,
                *DIRECT_ENTRY_CHANGED_OFFSETS,
                0x468D, 0x468E,
                0x46BB, 0x46BC, 0x46BD, 0x46BE, 0x46C0,
                0x4AEF, 0x4AF0, 0x4AF1, 0x4AF2,
                0x52DA, 0x52DB, 0x52DC, 0x52DF,
                *range(0x53AC, 0x53B1),
                *range(0x5519, 0x5522),
                *range(0xBD77, 0xBD7D),
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
            "calls are replaced with exact scalar clear/copy loops. Its SCE_RELA "
            "lookup is bounded to the 0x110-byte 14.02 PT_DYNAMIC span at RVA "
            "0x00cfe890 while retaining the existing signature and failure path. "
            "The clear covers 0x8200 "
            "bytes so the 0x8008-byte payload's NOBITS globals start at zero, and "
            "the nonessential inner kernel printf is removed. "
            "The live pthread entry builds the safe config, calls install_payload "
            "directly, creates the completion marker only after it returns zero, "
            "preserves a nonzero result, and exits. "
            "The outer jailbreak, installed-marker check, generic kernel-patch "
            "callback, and remaining config-file check are skipped "
            "because Afterglow already completed those operations. "
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
