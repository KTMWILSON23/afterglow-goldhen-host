/* Read-only counterparts of the gadget and syscall-stub checks in jb-g.js.
 * This module has no ROP builder, syscall caller, kernel stage, or payload.
 */

export const GADGET_PATTERNS = [
  ["POP_RDI_RET", "wk_POP_RDI_RET", [0x5f, 0xc3]],
  ["POP_RSI_RET", "wk_POP_RSI_RET", [0x5e, 0xc3]],
  ["POP_RDX_RET", "wk_POP_RDX_RET", [0x5a, 0xc3]],
  ["POP_RCX_RET", "wk_POP_RCX_RET", [0x59, 0xc3]],
  ["POP_R8_RET", "wk_POP_R8_RET", [null, 0x58, 0xc3]],
  ["POP_R9_RET", "wk_POP_R9_RET", [null, 0x59, 0xc3]],
  ["POP_RAX_RET", "wk_POP_RAX_RET", [0x58, 0xc3]],
  ["LEAVE_RET", "wk_LEAVE_RET", [0xc9, 0xc3]],
  ["MOV_RDI_RAX_RET", "wk_MOV_QWORD_PTR_RDI_RAX_RET", [0x48, 0x89, 0x07, 0xc3]],
  ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
  ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
  ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
  ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
  ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, "pivot_view_sp"]],
  ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
];

export const STUB_NUMBERS = [
  ["getpid", 20], ["getuid", 24], ["close", 6], ["socket", 97],
  ["socketpair", 135], ["getsockopt", 118], ["setsockopt", 105],
  ["mmap", 477], ["munmap", 73], ["thr_self", 432],
  ["getgroups", 79], ["getgid", 47], ["cpuset_getaffinity", 487],
  ["cpuset_setaffinity", 488], ["aio_multi_poll", 664],
  ["aio_multi_delete", 662], ["getegid", 43], ["aio_multi_wait", 663],
  ["aio_multi_cancel", 666], ["aio_submit_cmd", 669], ["write", 4],
  ["sysctl", 202], ["kill", 37], ["getppid", 39],
];

function stubNumber(value) {
  if ((value.low & 0x00ffffff) !== 0xc0c748 || (value.hi >>> 24) !== 0x49)
    return null;
  return ((value.low >>> 24) | ((value.hi & 0x00ffffff) << 8)) >>> 0;
}

export function inspectUserland(p, off, webkitBase, libkernelBase) {
  const badGadgets = [];
  for (const [name, key, pattern] of GADGET_PATTERNS) {
    const rva = off[key];
    if (!Number.isInteger(rva) || rva < 0) {
      badGadgets.push(name + ": missing offset");
      continue;
    }
    const at = webkitBase.add32(rva);
    let good = true;
    for (let i = 0; i < pattern.length; ++i) {
      const expected = pattern[i] === "pivot_view_sp" ? off.pivot_view_sp : pattern[i];
      if (expected === null) continue;
      if (!Number.isInteger(expected) || p.read1(at.add32(i)) !== expected) {
        good = false;
        break;
      }
    }
    if (!good) badGadgets.push(name);
  }
  if (badGadgets.length) {
    return {
      pass: false, stage: "gadgets", gadgetCount: GADGET_PATTERNS.length - badGadgets.length,
      gadgetTotal: GADGET_PATTERNS.length, badGadgets,
      stubCount: 0, stubTotal: STUB_NUMBERS.length, missingStubs: [],
    };
  }

  const found = new Set();
  const wanted = new Set(STUB_NUMBERS.map((entry) => entry[1]));
  if (off.k_stubs) {
    for (const numStr of Object.keys(off.k_stubs)) {
      const num = +numStr;
      if (!wanted.has(num)) continue;
      const rva = off.k_stubs[numStr];
      if (!Number.isInteger(rva) || rva < 0) continue;
      if (stubNumber(p.read8(libkernelBase.add32(rva))) === num) found.add(num);
    }
  }

  const limit = off.k_scan_stage1;
  if (!Number.isInteger(limit) || limit <= 0 || limit > 0x40000) {
    return {
      pass: false, stage: "stubs", gadgetCount: GADGET_PATTERNS.length,
      gadgetTotal: GADGET_PATTERNS.length, badGadgets: [],
      stubCount: found.size, stubTotal: STUB_NUMBERS.length,
      missingStubs: ["invalid scan limit"],
    };
  }
  for (let rva = 0; rva < limit && found.size < wanted.size; rva += 16) {
    const num = stubNumber(p.read8(libkernelBase.add32(rva)));
    if (wanted.has(num)) found.add(num);
  }
  const missingStubs = STUB_NUMBERS.filter((entry) => !found.has(entry[1]))
    .map((entry) => entry[0]);
  return {
    pass: missingStubs.length === 0, stage: "stubs",
    gadgetCount: GADGET_PATTERNS.length, gadgetTotal: GADGET_PATTERNS.length,
    badGadgets: [], stubCount: found.size, stubTotal: STUB_NUMBERS.length,
    missingStubs,
  };
}
