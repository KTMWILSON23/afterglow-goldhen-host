#!/usr/bin/env node
"use strict";

/* Offline-only generator. Nothing in site/ imports this file. */
const crypto = require("node:crypto");

const HOST_FREE = 0x130730;
const HOST_LAST = 0x131000;
const HOST_ROOM = HOST_LAST - HOST_FREE;
const TEARDOWN_START = 0x00b3a400;
const TEARDOWN_LENGTH = 0xc8;
const STATUS = Object.freeze({
  PATCHED: 0,
  ALREADY_FINAL: 1,
  REFUSED_MIXED_OR_UNKNOWN: 2,
  TEARDOWN_PADDING_DIRTY: 3,
  READBACK_FAILED_ROLLED_BACK: 4,
  READBACK_FAILED_ROLLBACK_FAILED: 5,
});

/* Hex is in increasing memory-address order. */
const SITES = Object.freeze([
  { id: "bootstrap-mmap-maxprot", rva: 0x490, stock: "ffffffff498b8740", final: "00000000498b8740" },
  { id: "bootstrap-mmap-branches-a", rva: 0x4b5, stock: "721385c9750f483b", final: "eb0085c9eb00483b" },
  { id: "bootstrap-mmap-branches-b", rva: 0x4b9, stock: "750f483b90f00000", final: "eb00483b90f00000" },
  { id: "bootstrap-mmap-branch-c", rva: 0x4c2, stock: "7269eb0485c97463", final: "eb69eb0485c97463" },
  { id: "bootstrap-syscall-gate", rva: 0xab4, stock: "9090909090909090", final: "ff26909090909090" },
  { id: "bootstrap-mmap-prot-immediates", rva: 0x1faeda, stock: "3341b23331c04531", final: "3741b23731c04531" },
  { id: "bootstrap-mmap-prot-immediate-second", rva: 0x1faedd, stock: "3331c04531f64531", final: "3731c04531f64531" },
  { id: "sysent11-narg", rva: 0x1102d80, stock: "00000000", final: "02000000" },
  { id: "sysent11-call", rva: 0x1102d88, dynamic: true, stockTargetRva: 0x1c07a0, finalTargetRva: 0xab4, length: 8 },
  { id: "sysent11-byte4", rva: 0x1102d84, stock: "00000000", final: "00000000" },
  { id: "sysent11-byte16", rva: 0x1102d90, stock: "0000000000000000", final: "0000000000000000" },
  { id: "sysent11-byte24", rva: 0x1102d98, stock: "0000000000000000", final: "0000000000000000" },
  { id: "sysent11-byte32", rva: 0x1102da0, stock: "0000000000000000", final: "0000000000000000" },
  { id: "sysent11-byte40", rva: 0x1102da8, stock: "00000000", final: "00000000" },
  { id: "sysent11-thrcnt", rva: 0x1102dac, stock: "04000000", final: "01000000" },
].map(Object.freeze));

const WRITES = Object.freeze([
  { id: "bootstrap-mmap-maxprot", rva: 0x490, width: 4, stock: "ffffffff", final: "00000000" },
  { id: "bootstrap-mmap-branches-a", rva: 0x4b5, width: 2, stock: "7213", final: "eb00" },
  { id: "bootstrap-mmap-branches-b", rva: 0x4b9, width: 2, stock: "750f", final: "eb00" },
  { id: "bootstrap-mmap-branch-c", rva: 0x4c2, width: 1, stock: "72", final: "eb" },
  { id: "bootstrap-syscall-gate", rva: 0xab4, width: 2, stock: "9090", final: "ff26" },
  { id: "sysent11-narg", rva: 0x1102d80, width: 4, stock: "00000000", final: "02000000" },
  { id: "sysent11-call", rva: 0x1102d88, width: 8, dynamic: true, stockTargetRva: 0x1c07a0, finalTargetRva: 0xab4 },
  { id: "sysent11-thrcnt", rva: 0x1102dac, width: 4, stock: "04000000", final: "01000000" },
  { id: "bootstrap-mmap-prot-immediates-a", rva: 0x1faeda, width: 1, stock: "33", final: "37" },
  { id: "bootstrap-mmap-prot-immediates-b", rva: 0x1faedd, width: 1, stock: "33", final: "37" },
].map(Object.freeze));

function bytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 || !/^[0-9a-f]+$/i.test(hex)) throw new Error("bad hex");
  return [...Buffer.from(hex, "hex")];
}
function addressHex(kbase, rva) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt.asUintN(64, BigInt(kbase) + BigInt(rva)));
  return out.toString("hex");
}
function expected(site, state, kbase) {
  if (!site.dynamic) return site[state];
  if (kbase === undefined) throw new Error("kbase required");
  return addressHex(kbase, state === "stock" ? site.stockTargetRva : site.finalTargetRva);
}

class Assembler {
  constructor() { this.b = []; this.labels = {}; this.fixups = []; this.trace = []; }
  get offset() { return this.b.length; }
  emit(...xs) { for (const x of xs) { if (!Number.isInteger(x) || x < 0 || x > 255) throw new Error("bad byte"); this.b.push(x); } }
  hex(x) { this.emit(...bytes(x)); }
  u32(x) { x = Number(x) >>> 0; this.emit(x & 255, (x >>> 8) & 255, (x >>> 16) & 255, (x >>> 24) & 255); }
  label(name) { if (name in this.labels) throw new Error("duplicate label"); this.labels[name] = this.offset; this.trace.push({ type: "label", name, offset: this.offset }); }
  rel(op, label, reason) { this.hex(op); const at = this.offset; this.u32(0); this.fixups.push({ at, label, reason }); }
  jne(label, reason) { this.rel("0f85", label, reason); }
  finish() {
    const out = Buffer.from(this.b);
    for (const f of this.fixups) {
      if (!(f.label in this.labels)) throw new Error("undefined label " + f.label);
      out.writeInt32LE(this.labels[f.label] - (f.at + 4), f.at);
    }
    return out;
  }
}

function emitKbase(a) {
  const start = a.offset;
  a.hex("b9820000c00f3248c1e22089c04809c24c8d9240feffff");
  a.trace.push({ type: "derive-kbase", start, end: a.offset, subtract: 0x1c0 });
}
function emitCompare(a, site, state, fail, phase) {
  const start = a.offset;
  if (site.dynamic) {
    a.hex("498d82"); a.u32(state === "stock" ? site.stockTargetRva : site.finalTargetRva);
    a.hex("493982"); a.u32(site.rva);
  } else {
    const value = bytes(site[state]);
    if (value.length === 8) { a.hex("48b8"); a.emit(...value); a.hex("493982"); a.u32(site.rva); }
    else if (value.length === 4) { a.hex("4181ba"); a.u32(site.rva); a.emit(...value); }
    else throw new Error("bad compare width");
  }
  const compareEnd = a.offset;
  a.jne(fail, phase + ":" + site.id);
  a.trace.push({ type: "check", phase, state, id: site.id, rva: site.rva, length: site.length || bytes(site[state]).length, start, compareEnd, end: a.offset, fail });
}
function emitChecks(a, state, fail, phase) { for (const site of SITES) emitCompare(a, site, state, fail, phase); }
function emitPadding(a, fail) {
  a.hex("31c0");
  for (let off = 0; off < TEARDOWN_LENGTH; off += 8) {
    const start = a.offset;
    a.hex("493982"); a.u32(TEARDOWN_START + off);
    const compareEnd = a.offset;
    a.jne(fail, "padding:" + off);
    a.trace.push({ type: "padding-check", rva: TEARDOWN_START + off, length: 8, start, compareEnd, end: a.offset, fail });
  }
}
function emitWrite(a, spec, state, phase) {
  const start = a.offset;
  if (spec.dynamic) {
    a.hex("498d82"); a.u32(state === "stock" ? spec.stockTargetRva : spec.finalTargetRva);
    a.hex("498982"); a.u32(spec.rva);
  } else {
    const value = bytes(spec[state]);
    if (value.length !== spec.width) throw new Error("write width mismatch");
    if (spec.width === 1) { a.hex("41c682"); a.u32(spec.rva); a.emit(...value); }
    else if (spec.width === 2) { a.hex("6641c782"); a.u32(spec.rva); a.emit(...value); }
    else if (spec.width === 4) { a.hex("41c782"); a.u32(spec.rva); a.emit(...value); }
    else throw new Error("bad write width");
  }
  a.trace.push({ type: "write", phase, state, id: spec.id, rva: spec.rva, width: spec.width, start, end: a.offset });
}
function emitFence(a, phase, purpose) {
  const start = a.offset;
  a.hex("0faef0");
  a.trace.push({ type: "barrier", phase, purpose, start, end: a.offset });
}
function emitBracket(a, state, phase) {
  const start = a.offset;
  a.hex("9cfa0f20c0504825fffffeff0f22c0"); // pushfq; cli; save CR0; clear WP
  const writesStart = a.offset;
  const activation = WRITES.find((spec) => spec.id === "sysent11-call");
  const dependencies = WRITES.filter((spec) => spec !== activation);
  if (state === "final") {
    /* Publish every dependency before the entry can point at the new gate. */
    for (const spec of dependencies) emitWrite(a, spec, state, phase);
    emitFence(a, phase, "publish-before-activation");
    emitWrite(a, activation, state, phase);
  } else {
    /* Stop new entrants and publish that fact before reverting gate/code. */
    emitWrite(a, activation, state, phase);
    emitFence(a, phase, "publish-deactivation");
    for (const spec of dependencies) emitWrite(a, spec, state, phase);
  }
  const writesEnd = a.offset;
  emitFence(a, phase, "flush-before-wp-restore");
  a.hex("580f22c09d");                     // exact CR0/RFLAGS restore
  a.trace.push({ type: "write-bracket", phase, state, start, writesStart, writesEnd, end: a.offset });
}
function emitReturn(a, name) {
  const start = a.offset;
  a.hex("b8"); a.u32(STATUS[name]); a.hex("c3");
  a.trace.push({ type: "return", status: name, value: STATUS[name], start, end: a.offset });
}

function build() {
  const a = new Assembler();
  a.label("entry"); emitKbase(a);
  emitChecks(a, "stock", "check-final", "preflight-stock");
  emitPadding(a, "padding-dirty");
  emitBracket(a, "final", "apply-final");
  emitChecks(a, "final", "rollback", "readback-final");
  emitReturn(a, "PATCHED");
  a.label("rollback");
  emitBracket(a, "stock", "rollback-stock");
  emitChecks(a, "stock", "rollback-failed", "readback-stock");
  emitReturn(a, "READBACK_FAILED_ROLLED_BACK");
  a.label("rollback-failed"); emitReturn(a, "READBACK_FAILED_ROLLBACK_FAILED");
  a.label("check-final");
  emitChecks(a, "final", "refused", "preflight-final");
  emitReturn(a, "ALREADY_FINAL");
  a.label("padding-dirty"); emitReturn(a, "TEARDOWN_PADDING_DIRTY");
  a.label("refused"); emitReturn(a, "REFUSED_MIXED_OR_UNKNOWN");
  const code = a.finish();
  if (code.length > HOST_ROOM) throw new Error("bootstrap exceeds host room");
  return Object.freeze({ code, hex: code.toString("hex"), sha256: crypto.createHash("sha256").update(code).digest("hex"), size: code.length, room: HOST_ROOM, labels: Object.freeze({ ...a.labels }), fixups: Object.freeze(a.fixups.map(Object.freeze)), trace: Object.freeze(a.trace.map(Object.freeze)) });
}

function snapshot(state, kbase) { return Object.fromEntries(SITES.map((s) => [s.id, expected(s, state, kbase)])); }
function matches(memory, state, kbase) { return SITES.every((s) => memory[s.id] === expected(s, state, kbase)); }
/* Specification simulator only; it does not execute native code. */
function simulate(input, options = {}) {
  const memory = { ...input }, writes = [], kbase = options.kbase;
  if (matches(memory, "final", kbase)) return { status: STATUS.ALREADY_FINAL, memory, writes };
  if (!matches(memory, "stock", kbase)) return { status: STATUS.REFUSED_MIXED_OR_UNKNOWN, memory, writes };
  if (options.paddingZero === false) return { status: STATUS.TEARDOWN_PADDING_DIRTY, memory, writes };
  for (const s of SITES) { memory[s.id] = expected(s, "final", kbase); writes.push({ phase: "apply-final", id: s.id }); }
  for (const id of options.failFinalIds || []) memory[id] = "bad";
  if (matches(memory, "final", kbase)) return { status: STATUS.PATCHED, memory, writes };
  for (const s of SITES) { memory[s.id] = expected(s, "stock", kbase); writes.push({ phase: "rollback-stock", id: s.id }); }
  for (const id of options.failRollbackIds || []) memory[id] = "bad";
  return { status: matches(memory, "stock", kbase) ? STATUS.READBACK_FAILED_ROLLED_BACK : STATUS.READBACK_FAILED_ROLLBACK_FAILED, memory, writes };
}

function manifest(r) {
  return { version: "guarded-bootstrap-1402-v1", offlineOnly: true, integrated: false, hostFree: "0x" + HOST_FREE.toString(16), hostLast: "0x" + HOST_LAST.toString(16), room: r.room, size: r.size, sha256: r.sha256, statuses: STATUS, sites: SITES, writes: WRITES, teardown: { startRva: "0x" + TEARDOWN_START.toString(16), length: TEARDOWN_LENGTH, endRvaInclusive: "0x" + (TEARDOWN_START + TEARDOWN_LENGTH - 1).toString(16) }, labels: r.labels, hex: r.hex };
}

module.exports = Object.freeze({ HOST_FREE, HOST_LAST, HOST_ROOM, TEARDOWN_START, TEARDOWN_LENGTH, STATUS, SITES, WRITES, expected, snapshot, simulate, build, manifest });
if (require.main === module) process.stdout.write(JSON.stringify(manifest(build()), null, 2) + "\n");
