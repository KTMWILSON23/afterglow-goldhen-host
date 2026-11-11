#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const preflight = require("../site/preflight-1402.js");
const guarded = require("../tools/build-guarded-bootstrap-1402.cjs");

const KBASE = 0xffffffff82200000n;
const built = guarded.build();
assert.equal(built.size, 1912, "reviewed code size changed");
assert.equal(built.sha256, "3e9850fbee181aa12e66870d699dbdefac8cbf5b7fa9af643505f90c9bce89a9", "reviewed machine code changed");
assert.ok(built.size <= guarded.HOST_ROOM);
assert.equal(built.size, built.code.length);
assert.equal(built.hex, built.code.toString("hex"));
assert.match(built.sha256, /^[0-9a-f]{64}$/);

for (const f of built.fixups) {
  assert.equal(f.at + 4 + built.code.readInt32LE(f.at), built.labels[f.label], f.reason);
}

const independent = preflight.sites().filter((s) => s.group === "bootstrap");
assert.equal(independent.length, 15);
assert.deepEqual(guarded.SITES.map((s) => s.id), independent.map((s) => s.id));
for (const site of guarded.SITES) {
  const other = independent.find((s) => s.id === site.id);
  assert.equal(site.rva, other.rva, site.id);
  assert.equal(guarded.expected(site, "stock", KBASE), preflight.expectedHex(other, "stock", KBASE.toString(16)), site.id);
  assert.equal(guarded.expected(site, "final", KBASE), preflight.expectedHex(other, "final", KBASE.toString(16)), site.id);
}

const checks = built.trace.filter((e) => e.type === "check");
for (const phase of ["preflight-stock", "preflight-final", "readback-final", "readback-stock"]) {
  const rows = checks.filter((e) => e.phase === phase);
  assert.equal(rows.length, 15, phase);
  assert.deepEqual(rows.map((e) => e.id), guarded.SITES.map((s) => s.id), phase);
  assert.deepEqual(rows.map((e) => e.length), [8, 8, 8, 8, 8, 8, 8, 4, 8, 4, 8, 8, 8, 4, 4], phase);
}

const padding = built.trace.filter((e) => e.type === "padding-check");
assert.equal(padding.length, 25);
assert.equal(padding[0].rva, guarded.TEARDOWN_START);
assert.equal(padding.at(-1).rva + 8, guarded.TEARDOWN_START + guarded.TEARDOWN_LENGTH);

const brackets = built.trace.filter((e) => e.type === "write-bracket");
assert.deepEqual(brackets.map((e) => e.phase), ["apply-final", "rollback-stock"]);
for (const bracket of brackets) {
  const writes = built.trace.filter((e) => e.type === "write" && e.phase === bracket.phase);
  assert.equal(writes.length, 10);
  assert.ok(writes.every((e) => e.start >= bracket.writesStart && e.end <= bracket.writesEnd));
  assert.equal(built.code[bracket.start], 0x9c);
  assert.equal(built.code[bracket.start + 1], 0xfa);
  assert.equal(built.code[bracket.end - 1], 0x9d);
}

/* sysent[11].sy_call is the activation edge.  Forward construction must make
   it the final store after a publication fence.  Rollback must remove it in
   the first store and publish that before reverting the gate or code bytes. */
const forwardWrites = built.trace.filter((e) => e.type === "write" && e.phase === "apply-final");
const rollbackWrites = built.trace.filter((e) => e.type === "write" && e.phase === "rollback-stock");
assert.equal(forwardWrites.at(-1).id, "sysent11-call");
assert.equal(rollbackWrites[0].id, "sysent11-call");
assert.ok(forwardWrites.slice(0, -1).some((e) => e.id === "bootstrap-syscall-gate"));
assert.ok(rollbackWrites.slice(1).some((e) => e.id === "bootstrap-syscall-gate"));

const forwardPublish = built.trace.find((e) => e.type === "barrier" && e.phase === "apply-final" && e.purpose === "publish-before-activation");
const rollbackPublish = built.trace.find((e) => e.type === "barrier" && e.phase === "rollback-stock" && e.purpose === "publish-deactivation");
assert.ok(forwardPublish.end <= forwardWrites.at(-1).start);
assert.ok(forwardWrites.at(-2).end <= forwardPublish.start);
assert.ok(rollbackWrites[0].end <= rollbackPublish.start);
assert.ok(rollbackPublish.end <= rollbackWrites[1].start);

/* Assert every observable partial transition is safe: before activation all
   dependencies are final; after deactivation no stock dependency is restored
   while the pointer is still final. */
const forwardState = Object.fromEntries(guarded.WRITES.map((w) => [w.id, "stock"]));
for (const event of forwardWrites) {
  if (event.id === "sysent11-call") {
    assert.ok(Object.entries(forwardState).every(([id, state]) => id === "sysent11-call" || state === "final"));
  }
  forwardState[event.id] = "final";
}
assert.ok(Object.values(forwardState).every((state) => state === "final"));

const rollbackState = Object.fromEntries(guarded.WRITES.map((w) => [w.id, "final"]));
for (const event of rollbackWrites) {
  if (event.id !== "sysent11-call") assert.equal(rollbackState["sysent11-call"], "stock");
  rollbackState[event.id] = "stock";
}
assert.ok(Object.values(rollbackState).every((state) => state === "stock"));

const firstWrite = Math.min(...built.trace.filter((e) => e.type === "write").map((e) => e.start));
assert.ok(checks.filter((e) => e.phase === "preflight-stock").every((e) => e.end < firstWrite));
assert.ok(padding.every((e) => e.end < firstWrite));

const stock = guarded.snapshot("stock", KBASE);
const final = guarded.snapshot("final", KBASE);
let run = guarded.simulate(stock, { kbase: KBASE, paddingZero: true });
assert.equal(run.status, guarded.STATUS.PATCHED); assert.deepEqual(run.memory, final);
run = guarded.simulate(final, { kbase: KBASE, paddingZero: true });
assert.equal(run.status, guarded.STATUS.ALREADY_FINAL); assert.equal(run.writes.length, 0);
run = guarded.simulate({ ...stock, [guarded.SITES[0].id]: final[guarded.SITES[0].id] }, { kbase: KBASE, paddingZero: true });
assert.equal(run.status, guarded.STATUS.REFUSED_MIXED_OR_UNKNOWN); assert.equal(run.writes.length, 0);
run = guarded.simulate({ ...stock, [guarded.SITES[1].id]: "bad" }, { kbase: KBASE, paddingZero: true });
assert.equal(run.status, guarded.STATUS.REFUSED_MIXED_OR_UNKNOWN); assert.equal(run.writes.length, 0);
run = guarded.simulate(stock, { kbase: KBASE, paddingZero: false });
assert.equal(run.status, guarded.STATUS.TEARDOWN_PADDING_DIRTY); assert.equal(run.writes.length, 0);
run = guarded.simulate(stock, { kbase: KBASE, paddingZero: true, failFinalIds: [guarded.SITES[2].id] });
assert.equal(run.status, guarded.STATUS.READBACK_FAILED_ROLLED_BACK); assert.deepEqual(run.memory, stock);
run = guarded.simulate(stock, { kbase: KBASE, paddingZero: true, failFinalIds: [guarded.SITES[2].id], failRollbackIds: [guarded.SITES[3].id] });
assert.equal(run.status, guarded.STATUS.READBACK_FAILED_ROLLBACK_FAILED);

console.log(JSON.stringify({ ok: true, version: "guarded-bootstrap-1402-v1", size: built.size, room: built.room, sha256: built.sha256, sites: guarded.SITES.length, intendedWrites: guarded.WRITES.length, paddingQwords: padding.length }));
