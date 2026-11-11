"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const api = require(path.join(__dirname, "..", "site", "preflight-1402.js"));
const kbase = { low: 0x82200000, hi: 0xffffffff };
const specs = api.sites();
const liveBootstrap = new Map([
  [0x490, "ffffffff498b8740"],
  [0x4b5, "721385c9750f483b"],
  [0x4b9, "750f483b90f00000"],
  [0x4c2, "7269eb0485c97463"],
  [0xab4, "9090909090909090"],
  [0x1faeda, "3341b23331c04531"],
  [0x1faedd, "3331c04531f64531"],
]);
for (const [rva, bytes] of liveBootstrap) {
  const site = specs.find((candidate) => candidate.rva === rva);
  assert.ok(site, `missing live bootstrap guard at 0x${rva.toString(16)}`);
  assert.equal(site.stock, bytes, `live bootstrap guard at 0x${rva.toString(16)}`);
}

assert.equal(specs.length, 30);
assert.equal(specs.filter((site) => site.group === "bootstrap").length, 15);
assert.equal(specs.filter((site) => site.group === "patches").length, 15);
assert.equal(Object.isFrozen(specs[0]), true);
assert.throws(() => { specs[0].rva = 0; }, TypeError);
assert.equal(api.sites()[0].rva, 0x490);

const call = specs.find((site) => site.id === "sysent11-call");
assert.equal(api.expectedHex(call, "stock", kbase), "a0073c82ffffffff");
assert.equal(api.expectedHex(call, "final", kbase), "b40a2082ffffffff");

function snapshot(state) {
  return Object.fromEntries(
    specs.map((site) => [site.id, api.expectedHex(site, state, kbase)]),
  );
}

const stock = snapshot("stock");
const final = snapshot("final");

let result = api.evaluate(stock, { kbase });
assert.equal(result.state, "all-stock");
assert.equal(result.groups.bootstrap.state, "all-stock");
assert.equal(result.groups.patches.state, "all-stock");
assert.deepEqual(result.counts, { stock: 25, final: 0, unchanged: 5, unknown: 0 });
assert.equal(result.safeToWrite, false);

result = api.evaluate(final, { kbase });
assert.equal(result.state, "all-final");
assert.equal(result.groups.bootstrap.state, "all-final");
assert.equal(result.groups.patches.state, "all-final");

const mixed = snapshot("stock");
mixed[specs[0].id] = final[specs[0].id];
result = api.evaluate(mixed, { kbase });
assert.equal(result.state, "mixed");
assert.equal(result.groups.bootstrap.state, "mixed");

const missing = snapshot("stock");
delete missing[specs[3].id];
result = api.evaluate(missing, { kbase });
assert.equal(result.state, "unknown");
assert.equal(result.sites.find((site) => site.id === specs[3].id).error, "missing-or-invalid-bytes");

const corrupt = snapshot("stock");
corrupt[specs[4].id] = "0011223344556677";
result = api.evaluate(corrupt, { kbase });
assert.equal(result.state, "unknown");
assert.equal(result.sites.find((site) => site.id === specs[4].id).error, "unexpected-bytes");

const malformed = snapshot("stock");
malformed[specs[5].id] = "gg" + malformed[specs[5].id];
result = api.evaluate(malformed, { kbase });
assert.equal(result.state, "unknown");
assert.equal(result.sites.find((site) => site.id === specs[5].id).error, "missing-or-invalid-bytes");

result = api.evaluate(stock);
assert.equal(result.state, "unknown");
assert.equal(result.sites.find((site) => site.id === "sysent11-call").error, "kernel-base-required");

const calls = [];
result = api.evaluate((rva, length, site) => {
  calls.push([rva, length, site.id]);
  return stock[site.id];
}, { kbase });
assert.equal(result.state, "all-stock");
assert.equal(calls.length, specs.length);
for (const [rva, length, id] of calls) {
  const site = specs.find((candidate) => candidate.id === id);
  assert.equal(rva, site.rva);
  assert.equal(length, api.expectedHex(site, "stock", kbase).length / 2);
}

console.log("14.02 preflight classifier self-test passed");
