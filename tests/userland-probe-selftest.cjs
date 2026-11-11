const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..", "site");
const probePath = path.join(root, "u1", "probe.js");
const checksPath = path.join(root, "u1", "checks.js");
const page = fs.readFileSync(path.join(root, "u1", "index.html"), "utf8");
const d1 = fs.readFileSync(path.join(root, "d1", "index.html"), "utf8");
const probe = fs.readFileSync(probePath, "utf8");
const jb = fs.readFileSync(path.join(root, "jb-g.js"), "utf8");

async function main() {
  // The page's complete static dependency graph excludes the launcher and
  // kernel module. It cannot fetch a payload or make a network request.
  const scripts = [...page.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)];
  assert.equal(scripts.length, 1);
  assert.equal([...page.matchAll(/<script\b/g)].length, 1);
  assert.match(scripts[0][1], /^\.\/probe\.js\?/);
  assert.match(page, /script-src 'self'/);
  assert.match(page, /connect-src 'none'/);
  assert.match(d1, /href="\.\.\/u1\/"/);
  const pending = [probePath];
  const seen = new Set();
  while (pending.length) {
    const file = pending.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    assert.ok(file.startsWith(root + path.sep), "module escaped site root");
    const source = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(source, /\bimport\s*\(/);
    assert.doesNotMatch(source, /\bfetch\s*\(/);
    assert.doesNotMatch(source, /\bXMLHttpRequest\b|\bWebSocket\b/);
    for (const match of source.matchAll(/^\s*import\s+(?:[\s\S]*?\sfrom\s*)?["']([^"']+)["']/gm)) {
      assert.ok(match[1].startsWith("."), "remote import in probe graph");
      pending.push(path.resolve(path.dirname(file), match[1]));
    }
  }
  assert.deepEqual([...seen].map((file) => path.relative(root, file).replace(/\\/g, "/")).sort(), [
    "core.js", "int64.js", "mem.js", "ps4_offsets.js",
    "u1/checks.js", "u1/probe.js",
  ]);
  assert.match(probe, /button\.addEventListener\("click"/);
  assert.ok(probe.indexOf('button.addEventListener("click"') < probe.indexOf("await establishPrimitive("));
  assert.doesNotMatch(probe, /\bcallAddr\b|\bloadPayload\b|\bp\.write[1248]\s*\(/);

  const checksSource = fs.readFileSync(checksPath, "utf8");
  const checks = await import("data:text/javascript;base64," +
    Buffer.from(checksSource).toString("base64"));
  const offsetsSource = fs.readFileSync(path.join(root, "ps4_offsets.js"), "utf8");
  const offsets = await import("data:text/javascript;base64," +
    Buffer.from(offsetsSource).toString("base64"));
  const target = offsets.PS4["14.02"];
  assert.ok(target);
  for (const [, key] of checks.GADGET_PATTERNS)
    assert.ok(Number.isInteger(target[key]), "missing 14.02 gadget offset " + key);
  for (const key of ["wk_expm1_builtin", "wk_JSFunction_m_function",
    "wk___imp___error", "k__error", "k_scan_stage1", "pivot_view_sp"])
    assert.ok(Number.isInteger(target[key]), "missing 14.02 base offset " + key);

  // The copied read-only checks must track the launcher's current signatures.
  const sysBlock = /const SYS = \{([\s\S]*?)\};/.exec(jb);
  assert.ok(sysBlock);
  const sys = Object.fromEntries([...sysBlock[1].matchAll(/([a-z_]+):\s*(0x[0-9a-f]+|\d+)/gi)]
    .map((entry) => [entry[1], Number(entry[2])]));
  assert.deepEqual(Object.fromEntries(checks.STUB_NUMBERS), sys);
  const gadgetBlock = /const GAD = (\[[\s\S]*?\n    \]);/.exec(jb);
  assert.ok(gadgetBlock);
  const fakeOff = {};
  for (let i = 0; i < checks.GADGET_PATTERNS.length; ++i)
    fakeOff[checks.GADGET_PATTERNS[i][1]] = 0x1000 + i * 0x20;
  fakeOff.pivot_view_sp = 0x18;
  const launcherGadgets = Function("off", "return " + gadgetBlock[1])(fakeOff);
  const probeGadgets = checks.GADGET_PATTERNS.map(([name, key, pattern]) =>
    [name, fakeOff[key], pattern.map((byte) => byte === "pivot_view_sp" ? 0x18 : byte)]);
  assert.equal(JSON.stringify(probeGadgets), JSON.stringify(launcherGadgets));

  // Positive and negative controls exercise every read-only signature.
  class Addr {
    constructor(value) { this.value = value; }
    add32(offset) { return new Addr(this.value + offset); }
  }
  const webkit = new Addr(0x100000000);
  const libkernel = new Addr(0x200000000);
  const off = { pivot_view_sp: 0x18, k_scan_stage1: 0x40000 };
  const bytes = new Map();
  const words = new Map();
  checks.GADGET_PATTERNS.forEach(([name, key, pattern], index) => {
    off[key] = 0x1000 + index * 0x20;
    pattern.forEach((byte, at) => {
      if (byte !== null)
        bytes.set(webkit.value + off[key] + at,
          byte === "pivot_view_sp" ? off.pivot_view_sp : byte);
    });
  });
  checks.STUB_NUMBERS.forEach(([name, num], index) => {
    words.set(libkernel.value + index * 16, {
      low: (0xc0c748 | ((num & 0xff) << 24)) >>> 0,
      hi: (0x49000000 | (num >>> 8)) >>> 0,
    });
  });
  const p = {
    read1(at) { return bytes.get(at.value); },
    read8(at) { return words.get(at.value) || { low: 0, hi: 0 }; },
  };
  const good = checks.inspectUserland(p, off, webkit, libkernel);
  assert.equal(good.pass, true);
  assert.equal(good.gadgetCount, 15);
  assert.equal(good.stubCount, 24);
  const badGadgetAt = webkit.value + off.wk_POP_RDI_RET;
  bytes.set(badGadgetAt, 0);
  const badGadget = checks.inspectUserland(p, off, webkit, libkernel);
  assert.equal(badGadget.pass, false);
  assert.equal(badGadget.stage, "gadgets");
  bytes.set(badGadgetAt, 0x5f);
  words.set(libkernel.value + 3 * 16, { low: 0, hi: 0 });
  const badStub = checks.inspectUserland(p, off, webkit, libkernel);
  assert.equal(badStub.pass, false);
  assert.ok(badStub.missingStubs.includes("socket"));
  console.log("userland probe graph, parity, and read-only signatures: PASS");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
