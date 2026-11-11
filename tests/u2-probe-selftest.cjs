"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..", "site");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const page = read("u2/index.html");
const start = read("u2/start.js");
const contractSource = read("u2/contract.js");
const jb = read("jb-g.js");
const afterglow = read("afterglow-g.js");

async function main() {
  // The landing page cannot start the check before a button press. Its module
  // graph contains no ROP, kernel code, or payload fetch.
  assert.match(page, /<button id="start"/);
  assert.match(page, /Cold reboot the 14\.02 PS4/);
  assert.match(page, /connect-src 'none'/);
  assert.equal([...page.matchAll(/<script\b/g)].length, 1);
  assert.match(page, /src="\.\/start\.js\?/);
  assert.ok(start.indexOf('button.addEventListener("click"') <
    start.indexOf("window.location.href ="));
  assert.match(start, /sessionStorage\.setItem\(ARM_KEY, run\)/);
  assert.match(start, /localStorage\.getItem\(RESULT_KEY\) !== record/);
  assert.doesNotMatch(start, /\bfetch\s*\(|\bcallAddr\b|\brunAfterglow\b/);
  assert.match(read("u1/index.html"), /href="\.\.\/u2\/"/);

  const contract = await import("data:text/javascript;base64," +
    Buffer.from(contractSource).toString("base64"));
  const good = { ok: true, reasons: [], pinRestored: true, rebootRequired: true };
  assert.deepEqual(contract.classifyProbeOutcome(good, true, null), {
    pass: true, reasons: [], rebootRequired: true,
  });
  assert.equal(contract.classifyProbeOutcome({ ok: false, reasons: ["no APM"] },
    true, null).pass, false);
  assert.equal(contract.classifyProbeOutcome(good, false, null).pass, false);
  assert.equal(contract.classifyProbeOutcome({ ...good, pinRestored: false },
    true, null).pass, false);
  assert.equal(contract.classifyProbeOutcome(null, true, new Error("failed"))
    .pass, false);
  const record = contract.makeProbeRecord("run", "pass", "ok\nextra", true);
  assert.equal(record.detail, "ok extra");
  assert.equal(record.rebootRequired, true);

  // Execute the landing script with a tiny browser stand-in. The button must
  // persist its token before navigating; unsupported firmware must stay put.
  const startBody = start.replace(/^import .*;\r?\n/gm, "");
  function landing(firmware, storageWorks = true) {
    const entries = new Map();
    const arm = new Map();
    const elements = new Map();
    function element(id) {
      if (!elements.has(id)) elements.set(id, {
        disabled: false, textContent: "", className: "", listeners: {},
        addEventListener(name, callback) { this.listeners[name] = callback; },
      });
      return elements.get(id);
    }
    const window = { location: { href: "" } };
    const localStorage = {
      getItem(key) { return entries.get(key) || null; },
      setItem(key, value) { if (storageWorks) entries.set(key, value); },
    };
    const sessionStorage = {
      getItem(key) { return arm.get(key) || null; },
      setItem(key, value) { if (storageWorks) arm.set(key, value); },
    };
    vm.runInNewContext(startBody, {
      document: { getElementById: element },
      navigator: { userAgent: firmware },
      offsetsFor: () => ({ key: firmware, off: firmware === "14.02" ? {} : null }),
      ARM_KEY: contract.ARM_KEY, RESULT_KEY: contract.RESULT_KEY,
      makeProbeRecord: contract.makeProbeRecord,
      localStorage, sessionStorage, window, Date, Math, JSON, encodeURIComponent,
    }, { filename: "u2/start.js" });
    return { window, element, entries, arm };
  }
  const supported = landing("14.02");
  assert.equal(typeof supported.element("start").listeners.click, "function");
  supported.element("start").listeners.click();
  assert.match(supported.window.location.href,
    /^\.\.\/launch\.html\?afterglow=probe&log=1&u2=1&run=/);
  assert.equal(JSON.parse(supported.entries.get(contract.RESULT_KEY)).stage, "started");
  assert.ok(supported.arm.get(contract.ARM_KEY));
  const unsupported = landing("14.00");
  assert.equal(unsupported.element("start").disabled, true);
  assert.equal(unsupported.window.location.href, "");
  const noStorage = landing("14.02", false);
  noStorage.element("start").listeners.click();
  assert.equal(noStorage.window.location.href, "");
  assert.match(noStorage.element("status").textContent, /Could not save/);

  // Evaluate the actual one-shot gate under accepted, replayed, and direct
  // navigation conditions. A used arm token cannot authorize a reload.
  const gateMatch = /const PROBE_ARMED = \(function \(\) \{[\s\S]*?\n\}\)\(\);/.exec(jb);
  assert.ok(gateMatch, "one-shot probe gate missing");
  function gate(search, referrer, saved) {
    const values = new Map(saved ? [[contract.ARM_KEY, saved]] : []);
    const sessionStorage = {
      getItem(key) { return values.has(key) ? values.get(key) : null; },
      removeItem(key) { values.delete(key); },
    };
    const result = vm.runInNewContext(gateMatch[0] + "\nPROBE_ARMED", {
      params: new URLSearchParams(search),
      document: { referrer },
      location: { origin: "https://host.test" },
      sessionStorage, URL, ARM_KEY: contract.ARM_KEY,
    });
    return { result, remaining: values.get(contract.ARM_KEY) };
  }
  const url = "?afterglow=probe&u2=1&run=run12345";
  assert.deepEqual(gate(url, "https://host.test/afterglow/u2/", "run12345"),
    { result: true, remaining: undefined });
  assert.equal(gate(url, "", "run12345").result, false);
  assert.equal(gate(url, "https://host.test/afterglow/u2/", "wrong").result, false);
  assert.equal(gate("?afterglow=probe", "https://host.test/afterglow/u2/",
    "run12345").result, false);

  const probe = afterglow.slice(afterglow.indexOf("export function probeAfterglow(ctx)"),
    afterglow.indexOf("/* --------------------------------------------------------------- the run */"));
  assert.ok(probe.length > 1000, "probe body missing");
  assert.doesNotMatch(probe, /shot\.take|\bk\.write|\brunAfterglow\b|\bloadPayload\b|\bloadEnabler\b|sc\(S\.(ioctl|kqueue|kevent)/);
  assert.match(probe, /out\.rebootRequired = held\.length > 0/);
  assert.match(probe, /out\.pinRestored = sc\(S\.cpuset_setaffinity/);
  assert.match(probe, /sockaddr\.u8\.set\(\[16, 2, 0x04, 0xD2, 0x0a, 0, 0, 1\]\)/);
  assert.match(probe, /const canary = sc\(S\.socket, 2, 2, 0\)/);
  assert.match(probe, /out\.optionFirst = "rc=" \+ rv/);
  assert.doesNotMatch(probe, /out\.optionsAccepted|accepted < TUNE\.sprays/);
  assert.ok(probe.indexOf("const canary =") < probe.indexOf("for (let i = 0; i < TUNE.sprays; i++)"));
  assert.match(probe, /runPrepared\(host\(\)\.prepareMany\(\[\[stubFor\(S\.getuid\), \[\]\]\]\)\)/);
  assert.match(jb, /const verdict = classifyProbeOutcome\(probeResult, restored, probeError\)/);
  assert.match(jb, /agOk = verdict\.pass/);
  const probeBranch = jb.indexOf('if (params.get("afterglow") === "probe")');
  assert.ok(probeBranch >= 0, "probe branch missing");
  assert.doesNotMatch(jb.slice(probeBranch), /agOk = true/);
  assert.match(jb, /probeCheckpoint\("device-probe", "Checking device access", true\)/);
  assert.match(jb, /location\.replace\(want === "probe" \? "u2\/" : "index\.html"\)/);
  assert.match(read("launch.html"), /jb-g\.js\?v=gh1402u2b/);
  assert.match(jb, /afterglow-g\.js\?v=gh1402u2b/);
  assert.match(jb, /if \(PROBE_ARMED\)[\s\S]*?else showRetry\(\)/);
  assert.match(jb, /Device check stalled\. Cold reboot before another exploit attempt/);
  assert.match(jb, /if \(SHOW_LOG \|\| !document\.body\) return/);
  assert.match(start, /afterglow=probe&log=1&u2=1&run=/);
  console.log("u2 one-shot gate, probe boundary, and truthful result: PASS");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
