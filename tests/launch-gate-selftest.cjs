"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const site = path.join(__dirname, "..", "site");
const code = fs.readFileSync(path.join(site, "launch.js"), "utf8");

function load({ failStorage = false } = {}) {
  const count = { textContent: "" };
  const content = {
    children: [],
    appendChild(child) { this.children.push(child); },
  };
  const session = new Map();
  const local = new Map();
  const assigned = [];

  function storage(map) {
    return {
      setItem(key, value) {
        if (failStorage) throw new Error("storage disabled");
        map.set(String(key), String(value));
      },
      getItem(key) { return map.has(String(key)) ? map.get(String(key)) : null; },
      removeItem(key) { map.delete(String(key)); },
    };
  }

  vm.runInNewContext(code, {
    document: {
      getElementById(id) { return id === "count" ? count : null; },
      querySelector(selector) { return selector === ".content" ? content : null; },
      createElement(tag) {
        return { tagName: tag.toUpperCase(), id: "", textContent: "", disabled: false, onclick: null };
      },
    },
    sessionStorage: storage(session),
    localStorage: storage(local),
    location: { assign(url) { assigned.push(url); } },
  }, { filename: "launch.js" });

  assert.equal(content.children.length, 1);
  return { button: content.children[0], count, session, local, assigned };
}

const armed = load();
assert.equal(armed.button.id, "startBtn");
assert.equal(armed.button.textContent, "Start one 14.02 core HEN attempt");
assert.equal(armed.button.disabled, false);
assert.equal(armed.count.textContent, "Ready to start 14.02 HEN.");

armed.button.onclick();
assert.equal(armed.assigned.length, 1);
const target = new URL(armed.assigned[0], "https://host.test/");
assert.equal(target.pathname, "/launch.html");
assert.equal(target.searchParams.get("v"), "1402hen17");
assert.equal(target.searchParams.get("afterglow"), "run");
assert.equal(target.searchParams.get("payload"), "hen-1402-core.bin");
assert.equal(target.searchParams.has("retry"), false);
const nonce = target.searchParams.get("run");
assert.match(nonce, /^[0-9]+-[0-9]+$/);
assert.equal(armed.session.get("hen-1402-core-tab-token"), nonce);
assert.equal(armed.local.get("hen-1402-core-attempted"), nonce + ":started");
assert.equal(armed.button.disabled, true);
armed.button.onclick();
assert.equal(armed.assigned.length, 1, "disabled button must not create a second handoff");

const blocked = load({ failStorage: true });
blocked.button.onclick();
assert.equal(blocked.assigned.length, 0);
assert.equal(blocked.button.disabled, false);
assert.match(blocked.count.textContent, /launch was not armed/);

const jb = fs.readFileSync(path.join(site, "jb-g.js"), "utf8");
assert.doesNotMatch(jb, /hen-1402-unlimited|scheduleUnlimitedShot|location\.reload/);
assert.match(jb, /sessionStorage\.getItem\("hen-1402-core-tab-token"\) === run/);
assert.match(jb, /localStorage\.getItem\("hen-1402-core-attempted"\) === run \+ ":started"/);
assert.match(jb, /markKernelStageEntered/);

const afterglow = fs.readFileSync(path.join(site, "afterglow-g.js"), "utf8");
assert.match(afterglow, /1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239/);
assert.equal((afterglow.match(/c\.callAddr\(fn, \[thr\.at, 0, entry, 0\]\)/g) || []).length, 1);

console.log("14.02 one-attempt launch gate self-test passed");
