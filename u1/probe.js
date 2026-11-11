import { establishPrimitive } from "../core.js";
import { installWindowP } from "../mem.js";
import { offsetsFor } from "../ps4_offsets.js";
import { inspectUserland } from "./checks.js";

/* This page stops after browser-module reads. It does not import the normal
 * launcher, construct a ROP call, invoke a syscall, or load a payload. */
const EXPECTED_FIRMWARE = "14.02";
const CHECKPOINT_KEY = "afterglow:u1:last:v1";
const button = document.getElementById("start");
const status = document.getElementById("status");
const log = document.getElementById("log");
const previous = document.getElementById("previous");
let runId = "";

function shortText(value, limit) {
  const text = String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f]/g, " ");
  return text.length > limit ? text.slice(0, limit) : text;
}

function line(text) {
  log.textContent += shortText(text, 160) + "\n";
  log.scrollTop = log.scrollHeight;
}

function checkpoint(stage, detail) {
  try {
    const raw = JSON.stringify({
      version: 1, run: runId, stage,
      detail: shortText(detail, 120), time: Date.now(),
    });
    localStorage.setItem(CHECKPOINT_KEY, raw);
    return localStorage.getItem(CHECKPOINT_KEY) === raw;
  } catch (_) {
    return false;
  }
}

function aligned(address) {
  return address && address.hi > 0 && (address.low & 0x3fff) === 0;
}

try {
  const record = JSON.parse(localStorage.getItem(CHECKPOINT_KEY) || "null");
  if (record && record.version === 1 && typeof record.stage === "string") {
    previous.textContent = "Previous check: " + shortText(record.stage, 32) +
      (record.detail ? " (" + shortText(record.detail, 120) + ")" : "");
  }
} catch (_) {
  previous.textContent = "Previous check unavailable.";
}

const firmware = offsetsFor(navigator.userAgent);
if (firmware.key !== EXPECTED_FIRMWARE || !firmware.off) {
  button.disabled = true;
  status.textContent = "This check is only for a PS4 on firmware 14.02.";
} else {
  button.addEventListener("click", async function () {
    button.disabled = true;
    runId = Date.now().toString(36) + "-" +
      Math.floor(Math.random() * 0x100000000).toString(36);
    if (!checkpoint("started", "browser-only check")) {
      status.textContent = "Could not save the start marker. Check stopped.";
      return;
    }
    status.textContent = "Checking the browser. It may close; reopen this page to see the last marker.";
    line("Started browser-only check on firmware 14.02.");

    try {
      const off = firmware.off;
      const carrier = await establishPrimitive({
        maxAttempts: 8,
        onEvent: function (tag, _detail, attempt) {
          if (/PASS|FAIL|ERROR|THREW|ABORT/i.test(tag))
            line(tag + (attempt == null ? "" : " (attempt " + attempt + ")"));
        },
      });
      if (!checkpoint("primitive", "browser memory read/write established"))
        throw new Error("Could not save the primitive marker");
      line("Browser memory primitive established.");

      const p = installWindowP(carrier, { promote: false });
      const cell = p.leakval(Math.expm1);
      const nativeFn = p.read8(
        p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function),
      );
      const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
      const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
      let libkernelBase = errorFn.sub32(off.k__error);
      const adjustment = libkernelBase.low & 0x3fff;
      if (adjustment) libkernelBase = libkernelBase.sub32(adjustment);
      if (!aligned(webkitBase) || !aligned(libkernelBase))
        throw new Error("Browser or library base alignment failed");
      if (!checkpoint("bases", "browser and library bases aligned"))
        throw new Error("Could not save the base marker");
      line("Browser and library base checks passed.");

      const result = inspectUserland(p, off, webkitBase, libkernelBase);
      line("Browser gadget signatures: " + result.gadgetCount + "/" + result.gadgetTotal + ".");
      if (!checkpoint("gadgets", result.gadgetCount + "/" + result.gadgetTotal))
        throw new Error("Could not save the gadget marker");
      if (result.badGadgets.length)
        throw new Error("Gadget mismatch: " + result.badGadgets.join(", "));
      line("Library syscall stubs: " + result.stubCount + "/" + result.stubTotal + ".");
      if (!checkpoint("stubs", result.stubCount + "/" + result.stubTotal))
        throw new Error("Could not save the stub marker");
      if (!result.pass)
        throw new Error("Missing stubs: " + result.missingStubs.join(", "));

      /* Intentional end of route: no ROP setup, device access, kernel writes,
       * GoldHEN import, or payload thread follows this point. */
      if (!checkpoint("complete", "15/15 gadgets; 24/24 stubs; no kernel access"))
        throw new Error("Could not save the completion marker");
      status.textContent = "PASS: browser checks completed. GoldHEN and the kernel exploit were not run.";
      status.className = "pass";
      line("Stopped before ROP and kernel stages.");
      return;
    } catch (error) {
      const message = shortText(error && error.message ? error.message : error, 120);
      checkpoint("failed", message);
      status.textContent = "Check stopped: " + message + ". GoldHEN was not run.";
      status.className = "fail";
      line("Stopped without a kernel step.");
    }
  });
}
