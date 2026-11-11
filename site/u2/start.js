import { offsetsFor } from "../ps4_offsets.js";
import { ARM_KEY, RESULT_KEY, makeProbeRecord } from "./contract.js";

const button = document.getElementById("start");
const status = document.getElementById("status");
const previous = document.getElementById("previous");
const firmware = offsetsFor(navigator.userAgent);

try {
  const last = JSON.parse(localStorage.getItem(RESULT_KEY) || "null");
  if (last && last.version === 1 && typeof last.stage === "string") {
    previous.textContent = "Previous check: " + last.stage +
      (last.detail ? "\n" + last.detail : "") +
      (last.rebootRequired ? "\nCold reboot required before another exploit attempt." : "");
    previous.className = last.stage === "pass" ? "pass" : "fail";
  }
} catch (_) {
  previous.textContent = "Previous check unavailable.";
}

if (firmware.key !== "14.02" || !firmware.off) {
  button.disabled = true;
  status.textContent = "This check is only for a PS4 on firmware 14.02.";
} else {
  button.addEventListener("click", function () {
    button.disabled = true;
    const run = Date.now().toString(36) + "-" +
      Math.floor(Math.random() * 0x100000000).toString(36);
    const record = JSON.stringify(makeProbeRecord(run, "started", "Device check armed", false));
    try {
      localStorage.setItem(RESULT_KEY, record);
      sessionStorage.setItem(ARM_KEY, run);
      if (localStorage.getItem(RESULT_KEY) !== record ||
          sessionStorage.getItem(ARM_KEY) !== run)
        throw new Error("Storage readback failed");
    } catch (_) {
      status.textContent = "Could not save the start marker. Check stopped.";
      return;
    }
    status.textContent = "Opening the device check...";
    window.location.href = "../launch.html?afterglow=probe&log=1&u2=1&run=" +
      encodeURIComponent(run);
  });
}
