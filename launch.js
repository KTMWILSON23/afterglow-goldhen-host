(function () {
  "use strict";

  var count = document.getElementById("count");
  var start = document.getElementById("start");
  var params = new URLSearchParams(window.location.search);
  var remaining = 5;
  var timer = null;
  var launched = false;

  function detectedFirmware() {
    var match = (navigator.userAgent || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!match) return null;
    return match[1] + "." + parseInt(match[2], 16).toString(16).padStart(2, "0");
  }

  function stop(message) {
    if (timer !== null) window.clearInterval(timer);
    if (count) count.textContent = message;
    if (start) start.style.display = "none";
  }

  function launchGoldHEN() {
    if (launched) return;
    launched = true;
    if (timer !== null) window.clearInterval(timer);
    if (start) start.disabled = true;
    if (count) count.textContent = "Starting GoldHEN...";

    // This must be a normal navigation from index.html. jb-g.js checks the
    // same-origin referrer before it will arm the kernel stage.
    window.location.href =
      "launch.html?v=gh1402panic3&log=1&afterglow=run&mode=goldhen";
  }

  if (params.get("afterglow") === "done") {
    stop("GoldHEN payload thread started. Check the console notification; reboot before another attempt.");
    return;
  }

  if (params.get("afterglow") === "failed") {
    stop("GoldHEN did not start. Cold boot the console before trying again.");
    return;
  }

  if (params.get("afterglow") === "probe") {
    stop("Probe finished. No GoldHEN payload was started.");
    return;
  }

  var firmware = detectedFirmware();
  if (firmware && firmware !== "14.00" && firmware !== "14.02") {
    stop("Firmware " + firmware + " is not supported by this release.");
    return;
  }

  if (firmware === "14.02") {
    stop("GoldHEN 14.02 is disabled after a hardware kernel panic. Do not retry this build.");
    return;
  }

  if (start) start.addEventListener("click", launchGoldHEN);

  timer = window.setInterval(function () {
    remaining -= 1;
    if (remaining <= 0) {
      launchGoldHEN();
      return;
    }
    if (count) {
      count.textContent =
        "GoldHEN starts in " + remaining +
        (remaining === 1 ? " second..." : " seconds...");
    }
  }, 1000);
})();
