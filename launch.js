(function () {
  "use strict";

  var count = document.getElementById("count");
  var start = document.getElementById("start");
  var crashReport = document.getElementById("crash-report");
  var crashSummary = document.getElementById("crash-summary");
  var acknowledge = document.getElementById("ack-crash");
  var diagnosticTest = document.getElementById("diagnostic-test");
  var testStorage = document.getElementById("test-storage");
  var testResult = document.getElementById("test-result");
  var params = new URLSearchParams(window.location.search);
  var diagnostics = window.AfterglowBreadcrumb || null;
  var remaining = 5;
  var timer = null;
  var launched = false;
  var testBound = false;

  function detectedFirmware() {
    var match = (navigator.userAgent || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!match) return null;
    return match[1] + "." + parseInt(match[2], 16).toString(16).padStart(2, "0");
  }

  function stop(message) {
    if (timer !== null) window.clearInterval(timer);
    timer = null;
    if (count) count.textContent = message;
    if (start) start.style.display = "none";
  }

  function launchGoldHEN() {
    if (launched) return;
    var firmware = detectedFirmware() || "unknown";
    if (firmware === "14.02") {
      stop("GoldHEN 14.02 is disabled after a hardware kernel panic. Do not retry this build.");
      return;
    }
    if (firmware !== "14.00") {
      stop("Firmware " + firmware + " is not supported by this release.");
      return;
    }
    launched = true;
    if (timer !== null) window.clearInterval(timer);
    timer = null;
    if (start) start.disabled = true;
    if (count) count.textContent = "Starting GoldHEN...";

    // This must be a normal navigation from index.html. jb-g.js checks the
    // same-origin referrer before it will arm the kernel stage.
    window.location.href =
      "launch.html?v=gh1402crumb1&log=1&afterglow=run&mode=goldhen";
  }

  function enableStorageTest(firmware) {
    if (!diagnosticTest || !testStorage || !testResult || !diagnostics) return;
    diagnosticTest.hidden = false;
    if (testBound) return;
    testBound = true;
    testStorage.addEventListener("click", function () {
      var opened = diagnostics.begin(firmware || "unknown", "harmless storage test");
      var armed = opened && diagnostics.checkpoint(
        "storage-test-armed",
        "storage only; no WebKit exploit or kernel code",
      );
      if (!armed) {
        testResult.textContent = "FAILED: " + diagnostics.error() + ". No kernel code was run.";
        return;
      }
      testStorage.disabled = true;
      testResult.textContent =
        "PASS: marker " + armed.stage + " was written and read back. Refresh or reopen this page to prove it survived.";
    });
  }

  function beginCountdown() {
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
      enableStorageTest(firmware);
      stop("GoldHEN 14.02 is disabled after a hardware kernel panic. Do not retry this build.");
      return;
    }

    if (start) {
      start.style.display = "inline-block";
      start.addEventListener("click", launchGoldHEN);
    }

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
  }

  function holdForPreviousRun(record) {
    if (!crashReport || !crashSummary || !acknowledge || !diagnostics) return false;
    crashReport.hidden = false;
    crashSummary.textContent = diagnostics.describe(record);
    if (diagnostics.isAcknowledged(record)) {
      acknowledge.style.display = "none";
      return false;
    }

    if (start) start.style.display = "none";
    if (count) count.textContent = "Auto-start paused until the previous run is acknowledged.";
    acknowledge.addEventListener("click", function () {
      if (!diagnostics.acknowledge(record)) {
        if (count) count.textContent =
          "Could not save acknowledgement (" + diagnostics.error() + "). Auto-start remains paused.";
        return;
      }
      acknowledge.disabled = true;
      acknowledge.textContent = "Previous run acknowledged";
      remaining = 5;
      beginCountdown();
    });
    return true;
  }

  var landingFirmware = detectedFirmware();
  if (landingFirmware === "14.02") {
    if (!diagnostics) {
      stop("Persistent diagnostics did not load. No kernel stage will run.");
      return;
    }
    var previous = diagnostics.latest();
    if (previous && !diagnostics.isComplete(previous) && holdForPreviousRun(previous)) return;
  }
  beginCountdown();
})();
