(function () {
  "use strict";

  var count = document.getElementById("count");
  var start = document.getElementById("start");
  var params = new URLSearchParams(window.location.search);
  var remaining = 5;
  var timer = null;
  var launched = false;

  function launchGoldHEN() {
    if (launched) return;
    launched = true;
    if (timer !== null) window.clearInterval(timer);
    if (start) start.disabled = true;
    if (count) count.textContent = "Starting GoldHEN...";

    // This must be a normal navigation from index.html. jb-g.js checks the
    // same-origin referrer before it will arm the kernel stage.
    window.location.href =
      "launch.html?v=1402s&log=1&afterglow=run&mode=goldhen";
  }

  if (params.get("afterglow") === "done") {
    if (count) {
      count.textContent =
        "GoldHEN run completed. Reboot the console before starting again.";
    }
    if (start) start.style.display = "none";
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
