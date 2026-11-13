/* One explicit same-tab handoff per clean boot. A fresh nonce prevents a
   browser-restored launch page from running without another button press. */
(function () {
  "use strict";
  const DEST = "launch.html?v=1402hen17&log=1&afterglow=run&payload=hen-1402-core.bin&g=drain:16&g=drainsz:0x4000";
  const LOCK = "hen-1402-core-attempted";
  const TOKEN = "hen-1402-core-tab-token";
  const CANDIDATE_READY = true;
  const count = document.getElementById("count");
  const content = document.querySelector(".content");
  const button = document.createElement("button");
  button.id = "startBtn";
  button.textContent = "Start one 14.02 core HEN attempt";
  button.disabled = true;
  if (content) content.appendChild(button);

  function status(message) { if (count) count.textContent = message; }
  function arm() {
    if (!CANDIDATE_READY) {
      status("Launch paused while the corrected 14.02 host is reviewed.");
      return;
    }
    status("Ready to start 14.02 HEN.");
    button.disabled = false;
  }
  button.onclick = function () {
    if (!CANDIDATE_READY || button.disabled) return;
    button.disabled = true;
    const nonce = String(Date.now()) + "-" + String(Math.random()).slice(2);
    try {
      sessionStorage.setItem(TOKEN, nonce);
      localStorage.setItem(LOCK, nonce + ":started");
      if (sessionStorage.getItem(TOKEN) !== nonce ||
          localStorage.getItem(LOCK) !== nonce + ":started")
        throw new Error("storage verification failed");
    } catch (_) {
      status("Browser storage is unavailable; the launch was not armed.");
      button.disabled = false;
      return;
    }
    status("Starting 14.02 HEN...");
    location.assign(DEST + "&run=" + encodeURIComponent(nonce));
  };
  arm();
})();
