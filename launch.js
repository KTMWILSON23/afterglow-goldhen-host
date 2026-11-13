/* Unlimited launch mode. The first press arms the same-tab handoff; later
   failed shots can restart directly without a per-boot attempt cap. */
(function () {
  "use strict";
  const DEST = "launch.html?v=1402hen16&log=1&afterglow=run&payload=hen-1402-core.bin&retry=0&g=drain:16&g=drainsz:0x4000";
  const LOCK = "hen-1402-core-attempted";
  const TOKEN = "hen-1402-core-tab-token";
  const UNLIMITED = "hen-1402-unlimited";
  const CANDIDATE_READY = true;
  const count = document.getElementById("count");
  const content = document.querySelector(".content");
  const button = document.createElement("button");
  button.id = "startBtn";
  button.textContent = "Start unlimited 14.02 HEN attempts";
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
    sessionStorage.setItem(TOKEN, nonce);
    localStorage.setItem(LOCK, nonce + ":started");
    localStorage.setItem(UNLIMITED, "1");
    status("Starting 14.02 HEN...");
    location.assign(DEST + "&run=" + encodeURIComponent(nonce));
  };
  arm();
})();
