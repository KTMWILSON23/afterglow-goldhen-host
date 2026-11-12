/* One manual attempt per acknowledged cold boot. The exploit page verifies
   this same-tab handoff again before it initializes WebKit. */
(function () {
  "use strict";
  const DEST = "launch.html?v=1402hen1&log=1&afterglow=run&payload=hen-1402-core.bin&retry=0&g=drain:16&g=drainsz:0x4000";
  const LOCK = "hen-1402-core-attempted";
  const TOKEN = "hen-1402-core-tab-token";
  /* Keep the UI locked until the corrected payload and dynamic host path
     have completed review together. */
  const CANDIDATE_READY = true;
  const count = document.getElementById("count");
  const content = document.querySelector(".content");
  const button = document.createElement("button");
  button.id = "startBtn";
  button.textContent = "Start corrected 14.02 HEN";
  button.disabled = true;
  if (content) content.appendChild(button);

  function status(message) { if (count) count.textContent = message; }
  function arm() {
    if (!CANDIDATE_READY) {
      status("Launch paused while the corrected 14.02 host is reviewed.");
      return;
    }
    if (localStorage.getItem(LOCK)) {
      status("Previous attempt recorded. Power off the PS4 completely before another attempt.");
      const input = document.createElement("input");
      input.placeholder = "Type COLD BOOT DONE";
      input.setAttribute("aria-label", "Cold boot acknowledgement");
      if (content) content.appendChild(input);
      const unlock = document.createElement("button");
      unlock.textContent = "Unlock after full power off";
      if (content) content.appendChild(unlock);
      unlock.onclick = function () {
        if (input.value !== "COLD BOOT DONE") return;
        localStorage.removeItem(LOCK);
        if (input.parentNode) input.parentNode.removeChild(input);
        if (unlock.parentNode) unlock.parentNode.removeChild(unlock);
        status("Ready for one manual attempt. A kernel panic is possible.");
        button.disabled = false;
      };
      return;
    }
    status("Ready for one manual attempt. A kernel panic is possible.");
    button.disabled = false;
  }
  button.onclick = function () {
    if (!CANDIDATE_READY || button.disabled || localStorage.getItem(LOCK)) return;
    button.disabled = true;
    const nonce = String(Date.now()) + "-" + String(Math.random()).slice(2);
    sessionStorage.setItem(TOKEN, nonce);
    localStorage.setItem(LOCK, nonce + ":started");
    status("Starting one attempt; power off completely before trying again.");
    location.assign(DEST + "&run=" + encodeURIComponent(nonce));
  };
  arm();
})();
