(function (root) {
  "use strict";

  var VERSION = 1;
  var BUILD = "gh1402crumb1";
  var SLOT_KEYS = [
    "afterglow:last-stage:v1:0",
    "afterglow:last-stage:v1:1",
  ];
  var ACK_KEY = "afterglow:last-stage:v1:ack";
  var activeRun = null;
  var activeFirmware = null;
  var lastError = "";

  function shortText(value, limit) {
    var text = value == null ? "" : String(value);
    text = text.replace(/[\u0000-\u001f\u007f]/g, " ");
    return text.length > limit ? text.slice(0, limit) : text;
  }

  function canonical(record) {
    return JSON.stringify([
      record.v,
      record.build,
      record.fw,
      record.run,
      record.seq,
      record.stage,
      record.ts,
      record.detail,
    ]);
  }

  function checksumText(text) {
    var hash = 2166136261 >>> 0;
    for (var i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = (hash + (hash << 1) + (hash << 4) +
        (hash << 7) + (hash << 8) + (hash << 24)) >>> 0;
    }
    return ("00000000" + hash.toString(16)).slice(-8);
  }

  function checksum(record) {
    return checksumText(canonical(record));
  }

  function validRecord(record) {
    if (!record || record.v !== VERSION) return false;
    if (typeof record.build !== "string" || !record.build) return false;
    if (typeof record.fw !== "string" || !record.fw) return false;
    if (typeof record.run !== "string" || !record.run) return false;
    if (typeof record.stage !== "string" || !/^[a-z0-9-]{1,48}$/.test(record.stage)) return false;
    if (typeof record.detail !== "string") return false;
    if (typeof record.seq !== "number" || !isFinite(record.seq) ||
        record.seq < 1 || Math.floor(record.seq) !== record.seq) return false;
    if (typeof record.ts !== "number" || !isFinite(record.ts) || record.ts < 1) return false;
    if (typeof record.sum !== "string" || record.sum !== checksum(record)) return false;
    return true;
  }

  function readSlot(key) {
    try {
      var raw = root.localStorage.getItem(key);
      if (!raw) return null;
      var record = JSON.parse(raw);
      return validRecord(record) ? record : null;
    } catch (error) {
      lastError = "read: " + shortText(error && error.message ? error.message : error, 120);
      return null;
    }
  }

  function latest() {
    var first = readSlot(SLOT_KEYS[0]);
    var second = readSlot(SLOT_KEYS[1]);
    if (!first) return second;
    if (!second) return first;
    if (first.seq !== second.seq) return first.seq > second.seq ? first : second;
    return first.ts >= second.ts ? first : second;
  }

  function store(record) {
    try {
      record.sum = checksum(record);
      var raw = JSON.stringify(record);
      var key = SLOT_KEYS[record.seq & 1];
      root.localStorage.setItem(key, raw);

      /* setItem is synchronous. Read the exact bytes back before allowing a
         dangerous transition; the other slot remains the previous valid
         checkpoint if this write is torn by a sudden reboot. */
      var reread = root.localStorage.getItem(key);
      if (reread !== raw) {
        lastError = "write readback mismatch";
        return null;
      }
      var verified = JSON.parse(reread);
      if (!validRecord(verified)) {
        lastError = "write checksum mismatch";
        return null;
      }
      lastError = "";
      return verified;
    } catch (error) {
      lastError = "write: " + shortText(error && error.message ? error.message : error, 120);
      return null;
    }
  }

  function nextSequence() {
    var record = latest();
    return record ? record.seq + 1 : 1;
  }

  function newRunId() {
    return Date.now().toString(36) + "-" +
      Math.floor(Math.random() * 0x100000000).toString(36);
  }

  function detectFirmware() {
    var match = (root.navigator && root.navigator.userAgent || "")
      .match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!match) return "unknown";
    return match[1] + "." + parseInt(match[2], 16).toString(16).padStart(2, "0");
  }

  function write(run, firmware, stage, detail) {
    var record = {
      v: VERSION,
      build: BUILD,
      fw: shortText(firmware || "unknown", 16),
      run: shortText(run, 64),
      seq: nextSequence(),
      stage: shortText(stage, 48).toLowerCase(),
      ts: Date.now(),
      detail: shortText(detail, 192),
    };
    return store(record);
  }

  function begin(firmware, detail) {
    activeRun = newRunId();
    activeFirmware = shortText(firmware || detectFirmware(), 16);
    return write(activeRun, activeFirmware, "run-created", detail || "landing page");
  }

  function checkpoint(stage, detail) {
    var previous = latest();
    if (!activeRun) {
      if (previous && previous.stage !== "complete") {
        activeRun = previous.run;
        activeFirmware = previous.fw;
      } else {
        activeRun = newRunId();
        activeFirmware = detectFirmware();
      }
    }
    return write(activeRun, activeFirmware || detectFirmware(), stage, detail || "");
  }

  function recordId(record) {
    return record ? record.run + "|" + record.seq + "|" + record.sum : "";
  }

  function describe(record) {
    if (!record || !validRecord(record)) return "No valid diagnostic marker was found.";
    var when = "";
    try { when = new Date(record.ts).toISOString(); } catch (error) {}
    return "Last persisted stage: " + record.stage +
      " | firmware " + record.fw +
      " | build " + record.build +
      " | run " + record.run +
      (record.detail ? " | " + record.detail : "") +
      (when ? " | " + when : "");
  }

  function acknowledge(record) {
    if (!record || !validRecord(record)) return false;
    try {
      var value = recordId(record);
      root.localStorage.setItem(ACK_KEY, value);
      var ok = root.localStorage.getItem(ACK_KEY) === value;
      if (!ok) lastError = "acknowledgement readback mismatch";
      return ok;
    } catch (error) {
      lastError = "acknowledge: " + shortText(error && error.message ? error.message : error, 120);
      return false;
    }
  }

  function isAcknowledged(record) {
    if (!record || !validRecord(record)) return false;
    try {
      return root.localStorage.getItem(ACK_KEY) === recordId(record);
    } catch (error) {
      lastError = "acknowledgement read: " + shortText(error && error.message ? error.message : error, 120);
      return false;
    }
  }

  root.AfterglowBreadcrumb = {
    version: VERSION,
    build: BUILD,
    latest: latest,
    begin: begin,
    checkpoint: checkpoint,
    acknowledge: acknowledge,
    isAcknowledged: isAcknowledged,
    isComplete: function (record) {
      return !!record && validRecord(record) && record.stage === "complete";
    },
    describe: describe,
    error: function () { return lastError; },
  };
})(window);
