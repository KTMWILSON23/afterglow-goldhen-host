(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module && module.exports) module.exports = api;
  if (root) root.AfterglowTeardownVerify = api;
})(typeof window !== "undefined" ? window : this, function () {
  "use strict";

  var TABLE_LENGTH = 11 * 8;
  var CLOSE_OFFSET = 7 * 8;
  var STUB = [0x31, 0xc0, 0xc3, 0, 0, 0, 0, 0];

  function samePointer(a, b) {
    return !!a && !!b && (a.low >>> 0) === (b.low >>> 0) &&
      (a.hi >>> 0) === (b.hi >>> 0);
  }

  function pointerBytes(pointer) {
    if (!pointer || !Number.isInteger(pointer.low) || !Number.isInteger(pointer.hi)) return null;
    var low = pointer.low >>> 0;
    var hi = pointer.hi >>> 0;
    return [low & 255, (low >>> 8) & 255, (low >>> 16) & 255, (low >>> 24) & 255,
      hi & 255, (hi >>> 8) & 255, (hi >>> 16) & 255, (hi >>> 24) & 255];
  }

  function sameBytes(actual, expected) {
    if (!actual || actual.length !== expected.length) return false;
    for (var i = 0; i < expected.length; i++) if (actual[i] !== expected[i]) return false;
    return true;
  }

  function expectedTable(source, stub) {
    if (!source || source.length !== TABLE_LENGTH) return null;
    var pointer = pointerBytes(stub);
    if (!pointer) return null;
    var table = new Uint8Array(source);
    table.set(pointer, CLOSE_OFFSET);
    return table;
  }

  function validFd(fd) {
    return Number.isInteger(fd) && fd >= 0 && fd <= 0xffff;
  }

  function verify(input) {
    var failures = [];
    var checked = { devices: 0, queues: 0, notes: 0, tables: 0 };
    var devs = input && input.devs;
    var queues = input && input.queues;
    if (!input || typeof input.read !== "function" || typeof input.read8 !== "function" ||
        typeof input.plus !== "function" || typeof input.inHeap !== "function" ||
        !Array.isArray(devs) || !devs.length || !Array.isArray(queues) || !queues.length ||
        !input.ofs || !input.stub || !input.dtab || !input.qtab ||
        !input.deviceSource || !input.queueSource || !input.noteBefore) {
      return { ok: false, failures: ["incomplete verification input"], checked: checked };
    }

    function read(address, length, label) {
      try {
        var bytes = input.read(address, length);
        if (!bytes || bytes.length !== length) {
          failures.push(label + ": unreadable");
          return null;
        }
        return bytes;
      } catch (error) {
        failures.push(label + ": read threw");
        return null;
      }
    }
    function read8(address, label) {
      try {
        var value = input.read8(address);
        if (!pointerBytes(value)) {
          failures.push(label + ": unreadable");
          return null;
        }
        return value;
      } catch (error) {
        failures.push(label + ": read threw");
        return null;
      }
    }
    function at(address, offset) {
      try { return input.plus(address, offset); }
      catch (error) { failures.push("address arithmetic failed"); return null; }
    }
    function inHeap(pointer) {
      try { return !!input.inHeap(pointer); }
      catch (error) { failures.push("heap check threw"); return false; }
    }

    var stub = read(input.stub, 8, "close stub");
    if (stub && !sameBytes(stub, STUB)) failures.push("close stub: unexpected bytes");

    function table(source, copy, label) {
      var expected = expectedTable(source.bytes, input.stub);
      if (!source.address || !expected) {
        failures.push(label + ": missing original table snapshot");
        return;
      }
      var original = read(source.address, TABLE_LENGTH, label + " original");
      if (original && !sameBytes(original, source.bytes)) failures.push(label + ": original changed");
      var cloned = read(copy, TABLE_LENGTH, label + " clone");
      if (cloned && !sameBytes(cloned, expected)) failures.push(label + ": clone mismatch");
      if (original && cloned && sameBytes(original, source.bytes) && sameBytes(cloned, expected)) checked.tables++;
    }
    table(input.deviceSource, input.dtab, "device table");
    table(input.queueSource, input.qtab, "queue table");

    function file(fd, group) {
      if (!validFd(fd)) {
        failures.push(group + " fd " + fd + ": invalid");
        return null;
      }
      var f = read8(at(input.ofs, fd * 8), group + " fd " + fd + " file");
      if (!f) return null;
      if (!inHeap(f)) {
        failures.push(group + " fd " + fd + ": file pointer outside heap");
        return null;
      }
      return f;
    }

    var seen = {};
    for (var i = 0; i < devs.length; i++) {
      var fd = devs[i];
      if (seen[fd]) { failures.push("device fd " + fd + ": duplicate"); continue; }
      seen[fd] = true;
      var f = file(fd, "device");
      if (!f) continue;
      var ops = read8(at(f, 8), "device fd " + fd + " f_ops");
      if (!samePointer(ops, input.dtab)) failures.push("device fd " + fd + ": f_ops not cloned");
      else checked.devices++;
    }

    var noteBefore = input.noteBefore;
    for (var j = 0; j < queues.length; j++) {
      var qfd = queues[j];
      if (seen[qfd]) { failures.push("queue fd " + qfd + ": duplicate"); continue; }
      seen[qfd] = true;
      var qfile = file(qfd, "queue");
      if (!qfile) continue;
      var qops = read8(at(qfile, 8), "queue fd " + qfd + " f_ops");
      if (!samePointer(qops, input.qtab)) failures.push("queue fd " + qfd + ": f_ops not cloned");
      else checked.queues++;

      var kq = read8(qfile, "queue fd " + qfd + " f_data");
      if (!kq) continue;
      if (!inHeap(kq)) {
        failures.push("queue fd " + qfd + ": f_data pointer outside heap");
        continue;
      }
      var before = noteBefore[qfd];
      if (!before || !Number.isInteger(before.low) || !Number.isInteger(before.hi)) {
        failures.push("queue fd " + qfd + ": missing note preimage");
        continue;
      }
      var note = read8(at(kq, 0xa0), "queue fd " + qfd + " note");
      if (!note) continue;
      if ((note.low >>> 0) !== (before.low >>> 0) || (note.hi >>> 0) !== 0)
        failures.push("queue fd " + qfd + ": note list not neutralized");
      else checked.notes++;
    }

    if (checked.devices !== devs.length) failures.push("device coverage incomplete");
    if (checked.queues !== queues.length) failures.push("queue coverage incomplete");
    if (checked.notes !== queues.length) failures.push("note coverage incomplete");
    if (checked.tables !== 2) failures.push("table coverage incomplete");
    return { ok: failures.length === 0, failures: failures, checked: checked };
  }

  return { TABLE_LENGTH: TABLE_LENGTH, CLOSE_OFFSET: CLOSE_OFFSET,
    expectedTable: expectedTable, verify: verify };
});
