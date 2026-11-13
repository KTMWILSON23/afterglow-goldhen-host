/* Pure checks for the offline 14.02 read-only snapshot. No console I/O here. */
export const SYSENT_RVA = 0x1102b70;
export const SYSENT_RECORD_SIZE = 0x30;
export const SYSENT_COPY_SIZE = 592 * SYSENT_RECORD_SIZE;
export const TEXT_SIZE_1402 = 0xcfe9a0;
/* 14.02 ELF program header 3: the live sysent interval is inside this map. */
export const TABLE_SEGMENT_RVA = 0x10ff000;
export const TABLE_SEGMENT_SIZE = 0x200000;
export const SYSCALL_NUMBERS = Object.freeze([
  11, 197, 198, 199, 200, 201, 384, 385, 386, 387, 388, 389,
  394, 409, 410, 411, 500, 591,
]);
export const HANDLER_NUMBERS = Object.freeze([
  384, 385, 386, 387, 388, 389, 394, 409, 410, 411,
]);

function qword(view, offset) {
  return { low: view.getUint32(offset, true), hi: view.getUint32(offset + 4, true) };
}

function same(a, b) {
  return a.low === b.low && a.hi === b.hi;
}

function add32(base, value) {
  const low = (base.low + value) >>> 0;
  return { low, hi: (base.hi + (low < base.low ? 1 : 0)) >>> 0 };
}

function sub32(pointer, base) {
  const low = (pointer.low - base.low) >>> 0;
  const hi = (pointer.hi - base.hi - (pointer.low < base.low ? 1 : 0)) >>> 0;
  return hi === 0 ? low : null;
}

export function hexBytes(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; ++i)
    out += ("0" + bytes[i].toString(16)).slice(-2);
  return out;
}

export function checksumText(value) {
  let hash = 2166136261 >>> 0;
  for (let i = 0; i < value.length; ++i) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return ("00000000" + hash.toString(16)).slice(-8);
}

export function baseHex(base) {
  return "0x" + ("00000000" + base.hi.toString(16)).slice(-8) +
    ("00000000" + base.low.toString(16)).slice(-8);
}

export function parseBaseHex(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{16}$/.test(value)) return null;
  return { hi: parseInt(value.slice(2, 10), 16), low: parseInt(value.slice(10), 16) };
}

/* Bounded read-only evidence for a shot-1 miss. No full leak or absolute
   pointer is included in the checkpoint; a separate digest distinguishes
   captures with the same counts. */
export function summarizeLeak(bytes, anchor) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 0x4000 ||
      !Number.isInteger(anchor) || anchor <= 0 || anchor >= 0x2000000) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let nonzeroBytes = 0, kernelPointers = 0, quartets = 0, alignedQuartets = 0;
  let firstQuartetOffset = -1, firstQuartetBase = null;
  const votes = new Map(), quartetBases = new Set();
  for (let i = 0; i < bytes.length; ++i) if (bytes[i] !== 0) ++nonzeroBytes;
  for (let off = 0; off <= bytes.length - 8; off += 8) {
    const a = qword(view, off);
    if (a.hi !== 0xffffffff) continue;
    ++kernelPointers;
    if (a.low !== 0xffffffff &&
        (a.low & 0x3fff) === (anchor & 0x3fff)) {
      const candidate = (a.low - anchor) >>> 0;
      if ((candidate & 0x3fff) === 0)
        votes.set(candidate, (votes.get(candidate) || 0) + 1);
    }
    if (off > bytes.length - 0x20) continue;
    const b = qword(view, off + 8), c = qword(view, off + 16), d = qword(view, off + 24);
    if (b.hi !== 0xffffffff || c.hi !== 0xffffffff || d.hi !== 0xffffffff ||
        ((b.low - a.low) >>> 0) !== 0x20 ||
        ((c.low - a.low) >>> 0) !== 0x40 ||
        ((d.low - a.low) >>> 0) !== 0x50) continue;
    ++quartets;
    const base = (a.low - anchor) >>> 0;
    quartetBases.add(base);
    if ((base & 0x3fff) === 0) ++alignedQuartets;
    if (firstQuartetOffset < 0) {
      firstQuartetOffset = off;
      firstQuartetBase = base;
    }
  }
  let topVotes = 0, secondVotes = 0, topBase = null;
  for (const [base, count] of votes) {
    if (count > topVotes) {
      secondVotes = topVotes; topVotes = count; topBase = base;
    } else if (count > secondVotes) secondVotes = count;
  }
  return { nonzeroBytes, kernelPointers, quartets, alignedQuartets,
    distinctQuartetBases: quartetBases.size,
    firstQuartetOffset, firstQuartetBase, voteCandidates: votes.size,
    topVotes, secondVotes, topBase };
}

export function leakSummaryDetail(observed, shaPrefix) {
  if (!observed || typeof shaPrefix !== "string" ||
      !/^[0-9a-f]{16}$/.test(shaPrefix)) return null;
  const briefHex = (value) => value === null ? "none" : value.toString(16);
  const detail = "unverified nz=" + observed.nonzeroBytes +
    " kp=" + observed.kernelPointers + " q=" + observed.quartets +
    "/" + observed.alignedQuartets + " dq=" +
    observed.distinctQuartetBases + " qoff=" +
    briefHex(observed.firstQuartetOffset < 0 ? null : observed.firstQuartetOffset) +
    " qb=" + briefHex(observed.firstQuartetBase) +
    " vc=" + observed.voteCandidates + " votes=" +
    observed.topVotes + "/" + observed.secondVotes +
    " vb=" + briefHex(observed.topBase) + " sha=" + shaPrefix;
  return detail.length <= 160 ? detail : null;
}

/* Require the two leak interpretations to agree before the next kernel read. */
export function deriveBaseFromLeak(bytes, anchor) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 0x4000 ||
      !Number.isInteger(anchor) || anchor <= 0 || anchor >= 0x2000000) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let found = null;
  for (let off = 0; off <= bytes.length - 0x20; off += 8) {
    const a = qword(view, off);
    if (a.hi !== 0xffffffff) continue;
    const b = qword(view, off + 8), c = qword(view, off + 16), d = qword(view, off + 24);
    if (b.hi !== 0xffffffff || c.hi !== 0xffffffff || d.hi !== 0xffffffff ||
        ((b.low - a.low) >>> 0) !== 0x20 ||
        ((c.low - a.low) >>> 0) !== 0x40 ||
        ((d.low - a.low) >>> 0) !== 0x50) continue;
    if (found && !same(found, a)) return null;
    found = a;
  }
  if (!found) return null;

  const votes = new Map();
  for (let off = 0; off <= bytes.length - 8; off += 8) {
    const a = qword(view, off);
    if (a.hi !== 0xffffffff || a.low === 0xffffffff ||
        (a.low & 0x3fff) !== (anchor & 0x3fff)) continue;
    const candidate = (a.low - anchor) >>> 0;
    if ((candidate & 0x3fff) === 0)
      votes.set(candidate, (votes.get(candidate) || 0) + 1);
  }
  let top = -1, count = 0, tied = false;
  for (const [candidate, n] of votes) {
    if (n > count) { top = candidate; count = n; tied = false; }
    else if (n === count) tied = true;
  }
  if (count === 0 || tied) return null;
  const base = { low: (found.low - anchor) >>> 0,
    hi: (found.hi - (found.low < anchor ? 1 : 0)) >>> 0 };
  if ((base.low & 0x3fff) !== 0 || base.hi !== 0xffffffff || top !== base.low)
    return null;
  return base;
}

export function validateKernelHeader(bytes, base) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 0x190 || !base ||
      base.hi !== 0xffffffff || (base.low & 0x3fff) !== 0) return false;
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (d.getUint32(0, true) !== 0x464c457f || bytes[4] !== 2 || bytes[5] !== 1 ||
      d.getUint16(16, true) !== 2 || d.getUint16(18, true) !== 62 ||
      d.getUint32(20, true) !== 1 || d.getUint32(32, true) !== 0x40 ||
      d.getUint32(36, true) !== 0 || d.getUint16(54, true) !== 56 ||
      d.getUint16(56, true) !== 6) return false;
  let textLoads = 0, tableMaps = 0;
  for (let i = 0; i < 6; ++i) {
    const at = 0x40 + i * 56;
    const type = d.getUint32(at, true), flags = d.getUint32(at + 4, true);
    if (type === 0x61000010 && flags === 4 &&
        d.getUint32(at + 8, true) === 0xcff000 &&
        d.getUint32(at + 12, true) === 0 &&
        same(qword(d, at + 16), add32(base, TABLE_SEGMENT_RVA)) &&
        d.getUint32(at + 32, true) === 0x20cc0 &&
        d.getUint32(at + 36, true) === 0 &&
        d.getUint32(at + 40, true) === TABLE_SEGMENT_SIZE &&
        d.getUint32(at + 44, true) === 0 &&
        SYSENT_RVA >= TABLE_SEGMENT_RVA &&
        SYSENT_RVA + SYSENT_COPY_SIZE <= TABLE_SEGMENT_RVA + TABLE_SEGMENT_SIZE)
      ++tableMaps;
    if (type !== 1 || (flags & 1) === 0) continue;
    if (flags !== 5 || d.getUint32(at + 8, true) !== 0 ||
        d.getUint32(at + 12, true) !== 0 ||
        !same(qword(d, at + 16), base) ||
        d.getUint32(at + 32, true) !== TEXT_SIZE_1402 ||
        d.getUint32(at + 36, true) !== 0 ||
        d.getUint32(at + 40, true) !== TEXT_SIZE_1402 ||
        d.getUint32(at + 44, true) !== 0) return false;
    ++textLoads;
  }
  return textLoads === 1 && tableMaps === 1;
}

export function parseSysent(table, base) {
  if (!(table instanceof Uint8Array) || table.length !== SYSENT_COPY_SIZE || !base)
    return null;
  const view = new DataView(table.buffer, table.byteOffset, table.byteLength);
  const records = [], handlerPlan = [];
  for (const number of SYSCALL_NUMBERS) {
    const at = number * SYSENT_RECORD_SIZE;
    const bytes = table.subarray(at, at + SYSENT_RECORD_SIZE);
    const target = qword(view, at + 8);
    const rva = sub32(target, base);
    if (target.hi !== 0xffffffff || rva === null || rva > TEXT_SIZE_1402 - 14)
      return null;
    records.push({ number, bytes: hexBytes(bytes) });
    if (HANDLER_NUMBERS.includes(number)) handlerPlan.push({ number, rva, target });
  }
  return { records, handlerPlan };
}

export function makeManifest(run, base, parsed, prologues, now) {
  if (!/^[a-z0-9-]{8,64}$/.test(run) || !base || !parsed ||
      !Array.isArray(prologues) || prologues.length !== HANDLER_NUMBERS.length)
    return null;
  const handlers = [];
  for (let i = 0; i < prologues.length; ++i) {
    const bytes = prologues[i];
    if (!(bytes instanceof Uint8Array) || bytes.length !== 14 ||
        bytes.every((b) => b === 0) || bytes.every((b) => b === 0xcc)) return null;
    handlers.push({ number: parsed.handlerPlan[i].number,
      rva: parsed.handlerPlan[i].rva, bytes: hexBytes(bytes) });
  }
  const body = {
    version: 1, firmware: "14.02", run, created: now,
    kernelBase: baseHex(base), textSize: TEXT_SIZE_1402, shotCount: 3,
    records: parsed.records, handlers,
  };
  return { ...body, checksum: checksumText(JSON.stringify(body)) };
}

/* Save the stock table before the third, independent handler read shot. */
export function makeTableSnapshot(run, base, parsed, now) {
  if (!/^[a-z0-9-]{8,64}$/.test(run) || !base || !parsed ||
      !Array.isArray(parsed.records) || parsed.records.length !== SYSCALL_NUMBERS.length ||
      !Array.isArray(parsed.handlerPlan) || parsed.handlerPlan.length !== HANDLER_NUMBERS.length)
    return null;
  const body = {
    version: 1, firmware: "14.02", run, created: now,
    kernelBase: baseHex(base), textSize: TEXT_SIZE_1402, shotCount: 2,
    records: parsed.records,
  };
  const value = { ...body, checksum: checksumText(JSON.stringify(body)) };
  return validateTableSnapshot(value) ? value : null;
}

/* Complete 592-entry table, private PC export. The selected 18 records bind it
   to the already-saved partial snapshot from this same run and live base. */
export function makeRawTable(partial, table, sha256, now) {
  if (!validateTableSnapshot(partial) || !(table instanceof Uint8Array) ||
      table.length !== SYSENT_COPY_SIZE || !/^[0-9a-f]{64}$/.test(sha256 || ""))
    return null;
  const body = { version: 1, firmware: "14.02", run: partial.run,
    created: now, kernelBase: partial.kernelBase, tableRva: SYSENT_RVA,
    byteLength: SYSENT_COPY_SIZE, sha256, partial,
    tableHex: hexBytes(table) };
  const value = { ...body, checksum: checksumText(JSON.stringify(body)) };
  return validateRawTable(value) ? value : null;
}

export function validateRawTable(value) {
  if (!value || value.version !== 1 || value.firmware !== "14.02" ||
      !validateTableSnapshot(value.partial) || value.run !== value.partial.run ||
      value.kernelBase !== value.partial.kernelBase ||
      !Number.isSafeInteger(value.created) || value.created < value.partial.created ||
      value.tableRva !== SYSENT_RVA || value.byteLength !== SYSENT_COPY_SIZE ||
      !/^[0-9a-f]{64}$/.test(value.sha256 || "") ||
      typeof value.tableHex !== "string" ||
      !/^[0-9a-f]+$/.test(value.tableHex) ||
      value.tableHex.length !== SYSENT_COPY_SIZE * 2) return false;
  for (const record of value.partial.records) {
    const at = record.number * SYSENT_RECORD_SIZE * 2;
    if (value.tableHex.slice(at, at + SYSENT_RECORD_SIZE * 2) !== record.bytes)
      return false;
  }
  const { checksum, ...body } = value;
  return checksum === checksumText(JSON.stringify(body));
}

function validRecords(records, base) {
  if (!Array.isArray(records) || records.length !== SYSCALL_NUMBERS.length) return false;
  for (let i = 0; i < records.length; ++i) {
    const record = records[i];
    if (!record || record.number !== SYSCALL_NUMBERS[i] ||
        typeof record.bytes !== "string" || !/^[0-9a-f]{96}$/.test(record.bytes)) return false;
    const raw = new Uint8Array(record.bytes.match(/../g).map((x) => parseInt(x, 16)));
    const target = qword(new DataView(raw.buffer), 8), rva = sub32(target, base);
    if (target.hi !== 0xffffffff || rva === null || rva > TEXT_SIZE_1402 - 14)
      return false;
  }
  return true;
}

export function validateTableSnapshot(value) {
  if (!value || typeof value !== "object" || value.version !== 1 ||
      value.firmware !== "14.02" || !/^[a-z0-9-]{8,64}$/.test(value.run || "") ||
      !Number.isSafeInteger(value.created) || value.created < 1 ||
      value.textSize !== TEXT_SIZE_1402 || value.shotCount !== 2 ||
      Object.prototype.hasOwnProperty.call(value, "handlers")) return false;
  const base = parseBaseHex(value.kernelBase);
  if (!base || base.hi !== 0xffffffff || (base.low & 0x3fff) !== 0 ||
      !validRecords(value.records, base)) return false;
  const { checksum, ...body } = value;
  return checksum === checksumText(JSON.stringify(body));
}

export function validateManifest(value) {
  if (!value || typeof value !== "object" || value.version !== 1 ||
      value.firmware !== "14.02" || !/^[a-z0-9-]{8,64}$/.test(value.run || "") ||
      !Number.isSafeInteger(value.created) || value.created < 1 ||
      value.textSize !== TEXT_SIZE_1402 || value.shotCount !== 3 ||
      !Array.isArray(value.records) || value.records.length !== SYSCALL_NUMBERS.length ||
      !Array.isArray(value.handlers) || value.handlers.length !== HANDLER_NUMBERS.length)
    return false;
  const base = parseBaseHex(value.kernelBase);
  if (!base || base.hi !== 0xffffffff || (base.low & 0x3fff) !== 0) return false;
  if (!validRecords(value.records, base)) return false;
  for (let i = 0; i < value.handlers.length; ++i) {
    const h = value.handlers[i];
    if (!h || h.number !== HANDLER_NUMBERS[i] ||
        !Number.isInteger(h.rva) || h.rva < 0 || h.rva > TEXT_SIZE_1402 - 14 ||
        typeof h.bytes !== "string" || !/^[0-9a-f]{28}$/.test(h.bytes)) return false;
    const record = value.records[SYSCALL_NUMBERS.indexOf(h.number)];
    const raw = new Uint8Array(record.bytes.match(/../g).map((x) => parseInt(x, 16)));
    const d = new DataView(raw.buffer);
    if (!same(qword(d, 8), add32(base, h.rva))) return false;
  }
  const { checksum, ...body } = value;
  return checksum === checksumText(JSON.stringify(body));
}
