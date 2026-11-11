(function (root, factory) {
  "use strict";

  var api = factory();
  if (typeof module === "object" && module && module.exports) module.exports = api;
  if (root) root.Afterglow1402Preflight = api;
})(typeof window !== "undefined" ? window : this, function () {
  "use strict";

  /*
   * This module only classifies bytes supplied by its caller. It deliberately
   * contains no exploit, syscall, fetch, memory-write, or payload-launch path.
   * A live reader may be connected only after the host has a genuinely safe
   * way to obtain kernel bytes and clean up without patching the kernel.
   */

  var STATIC_SITES = [
    {
      id: "bootstrap-mmap-maxprot",
      group: "bootstrap",
      rva: 0x00000490,
      stock: "ffffffff498b8740",
      final: "00000000498b8740",
      label: "sys_mmap maximum protection",
    },
    {
      id: "bootstrap-mmap-branches-a",
      group: "bootstrap",
      rva: 0x000004b5,
      stock: "721385c9750f483b",
      final: "eb0085c9eb00483b",
      label: "sys_mmap protection branches A",
    },
    {
      id: "bootstrap-mmap-branches-b",
      group: "bootstrap",
      rva: 0x000004b9,
      stock: "750f483b90f00000",
      final: "eb00483b90f00000",
      label: "sys_mmap protection branches B",
    },
    {
      id: "bootstrap-mmap-branch-c",
      group: "bootstrap",
      rva: 0x000004c2,
      stock: "7269eb0485c97463",
      final: "eb69eb0485c97463",
      label: "sys_mmap protection branch C",
    },
    {
      id: "bootstrap-syscall-gate",
      group: "bootstrap",
      rva: 0x00000ab4,
      stock: "9090909090909090",
      final: "ff26909090909090",
      label: "unused syscall gate",
    },
    {
      id: "bootstrap-mmap-prot-immediates",
      group: "bootstrap",
      rva: 0x001faeda,
      stock: "3341b23331c04531",
      final: "3741b23731c04531",
      label: "sys_mmap protection immediates",
    },
    {
      id: "bootstrap-mmap-prot-immediate-second",
      group: "bootstrap",
      rva: 0x001faedd,
      stock: "3331c04531f64531",
      final: "3731c04531f64531",
      label: "second sys_mmap protection immediate",
    },
    {
      id: "sysent11-narg",
      group: "bootstrap",
      rva: 0x01102d80,
      stock: "00000000",
      final: "02000000",
      label: "sysent[11].sy_narg",
    },
    {
      id: "sysent11-byte4",
      group: "bootstrap",
      rva: 0x01102d84,
      stock: "00000000",
      final: "00000000",
      label: "sysent[11] unchanged bytes 4 to 7",
    },
    {
      id: "sysent11-byte16",
      group: "bootstrap",
      rva: 0x01102d90,
      stock: "0000000000000000",
      final: "0000000000000000",
      label: "sysent[11] unchanged bytes 16 to 23",
    },
    {
      id: "sysent11-byte24",
      group: "bootstrap",
      rva: 0x01102d98,
      stock: "0000000000000000",
      final: "0000000000000000",
      label: "sysent[11] unchanged bytes 24 to 31",
    },
    {
      id: "sysent11-byte32",
      group: "bootstrap",
      rva: 0x01102da0,
      stock: "0000000000000000",
      final: "0000000000000000",
      label: "sysent[11] unchanged bytes 32 to 39",
    },
    {
      id: "sysent11-byte40",
      group: "bootstrap",
      rva: 0x01102da8,
      stock: "00000000",
      final: "00000000",
      label: "sysent[11] unchanged bytes 40 to 43",
    },
    {
      id: "sysent11-thrcnt",
      group: "bootstrap",
      rva: 0x01102dac,
      stock: "04000000",
      final: "01000000",
      label: "sysent[11].sy_thrcnt",
    },

    {
      id: "patch-bcopy",
      group: "patches",
      rva: 0x00000acd,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "bcopy",
    },
    {
      id: "patch-bzero",
      group: "patches",
      rva: 0x002bda9d,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "bzero",
    },
    {
      id: "patch-pagezero",
      group: "patches",
      rva: 0x002bdae1,
      stock: "761b4989ea4983c2",
      final: "eb1b4989ea4983c2",
      label: "pagezero",
    },
    {
      id: "patch-memcpy",
      group: "patches",
      rva: 0x002bdb5d,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "memcpy",
    },
    {
      id: "patch-pagecopy",
      group: "patches",
      rva: 0x002bdba1,
      stock: "761b4989ea4983c2",
      final: "eb1b4989ea4983c2",
      label: "pagecopy",
    },
    {
      id: "patch-copyin",
      group: "patches",
      rva: 0x002bdd4d,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "copyin",
    },
    {
      id: "patch-copyinstr",
      group: "patches",
      rva: 0x002be1fd,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "copyinstr",
    },
    {
      id: "patch-copystr",
      group: "patches",
      rva: 0x002be2cd,
      stock: "76174989ea4983c2",
      final: "eb174989ea4983c2",
      label: "copystr",
    },
    {
      id: "patch-dlsym-check-1",
      group: "patches",
      rva: 0x001b7c63,
      stock: "0f850b020000488b",
      final: "eb040b020000488b",
      label: "dlsym first check",
    },
    {
      id: "patch-dlsym-check-2",
      group: "patches",
      rva: 0x001b7c73,
      stock: "0f84fb010000493b",
      final: "eb04fb010000493b",
      label: "dlsym second check",
    },
    {
      id: "patch-dlsym-jump",
      group: "patches",
      rva: 0x001b7c93,
      stock: "0f8481010000bf10",
      final: "90e981010000bf10",
      label: "dlsym nop and jump",
    },
    {
      id: "patch-load-prx",
      group: "patches",
      rva: 0x001b7724,
      stock: "0f84c00000004c8d",
      final: "90e9c00000004c8d",
      label: "load_prx",
    },
    {
      id: "patch-dlsym-all-callers",
      group: "patches",
      rva: 0x001b7cd8,
      stock: "0f8239010000488b",
      final: "90e93c010000488b",
      label: "dlsym all callers",
    },
    {
      id: "patch-self-verification",
      group: "patches",
      rva: 0x00628b04,
      stock: "74074883c4085b5d",
      final: "eb004883c4085b5d",
      label: "self verification",
    },
    {
      id: "patch-delayed-panic",
      group: "patches",
      rva: 0x006293ef,
      stock: "7541488d3df87403",
      final: "eb00488d3df87403",
      label: "delayed panic on suspend",
    },
  ];

  var DYNAMIC_SITE = {
    id: "sysent11-call",
    group: "bootstrap",
    rva: 0x01102d88,
    stockRva: 0x001c07a0,
    finalRva: 0x00000ab4,
    length: 8,
    label: "sysent[11].sy_call",
  };

  function cleanHex(value) {
    if (typeof value !== "string") return null;
    var out = value.toLowerCase().replace(/^0x/, "").replace(/[\s:_-]/g, "");
    if (!/^[0-9a-f]*$/.test(out)) return null;
    return out.length % 2 === 0 ? out : null;
  }

  function byteLength(hex) {
    return hex.length / 2;
  }

  function pair(value) {
    if (value && typeof value === "object") {
      var low = value.low;
      var hi = value.hi;
      if (low === undefined) low = value.lo;
      if (hi === undefined) hi = value.high;
      if (typeof low === "number" && typeof hi === "number") {
        return { low: low >>> 0, hi: hi >>> 0 };
      }
    }
    if (typeof value === "string") {
      var hex = cleanHex(value);
      if (!hex || hex.length > 16) return null;
      hex = ("0000000000000000" + hex).slice(-16);
      return {
        low: parseInt(hex.slice(8), 16) >>> 0,
        hi: parseInt(hex.slice(0, 8), 16) >>> 0,
      };
    }
    return null;
  }

  function add32(value, amount) {
    var before = value.low >>> 0;
    var low = (before + (amount >>> 0)) >>> 0;
    return { low: low, hi: ((value.hi >>> 0) + (low < before ? 1 : 0)) >>> 0 };
  }

  function pairHexLE(value) {
    var bytes = [];
    var parts = [value.low >>> 0, value.hi >>> 0];
    for (var p = 0; p < parts.length; p++) {
      var n = parts[p];
      for (var i = 0; i < 4; i++) {
        bytes.push(("0" + ((n >>> (i * 8)) & 0xff).toString(16)).slice(-2));
      }
    }
    return bytes.join("");
  }

  function expectedHex(site, state, kbase) {
    if (site.id !== DYNAMIC_SITE.id) return site[state] || null;
    var base = pair(kbase);
    if (!base) return null;
    return pairHexLE(add32(base, state === "stock" ? site.stockRva : site.finalRva));
  }

  function actualHex(value) {
    if (typeof value === "string") return cleanHex(value);
    if (!value || typeof value.length !== "number") return null;
    var out = [];
    for (var i = 0; i < value.length; i++) {
      var n = Number(value[i]);
      if (!isFinite(n) || n < 0 || n > 255 || Math.floor(n) !== n) return null;
      out.push(("0" + n.toString(16)).slice(-2));
    }
    return out.join("");
  }

  function cloneSite(site) {
    var out = {};
    for (var key in site) {
      if (Object.prototype.hasOwnProperty.call(site, key)) out[key] = site[key];
    }
    return typeof Object.freeze === "function" ? Object.freeze(out) : out;
  }

  function sites() {
    var out = [];
    for (var i = 0; i < STATIC_SITES.length; i++) out.push(cloneSite(STATIC_SITES[i]));
    var nargAt = -1;
    for (var j = 0; j < out.length; j++) {
      if (out[j].id === "sysent11-narg") { nargAt = j; break; }
    }
    if (nargAt < 0) throw new Error("missing sysent[11] narg site");
    out.splice(nargAt + 1, 0, cloneSite(DYNAMIC_SITE));
    return out;
  }

  function getValue(source, site, length) {
    if (typeof source === "function") return source(site.rva, length, site);
    if (!source || typeof source !== "object") return null;
    if (Object.prototype.hasOwnProperty.call(source, site.id)) return source[site.id];
    var key = "0x" + site.rva.toString(16);
    if (Object.prototype.hasOwnProperty.call(source, key)) return source[key];
    return null;
  }

  function summarize(rows) {
    var counts = { stock: 0, final: 0, unchanged: 0, unknown: 0 };
    for (var i = 0; i < rows.length; i++) counts[rows[i].status]++;
    var state = "mixed";
    if (counts.unknown) state = "unknown";
    else if (counts.stock + counts.unchanged === rows.length) state = "all-stock";
    else if (counts.final + counts.unchanged === rows.length) state = "all-final";
    return { state: state, counts: counts, total: rows.length };
  }

  function evaluate(source, options) {
    options = options || {};
    var list = sites();
    var rows = [];

    for (var i = 0; i < list.length; i++) {
      var site = list[i];
      var stock = expectedHex(site, "stock", options.kbase);
      var final = expectedHex(site, "final", options.kbase);
      var length = site.length || (stock ? byteLength(stock) : 8);
      var got = null;
      var error = null;
      try {
        got = actualHex(getValue(source, site, length));
      } catch (caught) {
        error = "read-error: " + ((caught && caught.message) || caught);
      }

      var status = "unknown";
      if (!stock || !final) error = error || "kernel-base-required";
      else if (!got) error = error || "missing-or-invalid-bytes";
      else if (byteLength(got) !== length) error = "wrong-length";
      else if (got === stock && stock === final) status = "unchanged";
      else if (got === stock) status = "stock";
      else if (got === final) status = "final";
      else error = "unexpected-bytes";

      rows.push({
        id: site.id,
        group: site.group,
        rva: site.rva,
        length: length,
        label: site.label,
        status: status,
        actual: got,
        stock: stock,
        final: final,
        error: error,
      });
    }

    var bootstrap = [];
    var patches = [];
    for (var j = 0; j < rows.length; j++) {
      (rows[j].group === "bootstrap" ? bootstrap : patches).push(rows[j]);
    }

    return {
      state: summarize(rows).state,
      counts: summarize(rows).counts,
      total: rows.length,
      groups: {
        bootstrap: summarize(bootstrap),
        patches: summarize(patches),
      },
      sites: rows,
      safeToWrite: false,
    };
  }

  return {
    version: "1402-preflight-v1",
    sites: sites,
    expectedHex: expectedHex,
    evaluate: evaluate,
  };
});
