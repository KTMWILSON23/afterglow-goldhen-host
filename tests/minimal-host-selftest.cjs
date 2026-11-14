const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const site = path.join(root, "site");

function slash(value) {
  return value.split(path.sep).join("/");
}

function listFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const full = path.join(directory, entry.name);
      return entry.isDirectory() ? listFiles(full) : [slash(path.relative(site, full))];
    })
    .sort();
}

function sha256(relative) {
  let content = fs.readFileSync(path.join(site, relative));
  if (relative.endsWith(".js")) {
    content = Buffer.from(content.toString("utf8").replace(/\r\n/g, "\n"));
  }
  return crypto.createHash("sha256")
    .update(content)
    .digest("hex");
}

const expectedFiles = [
  "cache.html",
  "cache.manifest",
  "chain/afterglow.js",
  "chain/core.js",
  "chain/int64.js",
  "chain/jb.js",
  "chain/mem.js",
  "chain/ps4_offsets.js",
  "goldhen.bin",
  "index.html",
  "launch.html",
].sort();

assert.deepEqual(listFiles(site), expectedFiles, "published site must contain exactly eleven files");

const expectedHashes = {
  "chain/afterglow.js": "4227ea3e0fe2bf25017c6ca1f02a2b79ce423039a39f9765438e9c8144f75cc3",
  "chain/core.js": "34797091b327536e9118abd167215a7d669a62f23fc0f8c0aebb5c6373c24fa4",
  "chain/int64.js": "611da6a52da5ecf970a3718ab2a4561d3992c655c55342d066d12a9a50554f34",
  "chain/jb.js": "e8c844d5959056aa272b3d98e64468c0a54f6780e7bb1f411f483cb35129da74",
  "chain/mem.js": "71f700963b0fd2da1fd877122561a343507eb71050451a376daaeaf4f71f1da0",
  "chain/ps4_offsets.js": "23550c806225c714a3b9fb7a22faf0ba4c5fabf07153712930629252072e14eb",
  "goldhen.bin": "c5480587d99efc2e3cc132352d9b7cf052dd3068280f1686e7fbb37d57e9ba8b",
};

for (const [file, expected] of Object.entries(expectedHashes)) {
  assert.equal(sha256(file), expected, `${file} must match the proven pinned build`);
}

assert.equal(fs.statSync(path.join(site, "goldhen.bin")).size, 298776);

const index = fs.readFileSync(path.join(site, "index.html"), "utf8");
const launch = fs.readFileSync(path.join(site, "launch.html"), "utf8");
const cachePage = fs.readFileSync(path.join(site, "cache.html"), "utf8");
const cacheManifest = fs.readFileSync(path.join(site, "cache.manifest"), "utf8").replace(/\r\n/g, "\n");
const jb = fs.readFileSync(path.join(site, "chain/jb.js"), "utf8");
const afterglow = fs.readFileSync(path.join(site, "chain/afterglow.js"), "utf8");

assert.match(index, /XXFWilson23/);
assert.match(index, /sessionStorage\.setItem\("payload_path", "\.\/goldhen\.bin"\)/);
assert.match(index, /launch\.html\?mode=goldhen&afterglow=run&fw=1402/);
assert.doesNotMatch(index + launch + cachePage, /WebKitty/i, "upstream branding leaked into the public interface");
const externalUrls = [...(index + launch + cachePage).matchAll(/(?:src|href)=["'](https?:\/\/[^"']+)/gi)]
  .map((match) => match[1])
  .sort();
assert.deepEqual(externalUrls, [
  "https://discord.gg/gvd6nz8kQ4",
  "https://github.com/KTMWILSON23/afterglow-goldhen-host",
  "https://youtube.com/@XXFWilson23",
]);
assert.match(index, /class="social-icon youtube"/);
assert.match(index, /class="social-icon discord"/);
assert.match(index, /aria-label="Open XXFWilson23 on YouTube"/);
assert.match(index, /aria-label="Join the XXFWilson23 Discord"/);
assert.match(index, /PlayStation 4/);
assert.match(index, /location\.replace\("\.\/cache\.html"\)/);
assert.doesNotMatch(index, /<html[^>]+manifest=/i, "landing page must not start an AppCache update itself");
assert.match(cachePage, /<html[^>]+manifest="\.\/cache\.manifest"/i);
assert.doesNotMatch(launch, /<html[^>]+manifest=|swapCache|location\.reload/i,
  "exploit page must not install or activate a cache update");
assert.doesNotMatch(launch, /<script[^>]+type=["']module["'][^>]+src=/i,
  "exploit module must wait until any AppCache work has stopped");
assert.match(launch, /applicationCache/);
assert.match(launch, /appCache\.abort\(\)/);
assert.match(launch, /import\("\.\/chain\/jb\.js"\)/);
assert.match(cachePage, /appCache\.abort\(\)/);
assert.doesNotMatch(cachePage, /<script[^>]+src=|<iframe|chain\//i,
  "cache installer must not import exploit code");

assert.match(cacheManifest, /^CACHE MANIFEST\n/);
assert.match(cacheManifest, /# XXFWilson23 offline cache 2026-11-14\.3/);
const cacheBlock = /\nCACHE:\n([\s\S]*?)\nNETWORK:\n\*\s*$/.exec(cacheManifest);
assert.ok(cacheBlock, "cache manifest must contain CACHE and NETWORK sections");
assert.deepEqual(cacheBlock[1].trim().split("\n"), [
  "./",
  "./index.html",
  "./cache.html",
  "./launch.html",
  "./launch.html?mode=goldhen&afterglow=run&fw=1402",
  "./goldhen.bin",
  "./chain/jb.js",
  "./chain/core.js",
  "./chain/mem.js",
  "./chain/int64.js",
  "./chain/ps4_offsets.js",
  "./chain/afterglow.js",
]);

for (const [name, html] of [["index", index], ["cache", cachePage], ["launch", launch]]) {
  const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)];
  for (const [at, script] of inlineScripts.entries()) {
    new vm.Script(script[1], { filename: `${name}-inline-${at}.js` });
  }
}

for (const id of ["state", "console", "DebugConsole", "out", "ramBox"]) {
  assert.match(launch, new RegExp(`id=["']${id}["']`), `launch page is missing #${id}`);
}

const globalIndex = launch.indexOf("window.isPayloadElf");
const moduleIndex = launch.indexOf('import("./chain/jb.js")');
assert.ok(globalIndex >= 0 && moduleIndex > globalIndex, "required global must exist before gated module load");
assert.match(launch, /enabler running/);
assert.match(jb, /file === "" \|\| file === "index\.html"/);
assert.match(afterglow, /padding:\s+0xB3A298/);

console.log("XXFWilson23 host verified: 11 files, offline cache, pinned chain, stock GoldHEN payload.");
