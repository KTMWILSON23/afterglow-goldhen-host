const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

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
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(site, relative)))
    .digest("hex");
}

const expectedFiles = [
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

assert.deepEqual(listFiles(site), expectedFiles, "published site must contain exactly nine files");

const expectedHashes = {
  "chain/afterglow.js": "96211b18461f74b51938b9a6051ce98bb81ff8ee59888d16bfdccaad3b77503c",
  "chain/core.js": "851649fce41c80c8c44fb1d1b022e3f6e95caeb1660b4f85a953a1b1dd3202cf",
  "chain/int64.js": "15181de17bb63f316f10c0e1ce8cb6341111a23016c1047af4456d47f4896c52",
  "chain/jb.js": "ce0e2283856cd813e39b711ffc6819a8fb3e71674e0391a4cb819e9b81583b19",
  "chain/mem.js": "e58704779bc896cf25c371181f7986d368918d4198a7f30d8d8a947b5fafc08b",
  "chain/ps4_offsets.js": "249dbf616df7366cc38f98b429fa7d1f410b5e2984d4cbfccf623429c5937837",
  "goldhen.bin": "c5480587d99efc2e3cc132352d9b7cf052dd3068280f1686e7fbb37d57e9ba8b",
};

for (const [file, expected] of Object.entries(expectedHashes)) {
  assert.equal(sha256(file), expected, `${file} must match the proven pinned build`);
}

assert.equal(fs.statSync(path.join(site, "goldhen.bin")).size, 298776);

const index = fs.readFileSync(path.join(site, "index.html"), "utf8");
const launch = fs.readFileSync(path.join(site, "launch.html"), "utf8");
const jb = fs.readFileSync(path.join(site, "chain/jb.js"), "utf8");
const afterglow = fs.readFileSync(path.join(site, "chain/afterglow.js"), "utf8");

assert.match(index, /XXFWilson23/);
assert.match(index, /sessionStorage\.setItem\("payload_path", "\.\/goldhen\.bin"\)/);
assert.match(index, /launch\.html\?mode=goldhen&afterglow=run&fw=1402/);
assert.doesNotMatch(index + launch, /WebKitty/i, "upstream branding leaked into the public interface");
assert.doesNotMatch(index + launch, /(?:src|href)=["']https?:\/\/(?!github\.com\/KTMWILSON23\/afterglow-goldhen-host)/i,
  "public interface has an unexpected remote dependency");

for (const id of ["state", "console", "DebugConsole", "out", "ramBox"]) {
  assert.match(launch, new RegExp(`id=["']${id}["']`), `launch page is missing #${id}`);
}

const globalIndex = launch.indexOf("window.isPayloadElf");
const moduleIndex = launch.indexOf('type="module"');
assert.ok(globalIndex >= 0 && moduleIndex > globalIndex, "required global must exist before module load");
assert.match(launch, /src="\.\/chain\/jb\.js"/);
assert.match(launch, /enabler running/);
assert.match(jb, /file === "" \|\| file === "index\.html"/);
assert.match(afterglow, /padding:\s+0xB3A298/);

console.log("Minimal XXFWilson23 host verified: 9 files, pinned chain, stock GoldHEN payload.");
