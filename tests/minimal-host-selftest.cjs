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
  let content = fs.readFileSync(path.join(site, relative));
  if (relative.endsWith(".js")) {
    content = Buffer.from(content.toString("utf8").replace(/\r\n/g, "\n"));
  }
  return crypto.createHash("sha256")
    .update(content)
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
