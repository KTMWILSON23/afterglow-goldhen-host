# PS4 14.02 core HEN host

This branch is an experimental PS4 14.02 host for one core HEN attempt per
clean boot. It runs the Afterglow kernel stage and then a SHA-256-pinned,
reduced HEN payload that installs the core FSELF/FPKG hooks.

It is not GoldHEN. It does not provide plugins, a debug menu, port 9090,
Remote Play patches, ShellUI patches, or the optional process/UI paths that
have not been validated for 14.02.

## What has been proved

- The browser exploit, guarded kernel writes, jailbreak, core payload copy,
  and `pthread_create` path ran on a 14.02 PS4.
- Two clean-boot runs created `/user/temp/hen.installed` after the inner
  `install_payload` function returned zero.
- The current payload is regenerated only from the pinned original image and
  an exact, verifier-checked patch script.
- The current payload SHA-256 is
  `1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239`.

The current revision still needs one hardware run because its SCE_RELA search
was tightened to the exact 14.02 `PT_DYNAMIC` span after those two successful
marker runs. An actual FPKG or homebrew launch has not yet been proved.

## Running locally

From this folder:

```powershell
python debug_server.py --bind 0.0.0.0 --port 8766 --peer 192.168.1.104
```

Then open `http://192.168.1.99:8766/` on the PS4. Change the bind, peer, or URL
if the PC or PS4 address changes.

The public static host is:

`https://ktmwilson23.github.io/afterglow-goldhen-host/`

The local server records checkpoints; GitHub Pages does not. Telemetry is not
part of the exploit or payload ABI, so a missing `/beacon` endpoint does not
block the launch.

## Attempt rules

- Start from a fully powered-off console.
- Press the launch button once.
- The host never starts a second HEN installer thread in the same run.
- It does not reload after kernel work begins.
- If success is not explicitly confirmed, fully power off before trying again.

The landing page can create a fresh token whenever its button is pressed; web
code cannot prove that a real cold boot occurred. The operator must enforce
the clean-boot requirement.

## Important files

| File | Purpose |
|---|---|
| `index.html`, `launch.js` | Manual one-attempt launcher and same-tab nonce |
| `launch.html`, `jb-g.js` | WebKit entry, runtime checks, and heap cleanup |
| `afterglow-g.js` | 14.02 kernel stage and one core-HEN pthread handoff |
| `hen-1402-core.bin` | Current SHA-256-pinned reduced payload |
| `tools/patch-debug-1402.py` | Exact patch generator and binary verifier |
| `hen-1402-core.manifest.json` | Machine-readable patch record and scope |
| `debug_server.py` | No-cache local host restricted to one PS4 peer |
| `ONE_SHOT_1402.md` | Hardware evidence and remaining validation boundary |

## Result meaning

`pthread_create` returning zero proves only that the thread was accepted. The
host waits for `/user/temp/hen.installed`; the payload creates that marker only
when `install_payload` returns zero. Even that marker does not independently
prove every installed hook or a later FPKG launch. The next useful validation
is a real FPKG or homebrew launch after the marker appears.

## License and use

This work is for security research on hardware the operator owns. Repository
source is licensed under the GNU Affero General Public License v3.0 or later.
