# PS4 14.02 corrected debug.bin experiment

This branch is an offline candidate based on Akatsuki commit
`689446d47fe1f3057923db7d7580efef3f182d87`. It has not been run on
the 14.02 PS4. The launcher is deliberately paused by `CANDIDATE_READY` in
`launch.js` and `afterglow-g.js` until review.

The repository's original `debug.bin` is retained unchanged. Its 14.02
branch used the 14.00 SETLOGIN instruction address and would corrupt a live
14.02 instruction. `tools/patch-debug-1402.py` verifies the original SHA-256
and instruction, corrects only file bytes `0x18d6` and `0x18d7`, and verifies
the resulting `debug-1402-fixed.bin` SHA-256
`5862bf202a7c5f146820fd6354330dd07b1c6bdbe6e7f939ba71692b5410d083`.
This is an experimental HEN payload, not GoldHEN.

`debug_server.py` serves only to the configured PS4 IP on a new local port,
adds no-store headers, verifies both binary hashes, and keeps checkpoint logs
in `../debug-captures/`. The browser uses one manual Start, a same-tab token,
a persistent attempt lock, and no automatic WebKit or kernel retry. The host
checks 14.02 firmware, a two-way kernel base leak, the live ELF layout, the
unique swap gadget, exact stock bootstrap and host patch windows, and a
bounded series of thread, process, descriptor, file and map reads before any
kernel write. Success means only that `pthread_create` returned success;
the HEN runtime would still need visible confirmation.

Known limit: the APM UAF shots can still panic. The file descriptor array may
change while the next shot is prepared, and each map shot follows multiple
links before JavaScript can inspect them. Teardown must verify all device and
queue handles and notes; a failure requires leaving the page open until a
full console power off. No console run, public deployment, or push was made
while preparing this candidate.
