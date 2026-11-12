# PS4 14.02 corrected debug.bin experiment

This branch is a one-shot candidate based on Akatsuki commit
`689446d47fe1f3057923db7d7580efef3f182d87`. The manual launcher was
enabled after independent offline review; a kernel panic remains possible.
The first 14.02 run stopped before any kernel shot because its thread-function
resolver expected a module base in an information field that is empty in this
browser. The corrected launcher reads the existing WebKit pthread_create
import slot and verifies both the slot and its target against live mappings.
The next run also stopped before a kernel shot because the live mapping list
was collected after that import check; the order is corrected. A later run
verified the import, kernel base, exact stock bytes, and several bounded
kernel reads, then stopped at the filedesc headroom guard. It made no kernel
write and did not start the payload. The host now reserves descriptor-table
capacity with a temporary F_DUPFD descriptor before taking the filedesc
snapshot, keeps the 200-slot guard, and logs the header fields.

The repository's original `debug.bin` is retained unchanged. Its 14.02
branch used the 14.00 SETLOGIN instruction address and would corrupt a live
14.02 instruction. The first complete launch proved that the browser exploit,
guarded kernel writes, privilege changes, payload copy, and payload thread all
completed, but the PS4 UI then froze inside HEN startup. Offline comparison
with the 14.00 source and decrypted 14.02 kernel found two more definite bad
entries in the embedded 14.02 table: `sceSblACMgrGetPathId` pointed at an
unrelated function with a different argument contract, and
`RsaesPkcs1v15Dec2048CRT` pointed at the next, different wrapper.

`tools/patch-debug-1402.py` verifies the original SHA-256, exact instruction,
and exact old table values. It corrects only file bytes `0x18d6`, `0x18d7`,
`0x10c6c`, `0x10c6d`, and `0x10c84`, then verifies the resulting
`debug-1402-fixed.bin` SHA-256
`89538354a878afeade624276f928ff1d4f6d7d00baab2f1b6784bfa9f02ffc0b`.
The nuanced `sceSblAuthMgrVerifyHeader` underlying-body target and the valid
full-entry `sceSblPfsSetKeys` target are deliberately preserved. This remains
an experimental HEN payload, not GoldHEN, until confirmed on hardware.

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
full console power off. The first run stopped before any kernel shot or payload
start. No public deployment or push was made while preparing this candidate.
