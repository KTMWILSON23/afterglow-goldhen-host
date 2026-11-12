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
14.02 instruction. A complete launch later proved that the browser exploit,
guarded kernel writes, privilege changes, payload copy, and payload thread all
completed. HEN displayed its config-update notification, then the PS4 UI
froze during later startup. Offline comparison with the decrypted 14.02 kernel
found two more definite bad kernel-table entries: `sceSblACMgrGetPathId`
pointed at an unrelated function with a different argument contract, and
`RsaesPkcs1v15Dec2048CRT` pointed at the next, different wrapper.

The supplied `ps4-hen-main (1).zip` then exposed the next fault. It contains
dedicated 14.02 kernel files, but its ShellUI, RemotePlay, and ShellCore patch
RVAs in `kpayload/source/offsets/1402.c` were copied from 14.00. The earliest
unchecked write is inside the inner payload's `install_patches()` path. The
archive still describes public support only through 12.02, so the 14.02 files
must be treated as an incomplete port rather than a finished release.

`tools/patch-debug-1402.py` verifies the original SHA-256, exact instructions,
and exact old table values. It corrects the three proven kernel references,
retains the FSELF/FPKG kernel hooks, and forces the inner payload to skip the
unported process-patch and plugin-hook branches. The outer plugin injector and
deliberate PartyDaemon/ShellUI restart are also skipped. The resulting
`debug-1402-fixed.bin` SHA-256 is
`f20531799820035925b189f1763977340a81a1c2ec8c03779a5d0be991dc7a1a`.
The nuanced `sceSblAuthMgrVerifyHeader` underlying-body target and the valid
full-entry `sceSblPfsSetKeys` target remain deliberately preserved.

This is a real but reduced HEN launch candidate: jailbreak and core
FSELF/FPKG package-authentication hooks remain, while menu extras, RemotePlay,
plugins, and the forced UI restart are disabled. It is HEN, not GoldHEN, and
hardware confirmation is still required.

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
