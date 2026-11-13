# PS4 14.02 one-attempt evidence

## Hardware results already obtained

The 14.02 browser/kernel route has completed through the reduced HEN installer
on two clean boots. Both runs returned from `pthread_create` with `rc=0` and
later found `/user/temp/hen.installed`:

- `1794530805723-5446057519429423`, marker observed at about 15 seconds;
- `1794532556517-46065583190575876`, marker observed at about 30 seconds.

The direct payload stub creates that file only when `install_payload` returns
zero. These results therefore prove more than thread creation, but they do not
prove that every installed hook works or that an FPKG launches.

## Failures explained by the audit

Earlier “unlimited” revisions could start many HEN pthreads in one WebProcess.
Captured logs show repeated `pthread-returned rc=0` records in the same run.
That stacked multiple installers and explains those freezes without treating a
kernel panic or freeze as success.

Other corrected issues included:

- persistent launch state bypassing the same-tab handoff;
- reloads after unknown kernel state;
- a second installer when RWX was already open but the marker was missing;
- retained 137 MB WebKit heaps on verified pre-kernel exits;
- telemetry failures blocking static/GitHub-hosted execution;
- unconditional completion-marker creation;
- AVX and imported libc buffer calls in the ring-0 installer callback;
- an unbounded byte scan for `DT_SCE_RELA`;
- the final tag/value entry bound and the preserved kernel-base null guard.

## Current candidate

`hen-1402-core.bin` is 498720 bytes with SHA-256:

`1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239`

Its exact generator/verifier is `tools/patch-debug-1402.py`; the patch record is
`hen-1402-core.manifest.json`.

The final dynamic-table bound was added after the two successful marker runs.
The decrypted 14.02 file proves the `PT_DYNAMIC` address and size, while the
table itself is populated by the live loader. Therefore the next legitimate
test is one clean-boot hardware attempt with this exact hash.

## Next proof

1. Obtain the explicit green completion-marker result on the current hash.
2. Without running the host again on that boot, launch one known installed
   FPKG or homebrew title.
3. Record whether it opens, freezes, or returns a specific system error.

That result distinguishes “core installer returned zero” from “the installed
FSELF/FPKG hooks work in practice.”
