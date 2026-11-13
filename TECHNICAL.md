# PS4 14.02 core-HEN technical record

## Inputs and output

- Source binary: `debug.bin`, 498720 bytes, SHA-256
  `19939e83d0dc57c1172a156503461a333129ebd3f9db704f0dbc3f249ecfcbd5`.
- Akatsuki source commit:
  `689446d47fe1f3057923db7d7580efef3f182d87`.
- HEN source archive: `ps4-hen-main (1).zip`, SHA-256
  `bf418e981c40b8aa5aaf4874170eed98ba0b6c93228ba8e233542031739f3fac`.
- Current output: `hen-1402-core.bin`, 498720 bytes, SHA-256
  `1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239`.

`tools/patch-debug-1402.py` rejects any input, preimage, instruction, preserved
value, changed-byte set, output size, or output hash that differs from the
pinned audit record.

## Payload corrections

The generated payload:

- corrects the proven 14.02 SETLOGIN, `sceSblACMgrGetPathId`, and
  `RsaesPkcs1v15Dec2048CRT` references;
- recovers both 14.02 FSELF hook contexts from the live caller registers;
- replaces AVX copies in the user wrapper and syscall-11 callback with exact
  44-byte scalar copies;
- replaces ring-0 imported `memset`/`memcpy` calls with scalar clear/copy loops;
- clears `[payload, payload+0x8200)` before copying the 0x8008-byte initialized
  image, covering the audited BSS through relative offset 0x81F8;
- runs only the core installer, creates `/user/temp/hen.installed` only after
  `install_payload` returns zero, and preserves nonzero installer results;
- skips unported process/UI patches, plugin hooks/uploads, optional installer
  helpers, and the ShellUI/PartyDaemon restart.

## Bounded dynamic-table lookup

The decrypted 14.02 ELF program header places `PT_DYNAMIC` at RVA `0xCFE890`
with size `0x110`, ending at `0xCFE9A0` exclusive. The lookup compares an
8-byte tag and, on a match, reads the following 8-byte value. Therefore:

- first entry start: `0xCFE890`;
- last complete 16-byte entry start: `0xCFE990`;
- post-increment loop stop: `0xCFE991` exclusive.

The patch also preserves the original `r8` kernel-base null guard and its
failure target at file offset `0x42AA`. The decrypted file contains a zeroed
dynamic table; the live loader-populated contents require hardware validation.

## Runtime invariants

- A launch requires the exact same-tab session nonce and local lock created by
  the landing-page button. The session nonce is consumed before exploit work.
- A restored launch URL cannot run unattended.
- The production path contains one payload loader call and one
  `pthread_create` call.
- An existing marker returns before exploit work. A live RWX kernel with no
  marker is treated as unknown and does not start another installer.
- Marker checks occur at 30, 40, 50, and 60 seconds. Only `ENOENT` means
  absent; every other open error is unknown.
- No page reload or automatic HEN retry remains after kernel entry.
- Known pre-thread payload mappings and verified pre-kernel WebKit failure
  paths release their mappings/heaps.
- `pthread_create` return code zero is recorded before the opaque thread handle
  is read. The handle value is not treated as a success test.

## Evidence boundary

Two earlier clean-boot runs produced the completion marker:

- `1794530805723-5446057519429423` (about 15 seconds);
- `1794532556517-46065583190575876` (about 30 seconds).

Those runs prove that the then-current core installer returned zero. The final
bounded dynamic-table revision above was made afterward and needs one new
hardware marker run. No run yet proves a subsequent FPKG or homebrew launch.
A native notification request returning zero means the request was accepted;
it is not a ShellUI-render acknowledgement and is not used as the success
condition.
