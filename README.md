# GoldHEN host for PS4 14.00 / 14.02

Static GitHub Pages host for the supplied afterglow browser exploit. Firmware
14.00 uses the official **GoldHEN** binary and matched patchset. Firmware 14.02
has been disabled after the reconstructed candidate caused a hardware kernel
panic during its first console test. Later local read-only checks reached
kernel memory on two fresh boots and captured stock patch sites, but did not
run GoldHEN.

Hosted URL after Pages finishes deploying:

<https://ktmwilson23.github.io/afterglow-goldhen-host/>

Open that address in the PS4 browser. On 14.00, GoldHEN starts after a
five-second countdown or when the start button is selected. On 14.02, the
launch is disabled after a hardware kernel panic.

The separate [14.02 storage diagnostic](https://ktmwilson23.github.io/afterglow-goldhen-host/d1/)
contains no exploit or payload. It confirms that a diagnostic marker survives
a browser reload; passing it does not establish kernel or GoldHEN support.

## Published runtime

GitHub Pages deploys `site/`. The 14.02 experimental binary is present for
provenance but cannot be launched by the 14.02 page. The HEN payload, ISO,
and `kpstep` diagnostic routes are excluded.

The landing page navigates to:

```text
launch.html?v=gh1402panic3&log=1&afterglow=run&mode=goldhen
```

Do not open `launch.html` directly. The exploit checks that it was reached
from `index.html` on the same origin before arming.

## Updating

Pushing to `main` deploys `site/` through GitHub Actions. If JavaScript is
changed later, also change the `?v=` values used by the HTML and module
imports so the console cannot reuse an older GitHub Pages response.

## Safety

The kernel patch lasts until the console reboots. A failed exploit run can
freeze or crash the console; do not run it while anything is unsaved.

The 14.02 route is not an official GoldHEN release. It is currently fail-closed
after a real 14.02 console test produced a kernel panic on 2026-11-11.
Static analysis after that test found two concrete corruption paths. The web
stage tried to relocate 14.00 patches using one-byte guesses and could not find
the required 14.02 `+0x220` loader sites. The reconstructed GoldHEN table also
placed three return-one stubs `0x80` bytes before their validated 14.02 function
entries; one target landed inside an instruction.

The source now records all fifteen exact 14.02 eight-byte patch windows and
refuses mismatches instead of scanning or guessing. A separate local candidate
also corrects the three GoldHEN table entries, but it is deliberately not
published: the earlier kernel bootstrap and the remaining payload writes still
need complete preimage validation. Do not retry 14.02 from this host until that
work is complete. The 14.02 table is independently corroborated by
[ArabPixel/WebKitty commit 8e256c3](https://github.com/ArabPixel/WebKitty/commit/8e256c322b645984c56d4d90e253d4c7cf83e9e1)
and by the supplied kernel artifact at fourteen of fifteen sites. The local
read-only capture independently confirmed bcopy's stock first byte on a fresh
14.02 boot.

The exact static 14.02 bootstrap is also recorded now; it differs from 14.00
only at the two `sys_mmap` protection immediates (`+0x400`). It remains blocked
until an all-stock/all-final preflight protects every bootstrap write and the
unused syscall slot.

The offline investigation and remaining launch gates are recorded in
[the 14.02 port status](docs/14.02-port-status.md). The offline preflight
classifier and guarded bootstrap prototype are research tools; neither is
connected to the PS4 launch path.

The runtime verifies every firmware-fixed binary before use:

```text
goldhen.bin (official 14.00)       39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d
patchset.bin (14.00 only)         615f275b96831cc04173757db39e93f0d27b52888976af2a6444604aa8ac5dbf
goldhen-1402-experimental.bin     23fa75217949cd1be4ba0531e726c05f4ca0a2e47ed9eedb598e23da4eeacca9
supplied 14.02 compiled kpayload  5c643b05a52e06cc6a32a73b1780950a1ca90930e167f0a3eff9a56d54908c28
```

Licensed under the GNU Affero General Public License v3.0 or later. See
`LICENSE`.
