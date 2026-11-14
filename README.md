# XXFWilson23 PS4 14.02 GoldHEN host

This repository publishes the minimal **XXFWilson23** launch host at:

<https://ktmwilson23.github.io/afterglow-goldhen-host/>

The public site contains one original interface, one launch page, the six
unchanged modules needed by the proven 14.02 chain, and the untouched
GoldHEN v2.4b18.14 payload. It has no payload catalogue, language pack,
theme bundle, analytics, remote dependency, or unrelated exploit files.

## Public file set

```text
site/
  index.html
  launch.html
  goldhen.bin
  chain/
    jb.js
    core.js
    mem.js
    int64.js
    ps4_offsets.js
    afterglow.js
```

`goldhen.bin` is 298,776 bytes with SHA-256:

```text
c5480587d99efc2e3cc132352d9b7cf052dd3068280f1686e7fbb37d57e9ba8b
```

The GitHub Actions deployment refuses to publish if any public file is added,
removed, or changed unexpectedly.

## Provenance

The interface, minimal packaging, integrity checks, and deployment are the
XXFWilson23 host. The exploit implementation is preserved from the open-source
[WebKitty Afterglow chain](https://github.com/ArabPixel/WebKitty) at source
revision `b4423641016f05e8782c9c80c066e5f4fbfbc551`; this repository does not
claim authorship of that exploit or of GoldHEN.

The project is distributed under the GNU Affero General Public License v3.0.
See [LICENSE](LICENSE).
