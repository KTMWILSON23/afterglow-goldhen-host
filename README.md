# PS4 14.02 core HEN GitHub Pages host

This repository publishes the audited one-attempt PS4 14.02 core-HEN host at:

<https://ktmwilson23.github.io/afterglow-goldhen-host/>

The deployed path installs the reduced core FSELF/FPKG hooks. It is not
GoldHEN and does not claim plugins, a debug menu, port 9090, Remote Play
patches, ShellUI patches, or other unvalidated 14.02 extras.

## Current evidence

Two earlier clean-boot runs reached the reduced HEN installer and created
`/user/temp/hen.installed` after `install_payload` returned zero. The current
revision adds an exact bound around the live loader-populated `PT_DYNAMIC`
table and therefore still needs one new hardware marker run. No test yet proves
a subsequent FPKG or homebrew launch.

The deployed payload is `site/hen-1402-core.bin`, 498720 bytes, SHA-256:

`1773444cd5caf62f703e53d6b023882e30c29aba26fc96082f3257e16efa6239`

The full patch generator, manifest, audit notes, and local no-cache host are on
the [experiment/github-debug-1402 branch](https://github.com/KTMWILSON23/afterglow-goldhen-host/tree/experiment/github-debug-1402).
Its current deployment source commit is `ca06c18`.

## Launch behavior

- One explicit button press creates a same-tab nonce.
- A restored or hand-edited launch URL cannot run unattended.
- One run contains one payload loader call and one `pthread_create` call.
- The page never reloads after the first kernel shot.
- Existing RWX state without the completion marker is treated as unknown and
  does not start another installer.
- Static-host `/beacon` failures are fire-and-forget and cannot block a stage.
- If success is not explicitly confirmed, fully power off before another try.

Web code cannot prove a physical cold boot; the operator must enforce that
requirement.

## Deployment

GitHub Actions deploys the `site/` directory on every push to `main`. The
workflow runs the one-attempt launch-gate test plus the retained offline 14.02
preflight, bootstrap, and teardown tests before uploading the Pages artifact.

Licensed under the GNU Affero General Public License v3.0 or later. See
`LICENSE`.
