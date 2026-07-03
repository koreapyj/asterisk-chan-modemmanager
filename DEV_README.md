# Developer & packaging notes

User documentation (install, configure, dialplan, troubleshooting) lives in
[README.md](README.md). This file covers building from source, the test
suite, architecture, packaging and the release procedure.

## Building from source

Build dependencies: a C toolchain, `pkgconf`, Asterisk headers
(`asterisk-dev`), `libmm-glib-dev`, `libasound2-dev`, `libglib2.0-dev`,
`libcurl4-openssl-dev`.

```sh
make            # builds chan_modemmanager.so via pkg-config
make check      # host unit tests (no Asterisk installation needed)
sudo make install
```

Overridable variables: `CC`, `PKG_CONFIG`, `ASTERISK_INCLUDE` (default
`/usr/include`), `MODULES_DIR` (default `/usr/lib/asterisk/modules`),
`ASTETCDIR`, `DESTDIR`.

The tree builds warning-free; CI enforces `-Werror`.

## Architecture

- One module, `chan_modemmanager.so`, exporting a single symbol
  (`__internal_chan_modemmanager_self`, enforced by a version script).
- GLib/GDBus runs on a **private GMainContext in a dedicated thread**.
  Everything that touches D-Bus signal subscriptions must execute *on* that
  thread (`g_main_context_invoke`) — `g_main_context_push_thread_default`
  from another thread silently no-ops once the loop owns the context, and
  proxies/subscriptions created that way bind a dead context and never fire.
- Blocking work (libmm-glib `_sync` calls, tty I/O) runs on **per-modem
  serializers** over a shared threadpool (the res_pjsip pattern). Never block
  the GMainLoop thread or a channel/bridge thread.
- Audio is ALSA-direct: a capture thread per call
  (`snd_pcm_wait`+`readi`; capture streams need an explicit `snd_pcm_start`),
  and **non-blocking playback** (`SND_PCM_NONBLOCK`, frames dropped on
  `-EAGAIN`) so a stalled modem can never wedge the Asterisk bridge thread.
- MMS fetches run on their own worker thread; intake happens on modem
  serializers. Dedup is by (SIM, transaction-id) with terminal tombstones so
  ModemManager's multipart re-delivery quirks don't cause loops.
- Full threading/ownership rules: `src/mm_glue.h`.
- `src/mms/vendor/` is the WSP/MMS codec vendored from GPL-2
  [mmsd-tng](https://gitlab.com/kop316/mmsd) (provenance headers in each
  file). Keep local changes minimal and marked.

## Debian/Ubuntu packaging

```sh
dpkg-buildpackage -us -uc -b
```

Produces `asterisk-chan-modemmanager_*.deb` with the correct
`asterisk-abi-<hash>` dependency (via `dh --with asterisk`) and multiarch
module path. Because of the ABI pin, a `.deb` only installs on the release it
was built on — CI builds one per supported Ubuntu LTS.

## OpenWrt packaging

The package lives in `contrib/openwrt/asterisk-chan-modemmanager/`, targeting
OpenWrt 25.12 (APK package format). Local development against a buildroot or
SDK:

```sh
echo 'src-link modemmanager_local /path/to/this/repo/contrib/openwrt' >> feeds.conf
./scripts/feeds update modemmanager_local
./scripts/feeds install asterisk-chan-modemmanager
make package/asterisk-chan-modemmanager/compile \
  ASTERISK_CHAN_MM_SOURCE_URL=file:///path/to/this/repo \
  ASTERISK_CHAN_MM_SOURCE_VERSION=$(git -C /path/to/this/repo rev-parse HEAD)
```

Hard-earned gotchas:

- The source tarball is cached as `dl/asterisk-chan-modemmanager-<ver>.tar.*`
  and **not invalidated when the commit changes**. Remove it before
  rebuilding a new commit.
- `apk add` of an unchanged version-release is a **no-op** on an installed
  target. Bump `PKG_RELEASE`, `apk del` first, or copy the built `.so`
  directly while iterating.

## CI

`.github/workflows/ci.yml`:

- **test** — build with `-Werror`, `make check`, symbol/linkage/install
  checks on the current Ubuntu LTS runner.
- **deb** — `dpkg-buildpackage` + `lintian` in `ubuntu:24.04` and
  `ubuntu:26.04` containers, each against that release's own `asterisk-dev`
  (asterisk 20 and 22 — also our oldest/newest supported-API coverage).
- **openwrt** — one job per official 25.12 package architecture that can
  support the driver (32; audio-less architectures are excluded — see
  below), each using the release SDK of a representative target. Feeds
  come from the release's `feeds.buildinfo` (the exact commits the stock
  packages on downloads.openwrt.org were built from) with default package
  config (`defconfig`, matching the phase-2 buildbot), so the build
  matches the release's asterisk (23.x) by construction. SDK
  `dl`/`build_dir`/`staging_dir` are cached per architecture.
- **release** — on `v*` tag pushes, attaches every built `.deb`/`.apk` to a
  GitHub Release.

The OpenWrt release number is set once at the top of the workflow
(`OPENWRT_RELEASE`). When bumping it, regenerate the architecture matrix from
`https://downloads.openwrt.org/releases/<ver>/packages/` (one representative
target per architecture, from each target's `profiles.json`), applying two
availability filters:

- the architecture's feeds must ship every runtime dependency: `libcurl4`,
  `glib2`, `modemmanager`, `alsa-lib` (in `packages/`) and `asterisk` plus
  the bridge/codec sub-packages (in `telephony/`). In 25.12.5 the only
  gap is `alsa-lib` (it is `@AUDIO_SUPPORT`-gated, and we link libasound —
  the package DEPENDS carry `@AUDIO_SUPPORT @USB_SUPPORT` for the same
  reason);
- the chosen representative target's `kmods/` index must contain
  `kmod-usb-audio`.

Targets failing these (e.g. at91/sama7 = arm_cortex-a7_vfpv4 in 25.12) can
never run the driver: their kernels have no sound support. A guard step in
the workflow fails loudly if defconfig ever deselects the package, since the
compile would otherwise "succeed" without emitting an `.apk`.

## Release procedure

1. Bump versions in **both** places, keeping them in sync:
   - `debian/changelog` (new entry, `dch -v <ver>` or by hand)
   - `contrib/openwrt/asterisk-chan-modemmanager/Makefile` (`PKG_VERSION`,
     reset `PKG_RELEASE`)
2. Commit, then tag `v<ver>` and push the tag. CI builds all packages and
   creates the GitHub Release with them attached.
3. If publishing the OpenWrt package to a real feed (not just Releases),
   set `PKG_SOURCE_VERSION` to the release tag and replace
   `PKG_MIRROR_HASH:=skip` with the real hash.
