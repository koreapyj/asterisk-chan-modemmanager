# asterisk-chan-modemmanager

Asterisk channel driver for [ModemManager](https://modemmanager.org/).

## Features
- Phone calls (voice over the modem's USB audio function, ALSA-direct)
- SMS send/receive
- **MMS receive, natively** — no mmsd-tng daemon: WAP-push notifications are
  decoded in-driver and the message is fetched from your carrier's MMSC over
  HTTP (libcurl). Text parts are delivered to the dialplan message context;
  other attachments are spooled to disk and referenced through
  `MMS_ATTACHMENT_*` message variables.
- **Automatic audio device detection** — the modem's USB sysfs path is
  correlated with the ALSA card of its USB audio function, so
  `input_device`/`output_device` normally need no configuration (`auto`).
- **Per-modem init AT commands** — e.g. Quectel modems need `AT+QPCMV=1,2`
  after every boot before call audio flows; configure
  `init_commands = AT+QPCMV=1,2` and the driver sends it once per modem
  appearance over a spare AT port (ModemManager keeps its own ports; see
  `modemmanager.conf.sample`).

## Requirements
- Asterisk 20–23 headers (`asterisk-dev` on Debian/Ubuntu)
- glib-2.0 / gio-2.0 / gobject-2.0
- libmm-glib (ModemManager ≥ 1.20 recommended)
- alsa-lib
- libcurl

Modem requirements:
- Voice call support exposed through ModemManager (many modems do not
  support voice).
- Call audio reachable as an ALSA device (USB audio class). tty audio is not
  supported.

## Building

```sh
make            # builds chan_modemmanager.so via pkg-config
make check      # host unit tests (no Asterisk needed)
sudo make install
```

Overridable variables: `CC`, `PKG_CONFIG`, `ASTERISK_INCLUDE` (default
`/usr/include`), `MODULES_DIR` (default `/usr/lib/asterisk/modules`),
`ASTETCDIR`, `DESTDIR`.

### Debian/Ubuntu package

```sh
dpkg-buildpackage -us -uc -b
```

Produces `asterisk-chan-modemmanager_*.deb` with the correct
`asterisk-abi-*` dependency and multiarch module path.

### OpenWrt package

An OpenWrt package lives in `contrib/openwrt/asterisk-chan-modemmanager/`
(built against OpenWrt 25.12 and the matching `telephony`/`packages`
feeds; 25.12 uses APK as its package manager, so the build produces
`.apk` packages installed with `apk add`). Point a feed at it:

```sh
echo 'src-link modemmanager_local /path/to/this/repo/contrib/openwrt' >> feeds.conf
./scripts/feeds update modemmanager_local
./scripts/feeds install asterisk-chan-modemmanager
make menuconfig   # Network -> Telephony -> asterisk-chan-modemmanager
```

## Configuration

See `modemmanager.conf.sample` for all options. Summary:

- `[modemN] type=modem` sections are matched by ModemManager
  `DeviceIdentifier`; `[simN] type=sim` sections by `SimIdentifier` (ICCID).
  SIMs are located dynamically among the configured modems at load.
- Audio: `input_device`/`output_device` default to `auto`. Explicit values
  are ALSA PCM names (changed from PortAudio names in older versions).
- MMS: set `mmsc =` (and usually `mms_proxy`/`mms_interface`) per SIM.
  Bringing up the MMS APN bearer and routing is your responsibility, same
  as it was with mmsd-tng.
- Init AT commands: `init_commands = AT+QPCMV=1,2` (`;`-separated), optional
  `init_port = /dev/ttyUSBx`.

### Dialplan

- `Dial(ModemManager/{SimIdentifier}/{Number})`
  - e.g. `Dial(ModemManager/8982123456781234567/+821012345678,,r)`
- `MessageSend(ModemManager:{to_number}@{sim_identifier})`
  - e.g. `MessageSend(ModemManager:+821012345678@8982123456781234567)`
- Incoming SMS/MMS arrive as MESSAGE in `message_context` (MMS:
  `mms_context` if set). MMS attachments: `${MMS_ATTACHMENT_COUNT}`,
  `${MMS_ATTACHMENT_FILE_1}`, `${MMS_ATTACHMENT_TYPE_1}`, …

### CLI

- `modemmanager list available` — modems, SIMs and ALSA PCM devices.

## Architecture notes

- One module, `chan_modemmanager.so`. GLib runs on a private GMainContext
  in a dedicated thread; blocking work runs on per-modem serializers over a
  shared threadpool; MMS fetches run on their own worker. See
  `src/mm_glue.h` for the threading/ownership rules.
- `src/mms/vendor/` contains the WSP/MMS codec vendored from GPL-2
  [mmsd-tng](https://gitlab.com/kop316/mmsd) (provenance headers in each
  file).

## Tested environment
- Ubuntu 24.04+ (asterisk 20–22), OpenWrt 25.12 (asterisk 23)
- Quectel RM500Q, EM05, EC25 on UMTS(CS) and VoLTE/5G(PS)
