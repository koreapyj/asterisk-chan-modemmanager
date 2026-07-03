# asterisk-chan-modemmanager

Turn a USB cellular modem into a phone line for [Asterisk](https://www.asterisk.org/).

This channel driver connects Asterisk to modems managed by
[ModemManager](https://modemmanager.org/) and gives you:

- **Voice calls** (incoming and outgoing) over the modem's USB audio function
- **SMS** send and receive
- **MMS receive** — handled natively in the driver, no mmsd-tng daemon needed;
  attachments are saved to disk and exposed to the dialplan
- **Automatic audio device detection** — the driver finds the modem's ALSA
  sound card by itself; no audio configuration needed in the common case
- **Per-modem init AT commands** — for modems that need a setup command after
  every boot (e.g. Quectel `AT+QPCMV=1,2` to enable USB voice audio)

Everything works with **stock distribution packages**: no rebuilds of
Asterisk, ModemManager, or any other package are required, and no non-default
build options anywhere.

Developing or packaging? See [DEV_README.md](DEV_README.md).

## Install

Prebuilt packages for every release are attached to
[GitHub Releases](https://github.com/koreapyj/asterisk-chan-modemmanager/releases).

### OpenWrt 25.12

Download the `.apk` matching your package architecture (shown by
`apk info --print-arch` or in your firmware's profile), then:

```sh
apk add --allow-untrusted ./asterisk-chan-modemmanager-*.apk
```

Dependencies (asterisk, ModemManager, ALSA, the required asterisk bridge and
codec modules, and `kmod-usb-audio`) are installed automatically when the
package feeds are configured.

One-time setup — Asterisk runs as the `asterisk` user, which needs access to
the modem's sound card and (optionally) an AT port:

```sh
# add 'asterisk' to the audio and dialout groups in /etc/group:
sed -i -e 's/^audio:.*/&,asterisk/' -e 's/^dialout:.*/&,asterisk/' /etc/group
service asterisk restart
```

If you use `init_commands` and ModemManager holds every AT port of your modem,
free one with an ignore rule (ModemManager parses `/lib/udev/rules.d` itself
on OpenWrt, no udev needed). Example for a Quectel RM500Q (USB interface 03 =
second AT port):

```
# /lib/udev/rules.d/78-mm-chan-modemmanager-init-port.rules
ACTION!="add|change|move|bind", GOTO="end"
SUBSYSTEMS=="usb", ATTRS{bInterfaceNumber}=="?*", ENV{.MM_USBIFNUM}="$attr{bInterfaceNumber}"
ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0800", ENV{.MM_USBIFNUM}=="03", SUBSYSTEM=="tty", ENV{ID_MM_PORT_IGNORE}="1"
LABEL="end"
```

Then set `init_port = /dev/ttyUSBx` (the ignored port) in the config and
restart ModemManager.

### Ubuntu 24.04 / 26.04

Download the `.deb` built for **your** Ubuntu release (the package is pinned
to that release's Asterisk ABI — a 24.04 package will not install on 26.04
and vice versa), then:

```sh
sudo apt install ./asterisk-chan-modemmanager_*.deb
```

This pulls in Asterisk and all libraries automatically. Add the `asterisk`
user to the `audio` and `dialout` groups if it isn't already:

```sh
sudo usermod -aG audio,dialout asterisk
sudo systemctl restart asterisk
```

### Debian

Debian stable has not shipped an Asterisk package since 2023 (only sid
carries one), so there is no prebuilt Debian package. On sid you can build
your own with `dpkg-buildpackage -us -uc -b` (see
[DEV_README.md](DEV_README.md)).

## Configure

Config file: `/etc/asterisk/modemmanager.conf` (the full annotated reference
is `modemmanager.conf.sample`). You declare your modem(s) and SIM(s); the
driver matches them to live hardware dynamically, so replugging or swapping
slots keeps working.

Find your identifiers with `mmcli`:

```sh
mmcli -L                 # list modems
mmcli -m 0 | grep device # DeviceIdentifier  -> [modem] identifier
mmcli -m 0 --sim 0       # ICCID             -> [sim] identifier
```

Minimal working example:

```ini
[modem1]
type = modem
identifier = 0123456789abcdef0123456789abcdef01234567 ; mmcli DeviceIdentifier
; audio devices default to auto-detection; set explicitly only if that fails:
;input_device = plughw:CARD=Device,DEV=0
;output_device = plughw:CARD=Device,DEV=0
; Quectel modems need this after every boot for USB voice audio:
init_commands = AT+QPCMV=1,2
;init_port = /dev/ttyUSB3   ; optional: pin the AT port used for init_commands

[sim1]
type = sim
identifier = 8982123456781234567    ; ICCID
context = from-mobile               ; incoming calls land here
message_context = from-mobile-sms   ; incoming SMS/MMS land here
exten = s
```

### MMS

Set your carrier's MMSC per SIM. Bringing up the MMS APN bearer/routing is
your responsibility (same as with mmsd-tng):

```ini
[sim1]
; ...
mmsc = http://mms.example.com:9084
mms_interface = wwan0     ; bind fetches to the MMS bearer's netdev
;mms_proxy = 10.0.0.1:8080
;mms_spool = /var/spool/asterisk/mms
```

**IPv6-only carriers with NAT64** (verified on LGU+): some MMSCs publish a
native AAAA record that silently drops HTTP — real handsets reach them via
the IPv4 A record through 464XLAT/NAT64. If MMS fetches time out on an
IPv6-only bearer:

1. Discover the NAT64 prefix (RFC 7050): query `AAAA ipv4only.arpa` against
   the bearer's DNS server.
2. Resolve the MMSC's **A** record, map it into the prefix, and pin it in
   `/etc/hosts`, e.g. `2001:db8:64ff::c0a8:e60e  mms.example.com`.

The pin also covers retrieval URLs on other ports of the same host.

## Use

Dialplan:

```
; Outgoing call through the SIM
exten => _X.,1,Dial(ModemManager/8982123456781234567/${EXTEN},30)

; Outgoing SMS
same => n,MessageSend(ModemManager:+821012345678@8982123456781234567)

; Incoming calls arrive in the SIM's `context`; SMS/MMS arrive as MESSAGE
; in `message_context` (MMS: `mms_context` if set). MMS metadata:
[from-mobile-sms]
exten => s,1,Verbose(1,SMS from ${MESSAGE(from)}: ${MESSAGE(body)})
 same => n,Verbose(1,MMS attachments: ${MESSAGE_DATA(MMS_ATTACHMENT_COUNT)})
 same => n,Verbose(1,First file: ${MESSAGE_DATA(MMS_ATTACHMENT_FILE_1)} (${MESSAGE_DATA(MMS_ATTACHMENT_TYPE_1)}))
 same => n,Verbose(1,Subject: ${MESSAGE_DATA(MMS_SUBJECT)})
```

CLI: `modemmanager list available` shows detected modems, SIMs and ALSA
devices.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Call connects but no audio | `asterisk` user not in `audio` group; on OpenWrt `kmod-usb-audio` missing; on Quectel `AT+QPCMV=1,2` not applied (set `init_commands` — it resets on every modem boot) |
| "No translator path" / "Could not create class basic" (OpenWrt) | Missing asterisk codec/bridge packages — installed automatically by this package's dependencies since 1.0.0; `apk fix` or reinstall |
| `init_commands` never sent / port busy | ModemManager holds all AT ports. Add the `ID_MM_PORT_IGNORE` rule above and set `init_port` |
| MMS notification arrives but fetch fails | Is the MMS APN bearer up and routed? On IPv6-only bearers, apply the NAT64 pin above |
| SMS/call sending rejected while registered fine | Usually carrier-side provisioning of the SIM (e.g. data-only SIM); test the SIM in a phone |
| Wrong ALSA device picked | Set `input_device`/`output_device` explicitly; candidates are listed by `modemmanager list available` |

## Compatibility

- **Asterisk**: 20 – 23
- **Distributions**: OpenWrt 25.12, Ubuntu 24.04 / 26.04 (Debian sid: build
  from source). On OpenWrt the package exists for every architecture whose
  kernel has sound support — a few audio-less targets (e.g. at91/sama7)
  cannot run it and have no package.
- **Modems**: voice support must be exposed through ModemManager and call
  audio must be reachable as a USB audio class ALSA device (tty audio is not
  supported). Tested: Quectel RM500Q, EM05, EC25 on UMTS(CS) and VoLTE/5G(PS).
- **Carriers**: tested on LGU+ (Korea) including VoLTE, SMS, MMS over an
  IPv6-only bearer with NAT64.

## License

GPL-2.0-only. `src/mms/vendor/` contains the WSP/MMS codec vendored from
[mmsd-tng](https://gitlab.com/kop316/mmsd) (GPL-2).
