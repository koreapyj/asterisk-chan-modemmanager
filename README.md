# asterisk-chan-modemmanager
Asterisk channel driver for ModemManager

## Features
- Phone calls
- SMS send/receive
- MMS receive (res_mmsd)
  - MMS support requires mmsd-tng and proper network routing.
  - If you wish to relay received MMS to pjsip endpoints, please note that pjsip only supports plain text messages. Image or other attachments will be ignored.

## Limitations
- This driver does nothing about device hardware by itself.
  - If ModemManager support your device, this driver ask to ModemManager to make calls or send/receive SMS via DBus API.
- Any modem configurations are should be done by yourself.
  - IMS or USB audio, network, etc.
- MMS support is little bit tricky.
  - Since mmsd-tng does not support system dbus, it should run as same user as asterisk. Please note that if you installed asterisk with package manager, "asterisk" user don't have session dbus by default in many dists.
  - Many carriers deny access to MMSC from public internet. Network configuration takes some headaches.
- Audio configuration is not straight-forward since PortAudio API does not exposes device path.
  - ModemManager has audio port API but I never seen it returns proper value.
  - Maybe it can be resolved with sysfs but at this point there is no support to detect audio port automatically.

## Build Requirements
Detailed instructions are WIP.
- glib
- portaudio
- libmm-glib

## Modem Requirements
- Voice call functionallity. Many modems are not support voice call.
- Detected from and controllable with ModemManager
- Audio device detected with alsa or other PortAudio supported method. tty audio is not supported!

## Tested environment
- Ubuntu 24.04 asterisk 20.6, mmsd-tng from ubuntu apt source.
- Quectel RM500Q, EM05, EC25 modem on UMTS(CS) and VoLTE/5G(PS).
  - Quectel modems are require to send AT command `AT+QPCMV=1,2` for every reboots. For details, please refer "Voice Over USB and UAC Application Note" from Quectel.

## Usage
- Currently this channel driver is not in "just work" state.
- For configuration, see `modemmanager.conf.sample`.
  - Configured SIMs are not have static relationships with modems.
  - This driver will find your SIM from every configured modems and pick proper modem when loaded.

### CLI commands
- `modemmanager list available`
  - List available devices.
- `mmsd list mms`
  - List received MMS messages.

### Dialplan Applications
- `Dial`
  - `ModemManager/{Resource}/{Extension}`
    - Examples
      - `Dial(ModemManager/8982123456781234567/+821012345678,,r)`
    - Resource
      - SIM identifier. This value is normally ICCID.
    - Extension
      - Phone number.
- `MessageSend`
  - `ModemManager:{to_number}@{sim_identifier}`
    - Examples
      - `MessageSend(ModemManager:+821012345678@8982123456781234567)`
