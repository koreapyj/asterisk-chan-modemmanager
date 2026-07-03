#
# Copyright (C) 2025 koreapyj
#
# This is free software, licensed under the GNU General Public License v2.
#
# OpenWrt package for the chan_modemmanager Asterisk channel driver.
#
# Local development/CI: point the buildroot at this directory with a
# src-link feed and override the source, e.g.
#   echo 'src-link modemmanager_local /path/to/repo/contrib/openwrt' >> feeds.conf
#   ./scripts/feeds update modemmanager_local
#   ./scripts/feeds install asterisk-chan-modemmanager
#   make package/asterisk-chan-modemmanager/compile \
#     ASTERISK_CHAN_MM_SOURCE_URL=file:///path/to/repo \
#     ASTERISK_CHAN_MM_SOURCE_VERSION=$(git -C /path/to/repo rev-parse HEAD)
#
# Release: update PKG_SOURCE_VERSION to the release tag/commit and replace
# PKG_MIRROR_HASH with the real hash (make package/.../download; make check FIXUP=1).
#
# Local-dev gotchas (hard-earned):
# - The source tarball is cached as dl/$(PKG_NAME)-$(PKG_VERSION).tar.* and
#   NOT invalidated when the commit changes (hash check skipped). Remove it
#   before rebuilding a new commit:  rm dl/asterisk-chan-modemmanager-*.tar.*
# - `apk add` of a package with an unchanged version-release is a no-op on
#   an already-installed target. Bump PKG_RELEASE, `apk del` first, or copy
#   the built .so directly while iterating.

include $(TOPDIR)/rules.mk

PKG_NAME:=asterisk-chan-modemmanager
# OpenWrt 25.12+ packages with APK (USE_APK default y): the version is
# packed as $(PKG_VERSION)-r$(PKG_RELEASE) and must stay APK-valid
# (numeric dotted version, integer release). Keep in sync with
# debian/changelog.
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

ASTERISK_CHAN_MM_SOURCE_URL?=https://github.com/koreapyj/asterisk-chan-modemmanager.git
ASTERISK_CHAN_MM_SOURCE_VERSION?=main

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=$(ASTERISK_CHAN_MM_SOURCE_URL)
PKG_SOURCE_VERSION:=$(ASTERISK_CHAN_MM_SOURCE_VERSION)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>

MODULES_DIR:=/usr/lib/asterisk/modules

include $(INCLUDE_DIR)/package.mk

define Package/asterisk-chan-modemmanager
  SUBMENU:=Telephony
  SECTION:=net
  CATEGORY:=Network
  TITLE:=ModemManager channel driver for Asterisk
  URL:=https://github.com/koreapyj/asterisk-chan-modemmanager
  # Beyond the link-time libraries: kmod-usb-audio provides /dev/snd for
  # the modem's USB audio function (the driver's whole audio path), and
  # OpenWrt splits the asterisk modules every real call needs into
  # separate packages (verified on hardware: without the bridge and
  # codec packages calls connect but carry no audio).
  # @AUDIO_SUPPORT/@USB_SUPPORT: alsa-lib and kmod-usb-audio only exist
  # on targets with those features; without them the driver is unusable
  # (and unbuildable) anyway.
  DEPENDS:=@AUDIO_SUPPORT @USB_SUPPORT \
	asterisk +glib2 +modemmanager +alsa-lib +libcurl \
	+kmod-usb-audio \
	+asterisk-bridge-simple +asterisk-bridge-native-rtp \
	+asterisk-bridge-softmix \
	+asterisk-codec-ulaw +asterisk-codec-alaw +asterisk-codec-resample
endef

define Package/asterisk-chan-modemmanager/description
 Asterisk channel driver that places and receives voice calls, SMS and
 MMS through ModemManager, with ALSA-direct audio, automatic USB-to-ALSA
 device correlation and per-modem init AT commands (e.g. Quectel
 AT+QPCMV=1,2 for voice over the USB audio function).
endef

define Package/asterisk-chan-modemmanager/conffiles
/etc/asterisk/modemmanager.conf
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	+$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		PKG_CONFIG="$(PKG_CONFIG)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		ASTERISK_INCLUDE="$(STAGING_DIR)/usr/include" \
		MODULES_DIR="$(MODULES_DIR)" \
		chan_modemmanager.so
endef

define Package/asterisk-chan-modemmanager/install
	$(INSTALL_DIR) $(1)$(MODULES_DIR)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/chan_modemmanager.so $(1)$(MODULES_DIR)/
	$(INSTALL_DIR) $(1)/etc/asterisk
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/modemmanager.conf.sample \
		$(1)/etc/asterisk/modemmanager.conf
endef

define Package/asterisk-chan-modemmanager/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
  echo "asterisk-chan-modemmanager: the asterisk user needs the 'audio' group"
  echo "for call audio (/dev/snd) and 'dialout' for init_commands AT ports."
  echo "Add it to both groups in /etc/group and restart asterisk."
  echo "If ModemManager claims every AT port, free one for init_commands with"
  echo "an ID_MM_PORT_IGNORE udev rule (MM parses /lib/udev/rules.d itself on"
  echo "OpenWrt) and point init_port at it; see modemmanager.conf."
  echo "Optional extras per deployment: asterisk-pjsip (SIP endpoints),"
  echo "asterisk-format-wav (recordings), asterisk-app-mixmonitor,"
  echo "asterisk-res-clioriginate (CLI 'channel originate')."
fi
exit 0
endef

$(eval $(call BuildPackage,asterisk-chan-modemmanager))
