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
  DEPENDS:=asterisk +glib2 +modemmanager +alsa-lib +libcurl
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

$(eval $(call BuildPackage,asterisk-chan-modemmanager))
