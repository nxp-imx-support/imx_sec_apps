FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-eng_devcrypto.c-Add-support-to-ECDSA-with-CAAM-secure-key.patch"


PACKAGECONFIG ?= ""
PACKAGECONFIG_class-native = ""
PACKAGECONFIG_class-nativesdk = ""

PACKAGECONFIG[cryptodev-linux] = "enable-devcryptoeng,disable-devcryptoeng,cryptodev-linux"

PACKAGECONFIG_append_class-target = " cryptodev-linux"