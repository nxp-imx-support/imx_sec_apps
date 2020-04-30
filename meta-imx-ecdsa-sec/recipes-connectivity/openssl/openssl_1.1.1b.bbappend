FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-add-ecdsa-with-caam-secure-key-support.patch"

PACKAGECONFIG_append_class-target = " cryptodev-linux"