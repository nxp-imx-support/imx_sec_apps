FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "${@bb.utils.contains('PV', '1.1.1b', 'file://0001-add-ecdsa-with-caam-secure-key-support.patch ', '', d)}"
SRC_URI += "${@bb.utils.contains('PV', '1.1.1g', 'file://0001-openssl-1.1.1g-add-ecdsa-with-caam-secure-key-support.patch ', '', d)}"

PACKAGECONFIG_append_class-target = " cryptodev-linux"
