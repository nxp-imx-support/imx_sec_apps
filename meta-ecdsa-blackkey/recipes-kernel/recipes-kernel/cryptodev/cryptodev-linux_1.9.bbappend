FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-cryptodev-1.9-add-ecdsa-primitives-using-caam.patch"

do_install() {
        install -D ${S}/crypto/cryptodev.h ${D}${includedir}/crypto/cryptodev.h
}

