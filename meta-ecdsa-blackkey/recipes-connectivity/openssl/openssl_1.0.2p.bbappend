FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-openssl-1.0.2p-add-ecdsa-cryptodev-engine.patch"

do_install_append() {
        cp -rf ${S}/libcrypto.so.1.0.2 ${D}${libdir} 
}
