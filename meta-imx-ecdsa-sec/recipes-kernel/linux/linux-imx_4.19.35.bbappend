FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-add-caam-ecdsa-secure-key-driver.patch "
SRC_URI += "file://0002-add-caam-blob-driver.patch "
SRC_URI += "file://enable-caam-ecdsa-blob.cfg "

do_configure_append() {
        cat ../enable-caam-ecdsa-blob.cfg >> ${B}/.config
}
