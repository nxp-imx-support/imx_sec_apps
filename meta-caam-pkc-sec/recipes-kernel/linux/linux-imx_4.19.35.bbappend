FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-linux-imx-4.19.35_1.0.0-caam-ecdsa-primitives-using-secure-key.patch "
SRC_URI += "file://0002-linux-imx-4.19.35_1.0.0-caam-blob-support-driver.patch "
SRC_URI += "file://enable-caam-pkc-sec.cfg "

do_configure_append() {
        cat ../enable-caam-pkc-sec.cfg >> ${B}/.config
}
