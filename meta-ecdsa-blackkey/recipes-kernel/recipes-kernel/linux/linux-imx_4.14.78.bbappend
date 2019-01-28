FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "file://0001-linux-imx-4.14.78_1.0.0_ga-ecdsa-primitives-using-caam.patch "
SRC_URI += "file://0002-linux-imx-4.14.78_1.0.0_ga-caam-black-key-device.patch "
SRC_URI += "file://caam-ecdsa-blackkey.cfg "

do_configure_append() {
        cat ../caam-ecdsa-blackkey.cfg >> ${B}/.config
}
