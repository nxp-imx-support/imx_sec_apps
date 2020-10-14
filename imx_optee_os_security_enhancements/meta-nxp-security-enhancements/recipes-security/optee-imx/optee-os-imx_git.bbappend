FILESEXTRAPATHS_prepend := "${THISDIR}/files:"

SRC_URI += " \
    file://0001-imx-optee-os-4.14.98_2.0.0-security-enhacements.patch \
"

EXTRA_OEMAKE +="CFG_IMXCRYPT=y \
"
