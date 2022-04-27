SEC_ENHANCEMENTS_PATCH_PATH := "${THISDIR}/files"


SRC_URI += "${@bb.utils.contains('SRCBRANCH', 'imx_4.14.98_2.0.0_ga', \
    'file://0001-imx-optee-os-4.14.98_2.0.0-security-enhacements.patch', '', d)} \
"
SRC_URI += "${@bb.utils.contains('SRCBRANCH', 'lf-5.15.5_1.0.0', \
    'file://0001-imx-optee-os-5.15.5-1.0.0-security-enhacements.patch', '', d)} \
"

EXTRA_OEMAKE +="CFG_IMXCRYPT=y \
"

python () {
    d.prependVar("FILESEXTRAPATHS", "${SEC_ENHANCEMENTS_PATCH_PATH}")
}

