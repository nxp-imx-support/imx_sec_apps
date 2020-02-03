FILESEXTRAPATHS_prepend := "${THISDIR}/files:"

SRC_URI += " \
    file://0001-optee-os-imx-enable-caam-black-key-blob-mp-and-ocotp.patch \
"

CFLAGS+="-DDUMP_DESC"

EXTRA_OEMAKE +="CFG_TEE_TA_LOG_LEVEL=4 \
                CFG_TEE_CORE_LOG_LEVEL=4 \
				CFG_IMXCRYPT=y \
"