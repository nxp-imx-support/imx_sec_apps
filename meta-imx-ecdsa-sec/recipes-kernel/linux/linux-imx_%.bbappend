FILESEXTRAPATHS_prepend := "${THISDIR}/files:"
SRC_URI += "${@bb.utils.contains('SRCBRANCH', 'imx_4.19.35_1.1.0', 'file://0001-add-caam-ecdsa-secure-key-driver.patch ', '', d)}"
SRC_URI += "${@bb.utils.contains('SRCBRANCH', 'imx_4.19.35_1.1.0', 'file://0002-add-caam-blob-driver.patch ', '', d)}"
SRC_URI += "${@bb.utils.contains('SRCBRANCH', 'imx_4.19.35_1.1.0', 'file://enable-caam-ecdsa-blob.cfg ', '', d)}"
SRC_URI += "${@bb.utils.contains('KERNEL_BRANCH', 'imx_5.4.24_2.1.0', 'file://0001-linux-5.4.24_2.1.0-caam-ecdsa-primitives-using-secure-key.patch', '', d)}"
SRC_URI += "${@bb.utils.contains('KERNEL_BRANCH', 'imx_5.4.24_2.1.0', 'file://0002-linux-5.4.24_2.1.0-caam-blob-support-driver.patch', '', d)}"
SRC_URI += "${@bb.utils.contains('KERNEL_BRANCH', 'imx_5.4.24_2.1.0', 'file://enable-caam-pkc-blob.cfg ', '', d)}"

do_configure_append() {
    cat ../${CONFIG_PATCH_FILE} >> ${B}/.config    
}

python () {
    if d.getVar("SRCBRANCH", "True") == "imx_4.19.35_1.1.0":
        d.setVar("CONFIG_PATCH_FILE", "enable-caam-ecdsa-blob.cfg")
    elif d.getVar("KERNEL_BRANCH", "True") == "imx_5.4.24_2.1.0":
        d.setVar("CONFIG_PATCH_FILE", "enable-caam-pkc-blob.cfg")
}

