FILESEXTRAPATHS_prepend := "${THISDIR}/files:"

SRC_URI += "file://enable-dm-crypt.cfg \
            file://0001-block-undo-unexport-elv_register_queue-and-elv_unreg.patch \
            file://0001-full-disk-encryption-using-caam-secure-key.patch \
           "
