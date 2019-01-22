FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}-${PV}:"
SRC_URI += "file://openssl-1.0.2p-add-ecdsa-cryptodev-engine.patch"
