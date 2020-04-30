SUMMARY = "Demo utility for exporting and importing black EC keys to/from blob"
LICENSE = "GPL-2.0"
LIC_FILES_CHKSUM = "file://COPYING;md5=fd825d4bb161779ed4ded735684341e4"

DEPENDS = "openssl"

inherit pythonnative

SRC_URI += "file://Makefile \
            file://eckey.c \
			file://COPYING \
"
S = "${WORKDIR}"


do_compile() {
	unset LDFLAGS
    export CFLAGS="${CFLAGS} --sysroot=${STAGING_DIR_HOST}"
    oe_runmake -C ${S}
}

do_install () {
    mkdir -p ${D}${bindir}
	install -D -p -m0755 ${S}/eckey ${D}${bindir}
}

do_clean() {
    oe_runmake -C ${S} clean
}

FILES_${PN} += "${bindir}"

INSANE_SKIP_${PN} = "ldflags"

# Imports machine specific configs from staging to build
PACKAGE_ARCH = "${MACHINE_ARCH}"