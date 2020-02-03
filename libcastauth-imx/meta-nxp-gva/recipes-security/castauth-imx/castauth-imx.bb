SUMMARY = "CA to Retrieve Manufacturing Protection Public Key"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

DEPENDS = "openssl optee-client-imx optee-os-imx python-pycrypto-native"

inherit pythonnative

SRC_URI += "file://Makefile \
            file://ua/Makefile \
			file://ua/castauth.c \
            file://ca/Makefile \
            file://ca/imx_cast_auth_ca.h \
			file://ca/imx_cast_auth_ca.c \
            file://ta/Makefile \
            file://ta/imx_cast_auth_ta.c \
            file://ta/user_ta_header_defines.h \
            file://ta/sub.mk \
            file://ta/include/imx_cast_auth_ta.h \
"
S = "${WORKDIR}"

OPTEE_ARCH ?= "arm32"
OPTEE_ARCH_armv7a = "arm32"
OPTEE_ARCH_aarch64 = "arm64"

OPTEE_CLIENT_EXPORT = "${STAGING_DIR_HOST}${prefix}"
TEEC_EXPORT = "${STAGING_DIR_HOST}${prefix}"
TA_DEV_KIT_DIR = "${STAGING_INCDIR}/optee/export-user_ta_${OPTEE_ARCH}"

EXTRA_OEMAKE = " TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR} \
                 OPTEE_CLIENT_EXPORT=${OPTEE_CLIENT_EXPORT} \
                 TEEC_EXPORT=${TEEC_EXPORT} \
                 CROSS_COMPILE_HOST=${TARGET_PREFIX} \
                 CROSS_COMPILE_TA=${TARGET_PREFIX} \
                 V=1 \
               "

do_compile() {
	unset LDFLAGS
    export CFLAGS="${CFLAGS} --sysroot=${STAGING_DIR_HOST}"
    oe_runmake -C ${S}
}

do_install () {
    mkdir -p ${D}${nonarch_base_libdir}/optee_armtz
    mkdir -p ${D}${bindir}
	mkdir -p ${D}${libdir}
	install -D -p -m0755 ${S}/out/ua/* ${D}${bindir}
	install -D -p -m0644 ${S}/out/ca/* ${D}${libdir}
    install -D -p -m0444 ${S}/out/ta/* ${D}${nonarch_base_libdir}/optee_armtz
}

do_clean() {
    oe_runmake -C ${S} clean
}

FILES_${PN} += "${nonarch_base_libdir}/optee_armtz/"
FILES_${PN} += "${bindir}"
FILES_${PN} += "${libdir}"

SOLIBS = ".so"
FILES_SOLIBSDEV = ""

INSANE_SKIP_${PN} = "ldflags"

#For dev packages only
INSANE_SKIP_${PN}-dev = "ldflags"

# Imports machine specific configs from staging to build
PACKAGE_ARCH = "${MACHINE_ARCH}"
