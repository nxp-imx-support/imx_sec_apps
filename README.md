
# NXP Cast Authentication Library

## Introduction

Google Cast authentication aspects on i.MX8M are implemented in 5 separate components.

 - **Client Application (ca)**: interface to access the TA primitives from normal world.
 
 - **Trusted Application (ta)**: is the main component where most of the authentication aspects is implemented, device key and certification generation, signing etc
 
 - **Static/Pseudo Trusted Application (pta)**:  component is dedicated to enable operations in CAAM driver.
	 - RSA key-pair generation
	 -  Blacken RSA private key
	 - Sign using Black RSA key
	 - Signature verification
	 - Black blob encapsulation
	 - Black blob decapsulation
	 - Get chip unique id
	 - Get manufacturing protection public key
 
 - **CAAM driver for OPTEE** : The CAAM driver: used to enable the hardware cryptographic functions.
 
 - **Libcast authentication library** (libcast_auth.so) Wrapper of CA interfacing with Cast application.

## Instalaltion 

Details and build instructions for each component are described in the following document.
[https://community.nxp.com/docs/DOC-343388](https://community.nxp.com/docs/DOC-343388)


##  Changelog

**Version 2.0 (2019-05-14)**

- Enable CCM-blacken keys
- Enhanced communication between TA and PTA

**Version 1.0 (2019-05-01)**

- First release

##  Author

Marouene Boubakri <marouene.boubakri@nxp.com>
