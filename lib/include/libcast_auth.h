// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    libcast_auth.h
 *
 * @brief   Cast Authentication aspects implementation on i.MX.
 */

#include <cstdint>
#include <string>
#include <vector>

#define EXPORT __attribute__((visibility("default")))

// Even though they are C++ functions, the cast_auth library exports function
// names using normal C mangling.
extern "C" {

/// @brief Cryptographically signs a hash.
///
/// This function performs the following actions (within the secure world):
////
/// 1. Unwraps the private key 'wrapped_device_key', using the device­ specific
///    wrapping key. If unwrapping fails, the function returns `false`.
/// 2. Pads the supplied hash using PKCS1 type 1 padding.
/// 3. “RSA Decrypt” the hash, using the device private key. The result is a
///    256 byte value that is returned to the caller in 'signature'.
///
/// @note: It is assumed that, where necessary for PKCS1v1.5 signatures, the
/// hash value will already have the ASN.1 DER prefix that identifies the hash
/// type prepended. This API is not responsible for adding such a prefix.
///
/// @param[in] wrapped_device_key
///   "Wrapped" device-specific private key as returned by
///   `GenerateDeviceKeyAndCert`.
///
/// @param[in] hash
///   Hash to sign.
///
/// @param[out] signature
///   Pointer to variable that receives the signed hash (cannot be null).
///
/// @returns `true` on success, `false` on failure.
bool EXPORT SignHash(const std::vector < uint8_t > &wrapped_device_key,
		     const std::vector < uint8_t > &hash,
std::vector < uint8_t > *signature);

/// @brief Returns the model certificate chain.
///
/// This function returns the certificate chain linking the device certificate
/// template through the model RSA key up to (but not including) the Cast Root
/// CA. The chain is a series of concatenated X.509 certificates in PEM format,
/// starting with the device certificate template and ending with the Cast Audio
/// root.
///
/// @param[out] cert_chain
///   Pointer to variable that receives the certificate chain (cannot be null).
///
/// @returns `true` on success, `false` on failure.
bool EXPORT GetModelCertChain(std::string * cert_chain);

/// @brief Generates a device specific certificate.
///
/// This function performs these overall steps:
///
/// 1. Generates a new device-specific key-pair.
/// 2. Uses `bss_id` and hardware IDs to replace place-holders in the
///    certificate template 'cert'.
/// 3. Signs the "to-be-signed" part of the certificate.
/// 4. Wraps the device-specific private key and stores it in
///    `wrapped_device_key`,
/// 5. Stores the device-specific certificate in `cert`.
///
/// @param[in] bss_id
///   17-character ASCII string containing 6 pairs of hexadecimal digits
///   separated by ':', e.g. "AA:BB:CC:DD:EE:FF". Passed as a vector.
///
/// @param[out] wrapped_device_key
///   "Wrapped" device-specific private key.
///
/// @param[in,out] cert
///   On entry this contains the DER encoded model-specific certificate
///   template; on exit it contains the device-specific certificate.
///
/// @returns `true` on success, `false` on failure.
bool EXPORT GenerateDeviceKeyAndCert(const std::vector < uint8_t > &bss_id,
std::vector < uint8_t > *wrapped_device_key,
std::vector < uint8_t > *cert);

}
