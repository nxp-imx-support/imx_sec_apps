// SPDX-License-Identifier: BSD-2-Clause
/**
* @copyright 2019 NXP
*
* @file    libcast_auth.cpp
*
* @brief   Cast Receiver Authentication aspects implementation.
*/

#include "libcast_auth.h"

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <dlfcn.h>

void __attribute__((constructor)) init();
void __attribute__((destructor)) fini();

bool libCastAuthImxLoaded = false;

const std::string kLibCastAuthImxPath = "libcast_auth_imx.so";
const std::string kLibCastAuthImxGenDevKeyCert = "castauth_GenDevKeyCert";
const std::string kLibCastAuthImxSignHash = "castauth_SignHash";
const std::string kLibCastAuthImxGetModelCertChain = "castauth_GetModelCertChain";

const size_t kCastAuthKeySize = 256;

typedef void* dyn_lib_handle;

/* Prototypes */

static dyn_lib_handle load_lib(const std::string& path);
static void* resolve(const dyn_lib_handle handle, const std::string& symname);
static void close_lib(dyn_lib_handle handle);
bool EnsureLibCastAuthImxLoaded();
std::string FromVector(const std::vector<uint8_t>& vec);
std::vector<uint8_t> ToVector(const std::string& str);


struct dyn_lib {
	dyn_lib_handle  handle;
	std::string			path;

	dyn_lib(std::string p) : path(p), handle(nullptr) {}

	~dyn_lib() {
		if (handle != nullptr)
		close_lib(handle);
	}
};

typedef int (*PFN_GENERATE_DEVICE_KEY_AND_CERT)(const char*, uint32_t, char*, uint32_t, char**);
typedef int (*PFN_SIGN_HASH)(const char*, const unsigned char*, uint32_t, unsigned char*, uint32_t);
typedef char* (*PFN_GET_MODEL_CERT_CHAIN)();

PFN_SIGN_HASH _SignHash = nullptr;
PFN_GET_MODEL_CERT_CHAIN _GetModelCertChain = nullptr;
PFN_GENERATE_DEVICE_KEY_AND_CERT _GenerateDeviceKeyAndCert = nullptr;

std::vector<dyn_lib> libs;


static dyn_lib_handle load_lib(const std::string& path) {
	return dlopen(path.data() , RTLD_NOW);
}

static void* resolve(const dyn_lib_handle handle, const std::string& symname) {

	if (handle == nullptr) return nullptr;
	void *symaddr = dlsym(handle , symname.data());
	if (symaddr == nullptr) return nullptr;

	return symaddr;
}

static void close_lib(dyn_lib_handle handle) {
	dlclose(handle);
}

bool EnsureLibCastAuthImxLoaded() {

	if(libCastAuthImxLoaded)
	return true;

	libs.push_back(dyn_lib(kLibCastAuthImxPath));

	for (auto& l : libs) {
		l.handle = load_lib(l.path);
	}

	for (auto& l : libs){
		void *pfn = nullptr;
		if((pfn = resolve(l.handle, kLibCastAuthImxSignHash)))
		_SignHash =  reinterpret_cast<PFN_SIGN_HASH>(pfn);
		if((pfn = resolve(l.handle, kLibCastAuthImxGetModelCertChain)))
		_GetModelCertChain =  reinterpret_cast<PFN_GET_MODEL_CERT_CHAIN>(pfn);
		if((pfn = resolve(l.handle, kLibCastAuthImxGenDevKeyCert)))
		_GenerateDeviceKeyAndCert =  reinterpret_cast<PFN_GENERATE_DEVICE_KEY_AND_CERT>(pfn);
	}

	if((!_SignHash) || (!_GetModelCertChain) || (!_GenerateDeviceKeyAndCert)){
		std::cerr << "Error resolving one symbol or more from " << kLibCastAuthImxPath << std::endl;
		return false;
	}

	libCastAuthImxLoaded = true;
	return libCastAuthImxLoaded;
}

std::string FromVector(const std::vector<uint8_t>& vec) {
	return std::string(vec.begin(), vec.end());
}

std::vector<uint8_t> ToVector(const std::string& str) {
	return std::vector<uint8_t>(str.begin(), str.end());
}


// Given the |wrapped_device_key| and a |hash| value: unwrap the RSA key,
// prepend PKCS1 type 1 padding to the hash, then apply the RSA decrypt
// operation. The result is a 256 byte |signature| value.
// The result is true if the operation succeeded, false otherwise.
bool SignHash(const std::vector<uint8_t>& wrapped_device_key, const std::vector<uint8_t>& hash, std::vector<uint8_t>* signature) {

	if((!signature))
		return false;

	if (!EnsureLibCastAuthImxLoaded()) {
		std::cerr <<  "Error loading" << kLibCastAuthImxPath << std::endl;
		return false;
	}

	uint32_t expected_sigsz = static_cast<uint32_t>(kCastAuthKeySize);
	signature->resize(expected_sigsz);

	if(_SignHash(reinterpret_cast<const char *>(&wrapped_device_key.at(0)),
				reinterpret_cast<const unsigned char *>(&hash.at(0)),
				hash.size(), reinterpret_cast<unsigned char*>(&signature->at(0)), expected_sigsz))
	{
		std::cerr << "Failed to Sign Hash"<< std::endl;
		signature->clear();
		return false;
	}

	return true;
}


// Returns the |cert_chain| starting with the device certificate template
// followed by the model RSA cert and any intermediates up to (but not
// including) the Cast Root CA. The |cert_chain| is a string containing a
// concatenated series of X.509 certificates each in PEM format.
// The result is true if the operation succeeded, false otherwise.

bool GetModelCertChain(std::string* cert_chain_out) {

    char *cert_chain = NULL;

	if(!cert_chain_out)
		return false;

	if (!EnsureLibCastAuthImxLoaded()) {
		return false;
	}

	cert_chain = _GetModelCertChain();
	if(!cert_chain)
	{
		std::cerr << "Failed to get model cert chain" << std::endl;
		return false;
	}

	std::string local_contents(cert_chain);
	cert_chain_out->swap(local_contents);
	local_contents.clear();

	return true;
}

// Generate a new RSA 2048-bit device key (pair) and corresponding X.509
// device certificate. The device key is returned as |wrapped_device_key|, the
// wrapping (encryption) being unique to this device and such that unwrapping
// can only occur within the implementation of SignHash (see below).
// The initial value of |device_certificate| is the device certificate
// template in ASN.1 DER form. The modified value is the actual device
// certificate, also in DER form, which is generated from the template through
// the replacement of place-holders, and is then signed with the model key.
// The replacement values are generated within, or otherwise available to, the
// implementation of this function, with the exception of |mac_address| which
// is supplied by the caller as an ASCII string in the form XX:XX:XX:XX:XX:XX.
// The result is true if the operation succeeded, false otherwise.

bool GenerateDeviceKeyAndCert(const std::vector<uint8_t>& bss_id, std::vector<uint8_t>* device_key, std::vector<uint8_t>* cert_inout) {

	char *key = NULL;
	if (bss_id.size() != 17 || !device_key || !cert_inout) {
		return false;
	}

	if (!EnsureLibCastAuthImxLoaded()) {
		return false;
	}

	if(_GenerateDeviceKeyAndCert(reinterpret_cast<const char*>(&bss_id.at(0)),
				bss_id.size(),
				reinterpret_cast<char*>(&cert_inout->at(0)), cert_inout->size(),
				&key)
				)
	{
		std::cerr << "Failed to generate device key and cert " << std::endl;
		return false;

	}

	std::string key_str(key);
	std::vector<uint8_t> local_contents = ToVector(key_str);
	device_key->swap(local_contents);
	local_contents.clear();

	return true;
}

void init()
{
}

void fini()
{
	for (auto& l : libs) {
		close_lib(l.handle);
	}
}
\ No newline at end of file
