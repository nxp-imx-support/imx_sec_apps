/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

/*
* securekey_api.h
*/

#ifndef _SECUREKEY_API_H_
#define _SECUREKEY_API_H_

#include "securekey_api_types.h"

/* SK stands for: Secure Key */

/* This struct defines the function pointers to function defined by this
  * Library.
*/
struct SK_FUNCTION_LIST {
	SK_RET_CODE(*SK_EnumerateObjects)(SK_ATTRIBUTE *pTemplate,
			uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
			uint32_t maxObjects, uint32_t *pulObjectCount);
	SK_RET_CODE(*SK_GetObjectAttribute)(SK_OBJECT_HANDLE hObject,
			SK_ATTRIBUTE *attribute, uint32_t attrCount);
	SK_RET_CODE(*SK_Sign)(SK_MECHANISM_INFO *pMechanismType,
			SK_OBJECT_HANDLE hObject, const uint8_t *inDigest,
			uint16_t inDigestLen, uint8_t *outSignature,
			uint16_t *outSignatureLen);
	SK_RET_CODE(*SK_Decrypt)(SK_MECHANISM_INFO * pMechanismType,
			SK_OBJECT_HANDLE hObject, const uint8_t *inData,
			uint16_t inDataLen,	uint8_t *outData,
			uint16_t *outDataLen);
	SK_RET_CODE(*SK_Digest)(SK_MECHANISM_INFO *pMechanismType,
			const uint8_t *inData, uint16_t inDataLen,
			uint8_t *outDigest, uint16_t *outDigestLen);
};

typedef struct SK_FUNCTION_LIST SK_FUNCTION_LIST;

typedef SK_FUNCTION_LIST * SK_FUNCTION_LIST_PTR;

typedef SK_FUNCTION_LIST_PTR * SK_FUNCTION_LIST_PTR_PTR;


/* SK_GetFunctionList obtains a pointer to the Securekey library's list of
function pointers.
ppFuncList points to a value which will receive a pointer to the library's
SK_FUNCTION_LIST structure, which in turn contains function pointers for all
the Securekey API routines in the library.

* \param[in] ppFuncList This points to a value which will receive a pointer to
the library's SK_FUNCTION_LIST structure.
*
* \retval ::SKR_OK		Successful execution.
* \retval ::SKR_ERR_BAD_PARAMETERS	Invalid function arguments
*/
SK_RET_CODE SK_GetFunctionList(SK_FUNCTION_LIST_PTR_PTR  ppFuncList);

/*************************************************************/
/* Object Operations*/
/*************************************************************/
/**
* Enumerates all the Objects based on attribute list that currently exist on
the HSM and have \p pTemplate is an array of attributes that the returned
object must have.

In order to enumerate all the Objects, set NULL in \p pTemplate.

Each object has a unique SK_OBJECT_HANDLE value - this value depends on
the library implementation.

If \p phObject points to the array capable of holding maxObjects.

* \param[in] pTemplate The array of attributes that the enumerated object
must contain
* \param[in] attrcount The number of attributes in \p pTemplate
* \param[in, out] phObject IN: caller passes a buffer of at least maxObjects; OUT: contains the handles of the objects
*
* \param[in] maxObjects The maximum number of attributes application is
asking for.
* \param[out] pulObjectCount OUT: set to hold the exact number of handles
in objectHandles.
*
* \retval ::SKR_OK			Successful execution, phObject
will be filled with created object handle.
* \retval ::SKR_ERR_BAD_PARAMETERS	Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
* \retval ::SKR_ERR_NOT_SUPPORTED	The function and/or
parameters are not supported by the library.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_EnumerateObjects(SK_ATTRIBUTE *pTemplate,
		uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
		uint32_t maxObjects, uint32_t *pulObjectCount);

/**
* Creates an Object on the HSM, and returns a handle to it.

If the object already exists, it depends on the HSM behavior whether
this function succeeds (e.g. set a new value) or fail with an error.

\p attr is an array of attributes that the object should be created
with. Some of the attributes may be mandatory, such as
SK_ATTR_OBJECT_TYPE and SK_ATTR_OBJECT_INDEX (the id of the object),
and some are optional.
Application needs to take care that valid attributes are passed, library will not
return any error on receving inconsistent/incompatible attributes.

* \param[in] attr The array of attributes to be used in creating the Object
* \param[in] attrCount The number of attributes in \p attr
* \param[in, out] phObject IN: A pointer to a handle (must not be NULL);
OUT: The handle of the created Object
*
* \retval ::SKR_OK			Successful execution, phObject
will be filled with created object handle.
* \retval ::SKR_ERR_BAD_PARAMETERS	Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
* \retval ::SKR_ERR_NOT_SUPPORTED	The function and/or
parameters are not supported by the library.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_CreateObject(SK_ATTRIBUTE *attr,
		uint16_t attrCount, SK_OBJECT_HANDLE *phObject);

/**
* Generates key pair on the HSM, and returns a handle to it.

If the object already exists, it depends on the HSM behavior whether
this function succeeds (e.g. set a new value) or fail with an error.

\p pMechanism is mechanism for key pair generation. Eg:
SKM_RSA_PKCS_KEY_PAIR_GEN.
\p attr is an array of attributes that the object should be created
with. Some of the attributes may be mandatory, such as
SK_ATTR_OBJECT_INDEX (the id of the object), and some are optional.
Application needs to take care that valid attributes are passed, library will not
return any error on receving inconsistent/incompatible attributes.

* \param[in] pMechanism Mechanism for key pair generation
* \param[in] attr The array of attributes to be used in creating the Object
* \param[in] attrCount The number of attributes in \p attr
* \param[in, out] phKey IN: A pointer to a handle (must not be NULL);
OUT: The handle of the created Object
*
* \retval ::SKR_OK			Successful execution, phObject
will be filled with created object handle.
* \retval ::SKR_ERR_BAD_PARAMETERS	Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
* \retval ::SKR_ERR_NOT_SUPPORTED	The function and/or
parameters are not supported by the library.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_GenerateKeyPair(SK_MECHANISM_INFO *pMechanism,
		SK_ATTRIBUTE *attr, uint16_t attrCount,
		SK_OBJECT_HANDLE *phKey);

/**
* Erases an object from the HSM.

This means the object with the specified handle can no longer be used.

* \param[in] hObject The handle of the Object to be erased
*
* \retval ::SKR_OK Successful execution
* \retval ::SKR_ERR_BAD_PARAMETERS      Invalid function arguments
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_EraseObject(SK_OBJECT_HANDLE hObject);


/**
* Obtains the value of the Object's requested Attributes.

The parameter \p attribute specifies the array of the Types of the attribute
to be returned, and the data is returned in the attribute's value and valueLen
members.

If \p attribute->value is NULL, then all that the function does is return
(in \p *attribute->valueLen) a number of bytes which would suffice
to hold the value to be returned.  SKR_OK is returned by the function.

If \p attribute->value is not NULL, then \p *attribute->valueLen must
contain the number of bytes in the buffer \p attribute->value.  If that buffer
is large enough to hold the value be returned, then the data is copied to
\p attribute->value, and SKR_OK is returned by the function.
If the buffer is not large enough, then SKR_ERR_SHORT_BUFFER is returned.
In either case, \p *attribute->valueLen is set to hold the exact number of
bytes to be returned.

* \param[in] hObject The handle of the Object that its attribute's value
should be obtained.
* \param[in, out] attribute The array of attribute to be obtained.
* \param[in] attrCount The number of attributes in \p attribute.
*
* \retval ::SKR_OK Successful execution
* \retval ::SKR_ERR_BAD_PARAMETERS      Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
currently inaccessible.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_GetObjectAttribute(SK_OBJECT_HANDLE hObject,
		SK_ATTRIBUTE *attribute, uint32_t attrCount);

/**************************************************************/
/* Cryptographic Operations*/
/**************************************************************/

/**
* Signs the data provided using the Object key and the requested mechanism.

The Cryptographic Mechanism to be used is passed in the \p type member
of the \p pMechanismType parameter.
A handle to the key to sign the data with is provided by \p hObject.

If additional information is required by the specific signing mechanism, is will
be conveyed in \p pMechanismType->pParameter.

If \p outSignature is NULL, then all that the function does is return
(in \p *outSignatureLen) a number of bytes which would suffice to hold the
signature.  SKR_OK is returned by the function.

If \p outSignature is not NULL, then \p *outSignatureLen must contain the
number of bytes in the buffer \p outSignature.  If that buffer is large enough
to hold the signature be returned, then the data is copied to \p outSignature,
and SKR_OK is returned by the function.
If the buffer is not large enough, then SKR_ERR_SHORT_BUFFER is
returned.  In either case, \p *outSignatureLen is set to hold the exact number
of bytes to be returned.

* \param[in] pMechanismType The signing Cryptographic Mechanism to be
used
* \param[in] hObject The handle of the Object key to sign with
* \param[in] inData    Data buffer for that should be signed (Should be a
digest as defined in Mechaism)
* \param[in] inDataLen The length of data passed as argument
* \param[in,out] outSignature IN: caller passes a buffer to hold the signature;
OUT: contains the calculated signature;
* \param[in,out] outSignatureLen IN: length of the \p outSignature buffer passed;
OUT: the number of bytes returned in \p outSignature
*
* \retval ::SKR_OK Successful execution
* \retval ::SKR_ERR_BAD_PARAMETERS      Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
currently inaccessible.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_Sign(SK_MECHANISM_INFO *pMechanismType,
		SK_OBJECT_HANDLE hObject, const uint8_t *inDigest,
		uint16_t inDigestLen, uint8_t *outSignature,
		uint16_t *outSignatureLen);

/**
* Dncrypts the data provided using the Object key and the requested
mechanism.

The Cryptographic Mechanism to be used is passed in the \p type member
of the \p pMechanismType parameter.
A handle to the key to encrypt the data with is provided by \p hObject.

If additional information is required by the specific encryption mechanism,
is will be conveyed in \p pMechanismType->pParameter.

If \p outData is NULL, then all that the function does is return
(in \p *outDataLen) a number of bytes which would suffice
to hold the return value.  SKR_OK is returned by the function.

If \p outData is not NULL, then \p *outDataLen must contain the number
of bytes in the buffer \p outData.  If that buffer is large enough to hold the
data be returned, then the data is copied to \p outData, and SKR_OK is
returned by the function.
If the buffer is not large enough, then SKR_ERR_SHORT_BUFFER is returned.
In either case, \p *outDataLen is set to hold the exact number of bytes to be
returned.

* \param[in] pMechanismType The encryption Cryptographic Mechanism to be
used
* \param[in] hObject The handle of the Object key to decrypt with
* \param[in] inData    Data buffer for that should be decrypted
* \param[in] inDataLen The length of data passed as argument
* \param[in,out] outData    IN: caller passes a buffer to hold the data to be returned;
OUT: contains the decrypted data
* \param[in,out] outDataLen IN: length of the \p outData buffer passed;
OUT: the number of bytes returned in \p outData
*
* \retval ::SKR_OK Successful execution
* \retval ::SKR_ERR_BAD_PARAMETERS      Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
currently inaccessible.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_Decrypt(SK_MECHANISM_INFO *pMechanismType,
		SK_OBJECT_HANDLE hObject, const uint8_t *inData,
		uint16_t inDataLen, uint8_t *outData,
		uint16_t *outDataLen);

/**
* Calculates the Digest (e.g. Sha256) value of the data provided as input.

The Cryptographic Mechanism to be used is passed in the \p type member of
the \p pMechanismType parameter.

If additional information is required by the specific digest mechanism, is
will be conveyed in \p pMechanismType->pParameter.

If \p outDigest is NULL, then all that the function does is return (in \p *outDigestLen)
a number of bytes which would suffice to hold the digest value.  SKR_OK
is returned by the function.

If \p outDigest is not NULL, then \p *outDigestLen must contain the number
of bytes in the buffer \p outDigest.  If that buffer is large enough to hold the
digest value be returned, then the data is copied to \p outDigest, and SKR_OK
is returned by the function.
If the buffer is not large enough, then SKR_ERR_SHORT_BUFFER is returned. In either
case, \p *outDigestLen is set to hold the exact number of bytes to be returned.

* \param[in] pMechanismType The Digest Cryptographic Mechanism to be used
* \param[in] inData    Data buffer for which the digest must be calculated
* \param[in] inDataLen The length of data passed as argument
* \param[in,out] outDigest    IN: caller passes a buffer to hold the digest value;
OUT: contains the calculated digest
* \param[in,out] outDigestLen IN: length of the \p outDigest buffer passed;
OUT: the number of bytes returned in \p outDigest
*
* \retval ::SKR_OK Successful execution
* \retval ::SKR_ERR_BAD_PARAMETERS      Invalid function arguments
* \retval ::SKR_ERR_OUT_OF_MEMORY	Memory allocation failed.
* \retval ::SKR_ERR_SHORT_BUFFER	Short output buffer.
currently inaccessible.
* -- Some internal error codes other than mentioned above can also be
returned.
* Refer to securekey_api_types.h for error code description.
*/
SK_RET_CODE	SK_Digest(SK_MECHANISM_INFO *pMechanismType,
		const uint8_t *inData, uint16_t inDataLen, uint8_t *outDigest,
		uint16_t *outDigestLen);

#endif /* _SECUREKEY_API_H_*/
