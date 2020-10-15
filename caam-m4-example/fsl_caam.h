/*
 * Header file for gernerating SHA256 hash using CAAM
 *
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 */


#ifndef __CAAM_H__
#define	__CAAM_H__

//! @name Error codes
//@{
#if !defined(SUCCESS)
#define SUCCESS (0)
#endif

#define ERROR_ANY           (-1)
#define ERROR_IN_PAGE_ALLOC (1)



void caam_open(void);

////////////////////////////////////////////////////////////////////////////////
//! @brief SHA256 - generates hash of data using CAAM.
//!
//!
//! @return SUCCESS
//! @return ERROR_XXX
////////////////////////////////////////////////////////////////////////////////
uint32_t caam_hash_sha();

#endif /* __CAAM_H__ */
