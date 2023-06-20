/*
  Copyright (c) 2005, Dominik Reichl <dominik.reichl@t-online.de>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  - Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer. 
  - Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
  - Neither the name of ReichlSoft nor the names of its contributors may be
    used to endorse or promote products derived from this software without
    specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include "KeeCryptLib.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <tchar.h>
#include "Lib/Hash/sha2.h"
#include "Lib/Cipher/aes.h"
#include "BufCrypt.h"
#include "RandomSrc.h"

#define KC_MAX_FILE_BUFFER       8000
#define KC_KEY_TRANSFORM_ROUNDS 32000

static TCHAR g_szLibrary[] = _T("KeeCrypt File Encryption Library");
static TCHAR g_szCopy[] = _T("Copyright (c) 2005 Dominik Reichl");

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(fdwReason);
	UNREFERENCED_PARAMETER(lpvReserved);

	return TRUE;
}

#define KCF_CLEANUP { CloseHandle(hOut); CloseHandle(hIn); }

C_FN_SHARE DWORD KcEncryptFile(BOOL bEncrypt, LPCTSTR lpInFile, LPCTSTR lpOutFile, LPCTSTR lpPassword)
{
	HANDLE hIn;
	HANDLE hOut;
	BYTE aBuf[KC_MAX_FILE_BUFFER], aBuf2[32], aBuf3[32];
	BYTE aMasterSeed[32], aMasterKey[32], aCounter[16], aStoredHash[32], aMasterTransformKey[32];
	BYTE *pb11;
	BYTE *pb12;
	BYTE *pb21;
	BYTE *pb22;
	DWORD i, dwUserKeyLen, dwRead = 0, dwWritten = 0;
	aes_encrypt_ctx aes;
	sha256_ctx sha;

	if(lpInFile == NULL) return KCERR_INVALID_PARAM;
	if(lpInFile[0] == 0) return KCERR_INVALID_PARAM;
	if(lpOutFile == NULL) return KCERR_INVALID_PARAM;
	if(lpOutFile[0] == 0) return KCERR_INVALID_PARAM;
	if(lpPassword == NULL) return KCERR_INVALID_PARAM;

	if(_tcscmp(lpInFile, lpOutFile) == 0) return KCERR_INVALID_PARAM;

	dwUserKeyLen = (DWORD)_tcslen(lpPassword);

	hIn = CreateFile(lpInFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hIn == INVALID_HANDLE_VALUE) return KCERR_NOACCESS_INFILE;

	hOut = CreateFile(lpOutFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hOut == INVALID_HANDLE_VALUE) { CloseHandle(hIn); hIn = NULL; return KCERR_NOACCESS_OUTFILE; }

	if(bEncrypt != FALSE) // bEncrypt == TRUE
	{
		GenRandom256Bits(aMasterSeed);
		memcpy(aCounter, aMasterSeed, 16);

		GenRandom256Bits(aMasterSeed);
		GenRandom256Bits(aMasterTransformKey);

		// Hash the whole plaintext file
		sha256_begin(&sha);
		while(1)
		{
			ReadFile(hIn, aBuf, KC_MAX_FILE_BUFFER, &dwRead, NULL);
			if(dwRead == 0) break;

			sha256_hash(aBuf, dwRead, &sha);

			if(dwRead != KC_MAX_FILE_BUFFER) break;
		}
		sha256_end(aStoredHash, &sha);
		SetFilePointer(hIn, 0, 0, FILE_BEGIN);

		if(WriteFile(hOut, aMasterSeed, 32, &dwWritten, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_WRITE; }
		if(WriteFile(hOut, aCounter, 16, &dwWritten, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_WRITE; }
		if(WriteFile(hOut, aMasterTransformKey, 32, &dwWritten, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_WRITE; }
	}
	else // bEncrypt == FALSE
	{
		if(ReadFile(hIn, aMasterSeed, 32, &dwRead, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_READ; }
		if(ReadFile(hIn, aCounter, 16, &dwRead, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_READ; }
		if(ReadFile(hIn, aMasterTransformKey, 32, &dwRead, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_READ; }
	}

	// Generate master key
	sha256_begin(&sha);
	sha256_hash(aMasterSeed, 32, &sha);
	if(dwUserKeyLen != 0) sha256_hash((const BYTE *)lpPassword, dwUserKeyLen * sizeof(TCHAR), &sha);
	sha256_end(aMasterKey, &sha);

	// Encrypt the key (adds constant time factor)
	aes_encrypt_key256(aMasterTransformKey, &aes);
	memcpy(aBuf2, aMasterKey, 32);
	pb11 = (BYTE *)aBuf2; pb12 = &aBuf2[16]; pb21 = (BYTE *)aBuf3; pb22 = &aBuf3[16];
	for(i = 0; i < (KC_KEY_TRANSFORM_ROUNDS / 2); i++)
	{
		aes_encrypt(pb11, pb21, &aes);
		aes_encrypt(pb21, pb11, &aes);
		aes_encrypt(pb12, pb22, &aes);
		aes_encrypt(pb22, pb12, &aes);
	}

	// Hash again
	sha256_begin(&sha);
	sha256_hash(aBuf2, 32, &sha);
	sha256_end(aMasterKey, &sha); // This is the final key used for encryption/decryption

	// Initialize cipher and hash
	aes_encrypt_key256(aMasterKey, &aes); // CTR mode
	sha256_begin(&sha); // Used for data integrity check / key validation

	// Create/load and encrypt/decrypt the hash of the data
	if(bEncrypt != FALSE) // bEncrypt == TRUE
	{
		KcCryptBuffer(aStoredHash, 32, &aes, aCounter);

		if(WriteFile(hOut, aStoredHash, 32, &dwWritten, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_WRITE; }
	}
	else // bEncrypt == FALSE
	{
		if(ReadFile(hIn, aStoredHash, 32, &dwRead, NULL) == FALSE)
			{ KCF_CLEANUP; return KCERR_FILEERR_READ; }

		KcCryptBuffer(aStoredHash, 32, &aes, aCounter);
	}

	// Encrypt/decrypt the data
	while(1)
	{
		ReadFile(hIn, aBuf, KC_MAX_FILE_BUFFER, &dwRead, NULL);
		if(dwRead == 0) break;

		KcCryptBuffer(aBuf, dwRead, &aes, aCounter);

		if(bEncrypt == FALSE) sha256_hash(aBuf, dwRead, &sha);

		WriteFile(hOut, aBuf, dwRead, &dwWritten, NULL);
		if(dwRead != KC_MAX_FILE_BUFFER) break;
	}

	CloseHandle(hOut); hOut = NULL;
	CloseHandle(hIn); hIn = NULL;

	sha256_end(aBuf, &sha);
	if(bEncrypt == FALSE) // Verify computed hash against the stored hash
	{
		if(memcmp(aBuf, aStoredHash, 32) != 0)
		{
			DeleteFile(lpOutFile);
			return KCERR_FAILED;
		}
	}

	return KCERR_SUCCESS;
}

C_FN_SHARE DWORD KcSelfTest()
{
	DWORD i, dwRet = KCTESTERR_SUCCESS;
	BYTE aBuf[32];
	BYTE aBuf2[32];
	aes_encrypt_ctx aes;
	sha256_ctx sha;

	const BYTE ct1[16] = { 0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
		0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92 };
	const BYTE key2[32] = { 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x58,
		0x5A, 0x5B, 0x5C, 0x5D, 0x5F, 0x60, 0x61, 0x62,
		0x64, 0x65, 0x66, 0x67, 0x69, 0x6A, 0x6B, 0x6C,
		0x6E, 0x6F, 0x70, 0x71, 0x73, 0x74, 0x75, 0x76 };
	const BYTE pt2[16] = { 0x05, 0x04, 0x07, 0x06, 0x74, 0x77, 0x76, 0x79,
		0x56, 0x57, 0x50, 0x51, 0x22, 0x1D, 0x1C, 0x1F };
	const BYTE ct2[16] = { 0x74, 0x44, 0x52, 0x70, 0x95, 0x83, 0x8F, 0xE0,
		0x80, 0xFC, 0x2B, 0xCD, 0xD3, 0x08, 0x47, 0xEB };
	const BYTE ct3[16] = { 0x73, 0x37, 0x6F, 0xBB, 0xF6, 0x54, 0xD0, 0x68,
		0x6E, 0x0E, 0x84, 0x00, 0x14, 0x77, 0x10, 0x6B };

	const BYTE sha1[32] = { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
	const BYTE sha2[32] = { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };
	const BYTE sha3[32] = { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
		0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
		0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
		0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };

	for(i = 0; i < 32; i++) aBuf[i] = (BYTE)i;
	aes_encrypt_key256(aBuf, &aes);
	aes_encrypt(aBuf, aBuf2, &aes);
	if(memcmp(aBuf2, ct1, 16) != 0) dwRet |= KCTESTERR_CIPHER;

	aes_encrypt_key256(key2, &aes);
	aes_encrypt(pt2, aBuf2, &aes);
	if(memcmp(aBuf2, ct2, 16) != 0) dwRet |= KCTESTERR_CIPHER;

	memset(aBuf, 0, 32);
	aes_encrypt_key256(aBuf, &aes);
	aBuf[0] = 0x10;
	aes_encrypt(aBuf, aBuf2, &aes);
	if(memcmp(aBuf2, ct3, 16) != 0) dwRet |= KCTESTERR_CIPHER;

	sha256_begin(&sha);
	sha256_hash((const BYTE *)"abc", 3, &sha);
	sha256_end(aBuf, &sha);
	if(memcmp(aBuf, sha1, 32) != 0) dwRet |= KCTESTERR_HASH;

	sha256_begin(&sha);
	sha256_hash((const BYTE *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, &sha);
	sha256_end(aBuf, &sha);
	if(memcmp(aBuf, sha2, 32) != 0) dwRet |= KCTESTERR_HASH;

	sha256_begin(&sha);
	for(i = 0; i < 10000; i++)
		sha256_hash((const BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 100, &sha);
	sha256_end(aBuf, &sha);
	if(memcmp(aBuf, sha3, 32) != 0) dwRet |= KCTESTERR_HASH;

	return dwRet;
}
