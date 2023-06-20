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

#ifndef ___KEECRYPTLIB_H___
#define ___KEECRYPTLIB_H___

#include <windows.h>

// Return values for KcEncryptFile
#define KCERR_SUCCESS          0
#define KCERR_FAILED           1 // File corrupted or incorrect password
#define KCERR_INVALID_PARAM    2
#define KCERR_NOACCESS_INFILE  3
#define KCERR_NOACCESS_OUTFILE 4
#define KCERR_FILEERR_READ     5
#define KCERR_FILEERR_WRITE    6

// Return values for KcSelfTest
#define KCTESTERR_SUCCESS      0
#define KCTESTERR_CIPHER       1
#define KCTESTERR_HASH         2

#ifdef KCF_NODECL
#define C_FN_SHARE
#else
#ifdef C_FN_SHARE
#error C_FN_SHARE must not be defined.
#else
#ifdef _DLL
#define C_FN_SHARE extern "C" __declspec(dllimport)
#else
#define C_FN_SHARE extern "C" __declspec(dllexport)
#endif
#endif
#endif

#ifndef KCF_NODECL
C_FN_SHARE DWORD KcEncryptFile(BOOL bEncrypt, LPCTSTR lpInFile, LPCTSTR lpOutFile, LPCTSTR lpPassword);
C_FN_SHARE DWORD KcSelfTest();
#endif

typedef DWORD(WINAPI *LPKCENCRYPTFILE)(BOOL bEncrypt, LPCTSTR lpInFile, LPCTSTR lpOutFile, LPCTSTR lpPassword);
typedef DWORD(WINAPI *LPKCSELFTEST)();

#endif
