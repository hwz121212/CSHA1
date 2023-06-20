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

#include "BufCrypt.h"

void KcCryptBuffer(BYTE *pBuf, DWORD dwBufSize, aes_encrypt_ctx *pCipherCtx, BYTE *pCounter)
{
	BYTE *pIn = pBuf;
	BYTE buf[16];
	DWORD i, dwBlock;

	while(dwBufSize != 0)
	{
		dwBlock = (dwBufSize >= 16) ? 16 : dwBufSize;

		// CTR mode of encryption/decryption
		aes_encrypt(pCounter, buf, pCipherCtx);
		for(i = 0; i < dwBlock; i++) pIn[i] ^= buf[i];

		// Update CTR counter
		for(i = 0; i < 16; i++)
		{
			pCounter[i]++;
			if(pCounter[i] != 0) break;
		}

		pIn += 16;
		dwBufSize -= dwBlock;
	}
}