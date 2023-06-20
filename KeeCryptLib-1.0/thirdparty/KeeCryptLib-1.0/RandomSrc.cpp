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

#include "RandomSrc.h"
#include "Lib/Hash/sha2.h"

static DWORD g_dwCounter = 0;

void GenRandom256Bits(BYTE *pbStore32)
{
	sha256_ctx sha;
	DWORD dw;
	LARGE_INTEGER li;
	SYSTEMTIME st;
	POINT pt;
	MEMORYSTATUS ms;
	SYSTEM_INFO si;

	if(pbStore32 == NULL) return;

	sha256_begin(&sha);

	dw = g_dwCounter; g_dwCounter++;
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = GetTickCount();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	QueryPerformanceCounter(&li);
	sha256_hash((const BYTE *)&li, sizeof(LARGE_INTEGER), &sha);

	GetLocalTime(&st);
	sha256_hash((const BYTE *)&st, sizeof(SYSTEMTIME), &sha);

	GetCursorPos(&pt);
	sha256_hash((const BYTE *)&pt, sizeof(POINT), &sha);

	GetCaretPos(&pt);
	sha256_hash((const BYTE *)&pt, sizeof(POINT), &sha);

	GlobalMemoryStatus(&ms);
	sha256_hash((const BYTE *)&ms, sizeof(MEMORYSTATUS), &sha);

	dw = (DWORD)GetActiveWindow();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetCapture();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetClipboardOwner();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetClipboardViewer();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = GetCurrentProcessId();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetCurrentProcess();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = GetCurrentThreadId();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetCurrentThread();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetDesktopWindow();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetFocus();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetForegroundWindow();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetInputState();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = GetMessagePos();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetMessageTime();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetOpenClipboardWindow();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	dw = (DWORD)GetProcessHeap();
	sha256_hash((const BYTE *)&dw, sizeof(DWORD), &sha);

	GetSystemInfo(&si);
	sha256_hash((const BYTE *)&si, sizeof(SYSTEM_INFO), &sha);

	sha256_end(pbStore32, &sha);
}
