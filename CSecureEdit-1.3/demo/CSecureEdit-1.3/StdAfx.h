/*
  Copyright (c) 2003-2011 Dominik Reichl <dominik.reichl@t-online.de>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  - Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
  - Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

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

#if !defined(AFX_STDAFX_H__92F72B45_8867_11D7_BF16_0050BF14F5CC__INCLUDED_)
#define AFX_STDAFX_H__92F72B45_8867_11D7_BF16_0050BF14F5CC__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

#ifndef _SECURE_ATL
#define _SECURE_ATL 1
#endif

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _AFX_ALL_WARNINGS

#ifndef MMNOMIDI
#define MMNOMIDI
#endif
#ifndef MMNOAUX
#define MMNOAUX
#endif
#ifndef MMNOMIXER
#define MMNOMIXER
#endif

#if (_MSC_VER >= 1400) // Manifest linking
#if defined(_M_IX86)
#pragma comment(linker, "/manifestdependency:\"type='win32' " \
	"name='Microsoft.Windows.Common-Controls' " \
	"version='6.0.0.0' " \
	"processorArchitecture='x86' " \
	"publicKeyToken='6595b64144ccf1df' " \
	"language='*'\"")
#elif defined(_M_AMD64)
#pragma comment(linker, "/manifestdependency:\"type='win32' " \
	"name='Microsoft.Windows.Common-Controls' " \
	"version='6.0.0.0' " \
	"processorArchitecture='amd64' " \
	"publicKeyToken='6595b64144ccf1df' " \
	"language='*'\"")
#elif defined(_M_IA64)
#pragma comment(linker, "/manifestdependency:\"type='win32' " \
	"name='Microsoft.Windows.Common-Controls' " \
	"version='6.0.0.0' " \
	"processorArchitecture='ia64' " \
	"publicKeyToken='6595b64144ccf1df' " \
	"language='*'\"")
#endif
#endif // (_MSC_VER >= 1400)

#include <afxwin.h>
#include <afxext.h>
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>
#endif // _AFX_NO_AFXCMN_SUPPORT

//{{AFX_INSERT_LOCATION}}

#endif // !defined(AFX_STDAFX_H__92F72B45_8867_11D7_BF16_0050BF14F5CC__INCLUDED_)
