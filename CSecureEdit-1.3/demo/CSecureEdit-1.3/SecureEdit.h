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

// Version 1.3 (2011-07-22):
// - CSecureEdit is now distributed under a BSD-style license.
// - In Unicode builds, CSecureEdit now uses a dot as password masking
//   character.
// - The password control style is now set (when the user tries to copy
//   data out of the control, Windows shows a failure tooltip).
// - Added ability to accept text drops.
// - The password can now be retrieved using the GetRealText method
//   (instead of directly accessing the internal m_strRealText variable).
// - Improved change detection logic and performance of mask string
//   building.
// - Updated project files for Visual Studio 2008.
// - Added support for Aero theming in the demo application.
// - Minor other code improvements.

// Version 1.2 (2003-05-29):
// - The CSecureEdit class now supports Unicode, thanks to Steven Spencer
//   for support.

// Version 1.1 (2003-05-18):
// - Fixed a bug in the SetRealText function.

// Version 1.0 (2003-05-17):
// - First official release.

#ifndef AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_
#define AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <afxdisp.h>
#include <afxole.h>

/////////////////////////////////////////////////////////////////////////////

class CSecureDropTarget;

class CSecureEdit : public CEdit
{
public:
	DECLARE_DYNCREATE(CSecureEdit);

	CSecureEdit();
	virtual ~CSecureEdit();

	// Set the password
	void SetRealText(LPCTSTR pszNewText, DWORD dwCursorPos = 0);

	// Retrieve the entered password
	CString GetRealText() const;

	// If you want to take care of the password control style/character
	// on your own, you can disable the automatic configuration by
	// CSecureEdit using this method
	void EnablePasswordStyle(bool bEnable);

	//{{AFX_VIRTUAL(CSecureEdit)
	virtual void PreSubclassWindow();
	//}}AFX_VIRTUAL

private:
	bool _RegisterDropTarget(bool bRegister);

	TCHAR m_chDisplayMask;
	TCHAR m_chDataMask;

	bool m_bPasswordStyle;
	CSecureDropTarget* m_pSecDrop;

	CString m_strRealText;

protected:
	//{{AFX_MSG(CSecureEdit)
	afx_msg void OnUpdate();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

class CSecureDropTarget : public COleDropTarget
{
public:
	CSecureDropTarget(CSecureEdit* pControl);

private:
	CSecureEdit* m_pControl;

protected:
	// Implement COleDropTarget
	virtual DROPEFFECT OnDragEnter(CWnd* pWnd, COleDataObject* pDataObject,
		DWORD dwKeyState, CPoint point);
	virtual DROPEFFECT OnDragOver(CWnd* pWnd, COleDataObject* pDataObject,
		DWORD dwKeyState, CPoint point);
	virtual BOOL OnDrop(CWnd* pWnd, COleDataObject* pDataObject,
		DROPEFFECT dropEffect, CPoint point);
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}

#endif // AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_
