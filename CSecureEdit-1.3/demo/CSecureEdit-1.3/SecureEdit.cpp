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

#include "StdAfx.h"
#include "SecureEdit.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Disable incorrect "universal-character-name encountered in source" warning
#pragma warning(push)
#pragma warning(disable: 4428)

/////////////////////////////////////////////////////////////////////////////
// CSecureEdit

IMPLEMENT_DYNCREATE(CSecureEdit, CEdit)

CSecureEdit::CSecureEdit() : m_bPasswordStyle(true), m_pSecDrop(NULL)
{
#ifndef _UNICODE
	m_chDisplayMask = _T('*');
	m_chDataMask = _T('×');
#else
	m_chDisplayMask = _T('\u25CF');
	m_chDataMask = _T('\u25CF');
#endif
}

CSecureEdit::~CSecureEdit()
{
}

BEGIN_MESSAGE_MAP(CSecureEdit, CEdit)
	//{{AFX_MSG_MAP(CSecureEdit)
	ON_CONTROL_REFLECT(EN_UPDATE, OnUpdate)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////

void CSecureEdit::OnUpdate() 
{
	CString strWnd;
	GetWindowText(strWnd); // Current text (Windows has updated it already)
	const int nWndLen = strWnd.GetLength();
	const DWORD dwPos = GetSel() & 0xFFFF; // Current cursor position

	LPCTSTR lpWnd = strWnd.GetBuffer(nWndLen);

	int nOldLeft = -1;
	for(int l = 0; l < nWndLen; ++l)
	{
		if(lpWnd[l] != m_chDataMask) // New character
		{
			nOldLeft = l;
			break;
		}
	}

	int nOldRight = -1;
	for(int r = nWndLen - 1; r >= 0; --r)
	{
		if(lpWnd[r] != m_chDataMask) // New character
		{
			nOldRight = nWndLen - 1 - r;
			break;
		}
	}

	strWnd.ReleaseBuffer();

	const int nOldLen = m_strRealText.GetLength();

	CString strNewPart;
	if(nOldLeft == -1) // No new character; maybe deleted some?
	{
		ASSERT(nOldRight == -1);
		nOldLeft = static_cast<int>(dwPos);
		nOldRight = nWndLen - static_cast<int>(dwPos);

		if((nOldLeft + nOldRight) == nOldLen) return;
	}
	else // At least one new character
	{
		ASSERT(nOldRight >= 0);
		strNewPart = strWnd.Mid(nOldLeft, nWndLen - nOldRight - nOldLeft);
	}

	if(nOldLeft > nOldLen) nOldLeft = nOldLen;
	if(nOldRight > nOldLen) nOldRight = nOldLen;

	SetRealText(m_strRealText.Left(nOldLeft) + strNewPart +
		m_strRealText.Right(nOldRight), dwPos);
}

void CSecureEdit::SetRealText(LPCTSTR pszNewText, DWORD dwCursorPos)
{
	if(pszNewText == NULL) { ASSERT(false); return; }

	if(m_bPasswordStyle) SetPasswordChar(m_chDisplayMask);

	m_strRealText = pszNewText;

	CString strHidden = CString(m_chDataMask, m_strRealText.GetLength());
	SetWindowText(strHidden);

	if(dwCursorPos > 0) SetSel(dwCursorPos, dwCursorPos, FALSE);
}

CString CSecureEdit::GetRealText() const
{
	return m_strRealText;
}

void CSecureEdit::EnablePasswordStyle(bool bEnable)
{
	m_bPasswordStyle = bEnable;
}

bool CSecureEdit::_RegisterDropTarget(bool bRegister)
{
	if(bRegister && (m_pSecDrop == NULL))
	{
		m_pSecDrop = new CSecureDropTarget(this);
		return (m_pSecDrop->Register(this) != FALSE);
	}
	else if(!bRegister && (m_pSecDrop != NULL))
	{
		m_pSecDrop->Revoke();
		m_pSecDrop = NULL;
		return true;
	}

	return false;
}

void CSecureEdit::PreSubclassWindow()
{
	CEdit::PreSubclassWindow();
	_RegisterDropTarget(true);
}

/////////////////////////////////////////////////////////////////////////////
// CSecureDropTarget

CSecureDropTarget::CSecureDropTarget(CSecureEdit* pControl) :
	m_pControl(pControl), COleDropTarget()
{
}

DROPEFFECT CSecureDropTarget::OnDragEnter(CWnd* pWnd, COleDataObject* pDataObject,
	DWORD dwKeyState, CPoint point)
{
	return this->OnDragOver(pWnd, pDataObject, dwKeyState, point);
}

DROPEFFECT CSecureDropTarget::OnDragOver(CWnd* pWnd, COleDataObject* pDataObject,
	DWORD dwKeyState, CPoint point)
{
	ASSERT(m_pControl != NULL); if(m_pControl == NULL) return DROPEFFECT_NONE;
	ASSERT(pWnd == m_pControl); if(pWnd != m_pControl) return DROPEFFECT_NONE;
	ASSERT(pDataObject != NULL); if(pDataObject == NULL) return DROPEFFECT_NONE;

	UNREFERENCED_PARAMETER(dwKeyState);
	UNREFERENCED_PARAMETER(point);

	BOOL bHasFormat = FALSE;
	bHasFormat |= pDataObject->IsDataAvailable(CF_OEMTEXT, NULL);
	bHasFormat |= pDataObject->IsDataAvailable(CF_TEXT, NULL);
	bHasFormat |= pDataObject->IsDataAvailable(CF_UNICODETEXT, NULL);

	return ((bHasFormat != FALSE) ? DROPEFFECT_COPY : DROPEFFECT_NONE);
}

BOOL CSecureDropTarget::OnDrop(CWnd* pWnd, COleDataObject* pDataObject,
	DROPEFFECT dropEffect, CPoint point)
{
	ASSERT(m_pControl != NULL); if(m_pControl == NULL) return DROPEFFECT_NONE;
	ASSERT(pWnd == m_pControl); if(pWnd != m_pControl) return FALSE;
	ASSERT(pDataObject != NULL); if(pDataObject == NULL) return FALSE;

	UNREFERENCED_PARAMETER(dropEffect);
	UNREFERENCED_PARAMETER(point);

	if(pDataObject->IsDataAvailable(CF_UNICODETEXT, NULL) != FALSE)
	{
		HGLOBAL hUni = pDataObject->GetGlobalData(CF_UNICODETEXT, NULL);
		if(hUni == NULL) { ASSERT(FALSE); return FALSE; }

		LPCWSTR lpUni = (LPCWSTR)GlobalLock(hUni);
		if(lpUni == NULL) { ASSERT(FALSE); return FALSE; }

		CW2CT strText(lpUni);
		m_pControl->ReplaceSel(strText, FALSE);

		GlobalUnlock(hUni);
	}
	else if((pDataObject->IsDataAvailable(CF_TEXT, NULL) != FALSE) ||
		(pDataObject->IsDataAvailable(CF_OEMTEXT, NULL) != FALSE))
	{
		HGLOBAL hAnsi = pDataObject->GetGlobalData(CF_TEXT, NULL);
		if(hAnsi == NULL) hAnsi = pDataObject->GetGlobalData(CF_OEMTEXT, NULL);
		if(hAnsi == NULL) { ASSERT(FALSE); return FALSE; }

		LPCSTR lpAnsi = (LPCSTR)GlobalLock(hAnsi);
		if(lpAnsi == NULL) { ASSERT(FALSE); return FALSE; }

		CA2CT strText(lpAnsi);
		m_pControl->ReplaceSel(strText, FALSE);

		GlobalUnlock(hAnsi);
	}
	else return FALSE;

	return TRUE;
}

#pragma warning(pop)
