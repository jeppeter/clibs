// mymfc28B.h : main header file for the MYMFC28B DLL
//

#if !defined(AFX_MYMFC28B_H__D8F6203B_8E68_4519_81E0_04E767BD71A9__INCLUDED_)
#define AFX_MYMFC28B_H__D8F6203B_8E68_4519_81E0_04E767BD71A9__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CMymfc28BApp
// See mymfc28B.cpp for the implementation of this class
//

class CMymfc28BApp : public CWinApp
{
public:
	CMymfc28BApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMymfc28BApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CMymfc28BApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MYMFC28B_H__D8F6203B_8E68_4519_81E0_04E767BD71A9__INCLUDED_)
