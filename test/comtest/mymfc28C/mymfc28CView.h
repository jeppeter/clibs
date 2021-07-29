// mymfc28CView.h : interface of the CMymfc28CView class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_MYMFC28CVIEW_H__879DF95D_3344_4665_984C_E2288F1836E8__INCLUDED_)
#define AFX_MYMFC28CVIEW_H__879DF95D_3344_4665_984C_E2288F1836E8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


class CMymfc28CView : public CView
{
protected: // create from serialization only
	CMymfc28CView();
	DECLARE_DYNCREATE(CMymfc28CView)

// Attributes
public:
	CMymfc28CDoc* GetDocument();

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMymfc28CView)
	public:
	virtual void OnDraw(CDC* pDC);  // overridden to draw this view
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	protected:
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CMymfc28CView();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// Generated message map functions
protected:
	//{{AFX_MSG(CMymfc28CView)
	afx_msg void OnTestSpaceship();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

#ifndef _DEBUG  // debug version in mymfc28CView.cpp
inline CMymfc28CDoc* CMymfc28CView::GetDocument()
   { return (CMymfc28CDoc*)m_pDocument; }
#endif

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MYMFC28CVIEW_H__879DF95D_3344_4665_984C_E2288F1836E8__INCLUDED_)
