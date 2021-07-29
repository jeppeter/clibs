// mymfc28CDoc.h : interface of the CMymfc28CDoc class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_MYMFC28CDOC_H__339836BB_BA11_46D2_9D5A_9A3784EF62F2__INCLUDED_)
#define AFX_MYMFC28CDOC_H__339836BB_BA11_46D2_9D5A_9A3784EF62F2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


class CMymfc28CDoc : public CDocument
{
protected: // create from serialization only
	CMymfc28CDoc();
	DECLARE_DYNCREATE(CMymfc28CDoc)

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMymfc28CDoc)
	public:
	virtual BOOL OnNewDocument();
	virtual void Serialize(CArchive& ar);
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CMymfc28CDoc();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// Generated message map functions
protected:
	//{{AFX_MSG(CMymfc28CDoc)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MYMFC28CDOC_H__339836BB_BA11_46D2_9D5A_9A3784EF62F2__INCLUDED_)
