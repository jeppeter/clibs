// mymfc28CDoc.cpp : implementation of the CMymfc28CDoc class
//

#include "stdafx.h"
#include "mymfc28C.h"

#include "mymfc28CDoc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CDoc

IMPLEMENT_DYNCREATE(CMymfc28CDoc, CDocument)

BEGIN_MESSAGE_MAP(CMymfc28CDoc, CDocument)
	//{{AFX_MSG_MAP(CMymfc28CDoc)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CDoc construction/destruction

CMymfc28CDoc::CMymfc28CDoc()
{
	// TODO: add one-time construction code here

}

CMymfc28CDoc::~CMymfc28CDoc()
{
}

BOOL CMymfc28CDoc::OnNewDocument()
{
	if (!CDocument::OnNewDocument())
		return FALSE;

	// TODO: add reinitialization code here
	// (SDI documents will reuse this document)

	return TRUE;
}



/////////////////////////////////////////////////////////////////////////////
// CMymfc28CDoc serialization

void CMymfc28CDoc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
		// TODO: add storing code here
	}
	else
	{
		// TODO: add loading code here
	}
}

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CDoc diagnostics

#ifdef _DEBUG
void CMymfc28CDoc::AssertValid() const
{
	CDocument::AssertValid();
}

void CMymfc28CDoc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CDoc commands
