// mymfc28CView.cpp : implementation of the CMymfc28CView class
//

#include "stdafx.h"
#include "mymfc28C.h"

#include "mymfc28CDoc.h"
#include "mymfc28CView.h"
#include "Interface.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// {692D03A4-C689-11CE-B337-88EA36DE9E4E}
static const IID IID_IMotion =
{ 0x692d03a4, 0xc689, 0x11ce, { 0xb3, 0x37, 0x88, 0xea, 0x36, 0xde, 0x9e, 0x4e } };

// {692D03A5-C689-11CE-B337-88EA36DE9E4E}
static const IID IID_IVisual =
{ 0x692d03a5, 0xc689, 0x11ce, { 0xb3, 0x37, 0x88, 0xea, 0x36, 0xde, 0x9e, 0x4e } };

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CView

IMPLEMENT_DYNCREATE(CMymfc28CView, CView)

BEGIN_MESSAGE_MAP(CMymfc28CView, CView)
	//{{AFX_MSG_MAP(CMymfc28CView)
	ON_COMMAND(ID_TEST_SPACESHIP, OnTestSpaceship)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CView construction/destruction

CMymfc28CView::CMymfc28CView()
{
	// TODO: add construction code here

}

CMymfc28CView::~CMymfc28CView()
{
}

BOOL CMymfc28CView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs

	return CView::PreCreateWindow(cs);
}

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CView drawing

void CMymfc28CView::OnDraw(CDC* pDC)
{
	CMymfc28CDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	// TODO: add draw code for native data here
}

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CView diagnostics

#ifdef _DEBUG
void CMymfc28CView::AssertValid() const
{
	CView::AssertValid();
}

void CMymfc28CView::Dump(CDumpContext& dc) const
{
	CView::Dump(dc);
}

CMymfc28CDoc* CMymfc28CView::GetDocument() // non-debug version is inline
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CMymfc28CDoc)));
	return (CMymfc28CDoc*)m_pDocument;
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMymfc28CView message handlers

void CMymfc28CView::OnTestSpaceship() 
{
	// TODO: Add your command handler code here
	CLSID clsid;
    LPCLASSFACTORY pClf; 
    LPUNKNOWN pUnk;
    IMotion* pMot;
    IVisual* pVis;

    HRESULT hr;
    if ((hr = ::CLSIDFromProgID(L"Spaceship", &clsid)) != NOERROR)
	{
        TRACE("unable to find Program ID -- error = %x\n", hr);
        return;
    }
    if ((hr = ::CoGetClassObject(clsid, CLSCTX_INPROC_SERVER, NULL, IID_IClassFactory,
		(void **) &pClf)) != NOERROR)
	{
        TRACE("unable to find CLSID -- error = %x\n", hr);
        return;
    }

    pClf->CreateInstance(NULL, IID_IUnknown, (void**) &pUnk);
    pUnk->QueryInterface(IID_IMotion, (void**) &pMot); // All three
    pMot->QueryInterface(IID_IVisual, (void**) &pVis); //  pointers
                                                       //  should work
    TRACE("main: pUnk = %p, pMot = %p, pDis = %p\n", pUnk, pMot, pVis);

    // Test all the interface virtual functions
    pMot->Fly();
    int nPos = pMot->GetPosition();
    TRACE("nPos = %d\n", nPos);
    pVis->Display();

    pClf->Release();
    pUnk->Release();
    pMot->Release();
    pVis->Release();
    AfxMessageBox("Test succeeded. See Debug window for output.");
}
