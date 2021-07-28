﻿// ATLSpaceship.h: CATLSpaceship 的声明

#pragma once
#include "resource.h"       // 主符号



#include "spaceshipsvr_i.h"



#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Windows CE 平台(如不提供完全 DCOM 支持的 Windows Mobile 平台)上无法正确支持单线程 COM 对象。定义 _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA 可强制 ATL 支持创建单线程 COM 对象实现并允许使用其单线程 COM 对象实现。rgs 文件中的线程模型已被设置为“Free”，原因是该模型是非 DCOM Windows CE 平台支持的唯一线程模型。"
#endif

using namespace ATL;


// CATLSpaceship

class ATL_NO_VTABLE CATLSpaceship :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CATLSpaceship, &CLSID_ATLSpaceship>,
	public IDispatchImpl<IATLSpaceship, &IID_IATLSpaceship, &LIBID_spaceshipsvrLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IDispatchImpl<IVisual, &IID_IVisual, &LIBID_spaceshipsvrLib,0>,
	public IDispatchImpl<IMotion, &IID_IMotion, &LIBID_spaceshipsvrLib, 0>
{
public:
	CATLSpaceship()
	{
		m_nColor = m_nAcceleration = m_nPosition = 0;
	}

DECLARE_REGISTRY_RESOURCEID(106)


BEGIN_COM_MAP(CATLSpaceship)
	COM_INTERFACE_ENTRY(IATLSpaceship)
	COM_INTERFACE_ENTRY(IMotion)
	COM_INTERFACE_ENTRY2(IDispatch, IATLSpaceship)
	COM_INTERFACE_ENTRY(IVisual)
END_COM_MAP()



	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:



	int m_nColor;
	int m_nAcceleration;
	int m_nPosition;
	STDMETHOD(CallStartFleet)(float fStarDate, BSTR* pbstrRecipient);
	STDMETHOD(Fly)();
	STDMETHOD(GetPosition)(long* nPosition);
	STDMETHOD(Display)();
};

OBJECT_ENTRY_AUTO(__uuidof(ATLSpaceship), CATLSpaceship)
