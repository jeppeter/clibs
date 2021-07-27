

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for spaceshipsvr.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __spaceshipsvr_i_h__
#define __spaceshipsvr_i_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IATLSpaceship_FWD_DEFINED__
#define __IATLSpaceship_FWD_DEFINED__
typedef interface IATLSpaceship IATLSpaceship;

#endif 	/* __IATLSpaceship_FWD_DEFINED__ */


#ifndef __ATLSpaceship_FWD_DEFINED__
#define __ATLSpaceship_FWD_DEFINED__

#ifdef __cplusplus
typedef class ATLSpaceship ATLSpaceship;
#else
typedef struct ATLSpaceship ATLSpaceship;
#endif /* __cplusplus */

#endif 	/* __ATLSpaceship_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"
#include "shobjidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IATLSpaceship_INTERFACE_DEFINED__
#define __IATLSpaceship_INTERFACE_DEFINED__

/* interface IATLSpaceship */
/* [unique][nonextensible][dual][uuid][object] */ 


EXTERN_C const IID IID_IATLSpaceship;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("ace53709-fa8f-452e-99e8-d57985c53717")
    IATLSpaceship : public IDispatch
    {
    public:
    };
    
    
#else 	/* C style interface */

    typedef struct IATLSpaceshipVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IATLSpaceship * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IATLSpaceship * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IATLSpaceship * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IATLSpaceship * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IATLSpaceship * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IATLSpaceship * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IATLSpaceship * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        END_INTERFACE
    } IATLSpaceshipVtbl;

    interface IATLSpaceship
    {
        CONST_VTBL struct IATLSpaceshipVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IATLSpaceship_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IATLSpaceship_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IATLSpaceship_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IATLSpaceship_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IATLSpaceship_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IATLSpaceship_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IATLSpaceship_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IATLSpaceship_INTERFACE_DEFINED__ */



#ifndef __spaceshipsvrLib_LIBRARY_DEFINED__
#define __spaceshipsvrLib_LIBRARY_DEFINED__

/* library spaceshipsvrLib */
/* [version][uuid] */ 


EXTERN_C const IID LIBID_spaceshipsvrLib;

EXTERN_C const CLSID CLSID_ATLSpaceship;

#ifdef __cplusplus

class DECLSPEC_UUID("77562bec-dd02-4645-ada1-d0c254a98de7")
ATLSpaceship;
#endif
#endif /* __spaceshipsvrLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


