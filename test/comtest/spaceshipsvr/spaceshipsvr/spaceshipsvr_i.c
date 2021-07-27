

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


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



#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        EXTERN_C __declspec(selectany) const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif // !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IATLSpaceship,0xace53709,0xfa8f,0x452e,0x99,0xe8,0xd5,0x79,0x85,0xc5,0x37,0x17);


MIDL_DEFINE_GUID(IID, IID_IMotion,0x692D03A4,0xC689,0x11CE,0xB3,0x37,0x88,0xEA,0x36,0xDE,0x9E,0x4E);


MIDL_DEFINE_GUID(IID, IID_IVisual,0x692D03A5,0xC689,0x11CE,0xB3,0x37,0x88,0xEA,0x36,0xDE,0x9E,0x4E);


MIDL_DEFINE_GUID(IID, LIBID_spaceshipsvrLib,0xc1b1ca83,0xb9bf,0x4e99,0x8b,0xe6,0xcc,0x5d,0x16,0xb6,0x25,0x70);


MIDL_DEFINE_GUID(CLSID, CLSID_ATLSpaceship,0x77562bec,0xdd02,0x4645,0xad,0xa1,0xd0,0xc2,0x54,0xa9,0x8d,0xe7);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



