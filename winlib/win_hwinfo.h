#ifndef __WIN_HWINFO_H_F3D56C34D985D7525428A4E503638064__
#define __WIN_HWINFO_H_F3D56C34D985D7525428A4E503638064__


#include <win_types.h>


#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


typedef struct __hw_prop {
	char* m_propguid;
	uint8_t* m_propbuf;
	ULONG m_propbuflen;
	ULONG m_propbufsize;
	int m_propguidsize;
	int m_propguididx;
} hw_prop_t,*phw_prop_t;

typedef struct __hw_info {
	phw_prop_t* m_proparr;
	int m_propsize;
	int m_proplen;
} hw_info_t,*phw_info_t;


#define  GUID_NULL_PTR ((LPGUID)0x1)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API int get_hw_infos(LPGUID pguid, DWORD flags,phw_info_t** pppinfos, int *psize);
WINLIB_API int get_hw_prop(phw_info_t pinfo, char* propguid, int propidx, uint8_t** ppbuf, int *psize);
WINLIB_API int get_guid_str(LPGUID pguid, char** ppstr, int *psize);
WINLIB_API int guid_from_str2(LPGUID pguid, char* pstr);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_HWINFO_H_F3D56C34D985D7525428A4E503638064__ */
