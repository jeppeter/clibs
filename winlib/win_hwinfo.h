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
	int m_propbuflen;
	int m_propbufsize;
	int m_propguidsize;
	int m_reserv1;
} hw_prop_t,*phw_prop_t;

typedef struct __hw_info {
	phw_prop_t* m_proparr;
	int m_propsize;
	int m_proplen;
} hw_info_t,*phw_info_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API int get_hw_infos(LPGUID pguid, DWORD flags,phw_info_t** pppinfos, int *psize);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_HWINFO_H_F3D56C34D985D7525428A4E503638064__ */
