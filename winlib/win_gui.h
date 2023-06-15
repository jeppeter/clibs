#ifndef __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__
#define __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#include <win_types.h>

typedef struct __display_name {
	char m_name[256];
	char m_devname[256];
	char m_id[256];
	char m_key[256];
	char m_devstr[256];
	int m_state;
} display_name_t , *pdisplay_name_t;

typedef struct __display_mode {
	char m_name[256];
	char m_devname[256];
	int m_width;
	int m_height;
	int m_refresh;
} display_mode_t,*pdisplay_mode_t;

typedef struct __display_info {
	char m_sourcename[256];
	char m_targetname[256];
	char m_adaptername[256];
	uint32_t m_targetid;
	uint32_t m_sourceid;
	uint32_t m_persistence;
	uint32_t m_basetype;
} display_info_t, *pdisplay_info_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API int enum_display_devices(int freed,pdisplay_name_t* ppdevices, int *psize);
WINLIB_API int enum_display_mode(char* devname, pdisplay_mode_t* ppmode, int *psize);
WINLIB_API int set_display_mode(pdisplay_mode_t pmode,DWORD flags);
WINLIB_API int get_display_info(int freed,pdisplay_info_t *ppinfo,int *psize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__ */
