#ifndef __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__
#define __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

typedef struct __display_name {
	char m_name[256];
	char m_id[256];
	char m_key[256];
	char m_devstr[256];
	int m_state;
} display_name_t , *pdisplay_name_t;

typedef struct __display_mode {
	char m_name[256];
	int m_width;
	int m_height;
	int m_refresh;
} display_mode_t,*pdisplay_mode_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API int enum_display_devices(int freed,pdisplay_name_t* ppdevices, int *psize);
WINLIB_API int enum_display_mode(char* devname, pdisplay_mode_t* ppmode, int *psize);
WINLIB_API int set_display_mode(pdisplay_mode_t pmode);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_GUI_H_5A7B57E05E725571FEABB5C3CD871E7E__ */
