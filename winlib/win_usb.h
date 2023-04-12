#ifndef __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__
#define __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__

#include <win_types.h>

typedef struct __usb_dev {
	uint32_t m_vendorid;
	uint32_t m_prodid;
	uint8_t  m_path[256];
} usb_dev_t, *pusb_dev_t;

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


WINLIB_API int list_usb_devices(int freed, pusb_dev_t* ppur, int *psize);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__ */
