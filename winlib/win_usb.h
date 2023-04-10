#ifndef __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__
#define __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__

#include <win_types.h>

typedef struct __usb_dev {	
} usb_dev_t, *pusb_dev_t;

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

WINLIB_API int list_usb_roots(int freed, pusb_dev_t* ppur, int *psize);


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/




#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_USB_H_60D69BAC37D7039065EAF9A0286A7FA5__ */
