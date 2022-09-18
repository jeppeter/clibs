#ifndef __WIN_SERIAL_H_744FE42CD4A1F558BA43170D0A3657EC__
#define __WIN_SERIAL_H_744FE42CD4A1F558BA43170D0A3657EC__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API void* open_serial(const char* name, int baudrate);
WINLIB_API void close_serial(void** ppcom);
WINLIB_API int read_serial(void* pcom1, void* pbuf, int bufsize);
WINLIB_API int write_serial(void* pcom1, void* pbuf,int bufsize);
WINLIB_API HANDLE get_serial_read_handle(void* pcom1);
WINLIB_API HANDLE get_serial_write_handle(void* pcom1);
WINLIB_API int complete_serial_read(void* pcom1);
WINLIB_API int complete_serial_write(void* pcom1);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_SERIAL_H_744FE42CD4A1F558BA43170D0A3657EC__ */
