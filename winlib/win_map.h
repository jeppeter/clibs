#ifndef __WIN_MAP_H_0A8F56E4926A88B6BBD59FDAF949B028__
#define __WIN_MAP_H_0A8F56E4926A88B6BBD59FDAF949B028__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#define   MAP_FILE_WRITE               0x4
#define   MAP_FILE_READ                0x2
#define   MAP_FILE_EXEC                0x1

#define   MAP_FILE_FLAGS               (MAP_FILE_WRITE | MAP_FILE_READ | MAP_FILE_EXEC)

WINLIB_API int map_buffer(char* name,int flag,int size,void** ppmap);
WINLIB_API int write_buffer(void* pmap, int offset,void* pbuf, int size);
WINLIB_API int read_buffer(void* pmap, int offset, void* pbuf, int size);
WINLIB_API void unmap_buffer(void** ppmap);

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_MAP_H_0A8F56E4926A88B6BBD59FDAF949B028__ */
