#ifndef __WIN_DNS_H_F476C674B0F5F9B07B7F816311F6739C__
#define __WIN_DNS_H_F476C674B0F5F9B07B7F816311F6739C__


#include <win_types.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API void* start_dns_query(int type,const char* name,const char* portstr);
WINLIB_API void free_dns_query(void** ppdnsqry);
WINLIB_API int is_dns_query_completed(void* pdnsqry);
WINLIB_API int dns_query_time_left(void* pdnsqry, int timeout);
WINLIB_API int is_dns_query_error(void* pdnsqry);
WINLIB_API HANDLE dns_query_get_complete_evt(void* pdnsqry);
WINLIB_API HANDLE dns_query_get_error_evt(void* pdnsqry);
WINLIB_API int dns_query_get_result(void* pdnsqry,int idx,char** ppstr, int *psize);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_DNS_H_F476C674B0F5F9B07B7F816311F6739C__ */
