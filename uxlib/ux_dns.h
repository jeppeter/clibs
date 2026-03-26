#ifndef __UX_DNS_H_039A8D012483FADEDCDCF3E6F9C5A608__
#define __UX_DNS_H_039A8D012483FADEDCDCF3E6F9C5A608__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

void* start_dns_query(int aftype,const char* name, char* portstr);
void free_dns_query(void** ppdnsqry);
int is_dns_query_completed(void* pdnsqry);
int dns_query_get_complete_evt(void* pdnsqry);
int dns_query_get_result(void* pdnsqry,int idx,char** ppstr, int *psize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_DNS_H_039A8D012483FADEDCDCF3E6F9C5A608__ */
