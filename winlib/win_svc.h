#ifndef __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__
#define __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  SVC_START_ON_BOOT            1
#define  SVC_START_ON_AUTO            2
#define  SVC_START_ON_SYSTEM          3
#define  SVC_START_ON_DEMAND          4
#define  SVC_START_ON_DISABLED        5


int is_service_exist(const char* name);
int is_service_running(const char* name);
int is_service_forbid(const char* name);

int stop_service(const char* name);
int forbid_service(const char* name);
int enable_service(const char* name);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__ */
