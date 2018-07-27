#ifndef __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__
#define __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


#define  SVC_START_ON_UNKNOWN         0
#define  SVC_START_ON_BOOT            1
#define  SVC_START_ON_SYSTEM          2
#define  SVC_START_ON_AUTO            3
#define  SVC_START_ON_DEMAND          4
#define  SVC_START_ON_DISABLED        5


#define  SVC_STATE_UNKNOWN            0
#define  SVC_STATE_STOPPED            1
#define  SVC_STATE_START_PENDING      2
#define  SVC_STATE_RUNNING            3
#define  SVC_STATE_STOP_PENDING       4
#define  SVC_STATE_PAUSED             5
#define  SVC_STATE_PAUSE_PENDING      6
#define  SVC_STATE_CONTINUE_PENDING   7


int is_service_exist(const char* name);
int is_service_running(const char* name);
int is_service_stopped(const char* name);
int service_start_mode(const char* name);
int service_running_mode(const char* name);


int stop_service(const char* name,int mills);
int start_service(const char* name, int mills);
int config_service_start(const char* name, int startmode);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_SVC_H_76534A2CAA1D59EFE44080E15F81572C__ */
