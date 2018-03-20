#ifndef __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__
#define __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

#define  PROC_PIPE_STDIN            0x1
#define  PROC_PIPE_STDOUT           0x2
#define  PROC_PIPE_STDERR           0x4
#define  PROC_NO_WINDOW             0x8


WINLIB_API int get_pid_argv(int pid,char*** pppargv,int *pargvsize);

WINLIB_API void* start_cmd(int createflag,const char* prog,...);
WINLIB_API void* start_cmdv(int createflag,char* prog[]);
WINLIB_API HANDLE get_stdin(void* proc);
WINLIB_API HANDLE get_stdout(void* proc);
WINLIB_API HANDLE get_stderr(void* proc);
WINLIB_API HANDLE get_proc(void* proc);
WINLIB_API int kill_proc(void* proc,int* exitcode);
WINLIB_API int get_proc_exit(void* proc, int timeout, int *exitcode);
WINLIB_API int run_cmd_output(char* pin, int insize,char** ppout,int *poutsize, char** pperr, int *perrsize, int *exitcode, const char* prog,...);
WINLIB_API int run_cmd_outputv(char* pin, int insize,char** ppout,int *poutsize, char** pperr, int *perrsize, int *exitcode, char* prog[]);

#ifdef __cplusplus
};
#endif



#endif /* __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__ */
