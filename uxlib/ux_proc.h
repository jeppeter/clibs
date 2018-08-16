#ifndef __UX_PROC_H_F4C0C7C240CEFC18D6E2FB745849834F__
#define __UX_PROC_H_F4C0C7C240CEFC18D6E2FB745849834F__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int run_cmd_output(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...);
int run_cmd_outputa(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap);
int run_cmd_outputv(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[]);
int run_cmd_output_single(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog);


int run_cmd_event_output(int evtfd, char* pin,  int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...);
int run_cmd_event_outputa(int evtfd, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap);
int run_cmd_event_outputv(int evtfd, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[]);
int run_cmd_event_output_single(int evtfd, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_PROC_H_F4C0C7C240CEFC18D6E2FB745849834F__ */
