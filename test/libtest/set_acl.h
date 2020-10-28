#ifndef __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__
#define __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__

#include <stdlib.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int dump_process_security(FILE* fp,int pid);
int proc_dacl_set(FILE* fp,int pid,char* maskstr,char* modestr, char* inheritstr, char* username);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__ */
