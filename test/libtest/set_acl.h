#ifndef __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__
#define __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__

#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <sddl.h>
#include <accctrl.h>


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int dump_process_security(int pid);
int get_mask_from_str(FILE* fp,char* maskstr, ACCESS_MASK* pmask);
int get_mode_from_str(FILE* fp,char* modestr, ACCESS_MODE* pmode);
int get_inherit_from_str(FILE* fp,char* inheritstr, DWORD *pinherit);
int proc_dacl_set(int pid,ACCESS_MASK mask, ACCESS_MODE mode,DWORD inherit,char* username);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __SET_ACL_H_6C9E498F451EF47BADF481D80E18EDC7__ */
