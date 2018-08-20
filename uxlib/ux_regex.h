#ifndef __UX_REGEX_H_11DA013AD483DBB19E7D9BF482D180BD__
#define __UX_REGEX_H_11DA013AD483DBB19E7D9BF482D180BD__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  REGEX_NONE                     0
#define  REGEX_IGNORE_CASE              1


int regex_compile(const char* restr, int flags, void**ppreg);
int regex_exec(void* preg,const char* instr, int** ppstartpos, int **ppendpos, int * psize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_REGEX_H_11DA013AD483DBB19E7D9BF482D180BD__ */
