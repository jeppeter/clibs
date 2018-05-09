#ifndef __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__
#define __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

WINLIB_API int mktempfile_safe(char* inputtemplate,char**ppoutput,int* bufsize);
WINLIB_API int read_file_encoded(char* infile,char** ppoutbuf,int *bufsize);
WINLIB_API int read_file_whole(char* infile,char** ppoutbuf,int *bufsize);
WINLIB_API int read_stdin_whole(int freed,char** ppoutbuf,int *bufsize);
WINLIB_API int delete_file(const char* infile);
WINLIB_API int get_full_path(char* pinfile, char** ppfullpath, int *pfullsize);

#ifdef __cplusplus
};
#endif

#endif /* __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__ */
