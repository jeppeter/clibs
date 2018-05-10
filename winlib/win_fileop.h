#ifndef __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__
#define __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

#define  STDOUT_FILE_FLAG         1
#define  STDERR_FILE_FLAG         2


WINLIB_API int mktempfile_safe(char* inputtemplate,char**ppoutput,int* bufsize);
WINLIB_API int read_file_encoded(char* infile,char** ppoutbuf,int *bufsize);
WINLIB_API int read_file_whole(char* infile,char** ppoutbuf,int *bufsize);
WINLIB_API int read_stdin_whole(int freed,char** ppoutbuf,int *bufsize);
WINLIB_API int delete_file(const char* infile);
WINLIB_API int get_full_path(char* pinfile, char** ppfullpath, int *pfullsize);
WINLIB_API int write_file_whole(char* outfile,char* poutbuf,int outsize);
WINLIB_API int write_out_whole(int flag,char* poutbuf,int outsize);

#ifdef __cplusplus
};
#endif

#endif /* __WIN_FILEOP_H_9B720185ABBC9B1C19F2903D4A43CC38__ */
