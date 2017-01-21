#ifndef __WIN_UNI_ANSI_H__
#define __WIN_UNI_ANSI_H__

#include <Windows.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#ifdef __cplusplus
extern "C"  {
#endif

/**********************************************************
*    if pWideChar==NULL  will reset *ppChar=NULL and free memory
*    else set *ppChar by new and *pCharSize is the size of *ppChar
*    return value success >= 0 number of bytes in *ppChar
*    otherwise negative error code
**********************************************************/
WINLIB_API int UnicodeToAnsi(wchar_t* pWideChar,char** ppChar,int*pCharSize);

/**********************************************************
*    if pChar==NULL  will reset *ppWideChar=NULL and free memory
*    else set *ppWideChar by new and *pWideCharSize is the size of *ppWideChar
*    return value success >= 0 number of bytes in *ppWideChar
*    otherwise negative error code
**********************************************************/
WINLIB_API int AnsiToUnicode(char* pChar,wchar_t **pWideChar,int*pWideCharSize);

/**********************************************************
*    if ptchar==NULL  will reset *ppChar=NULL and free memory
*    else set *ppChar by new and *pCharSize is the size of *ppChar
*    return value success >= 0 number of bytes in *ppChar
*    otherwise negative error code
**********************************************************/
WINLIB_API int TcharToAnsi(TCHAR *ptchar,char** ppChar,int*pCharSize);

/**********************************************************
*    if pChar==NULL  will reset *pptchar=NULL and free memory
*    else set *pptchar by new and *pptchar is the size of *ptcharsize
*    return value success >= 0 number of bytes in *pptchar
*    otherwise negative error code
**********************************************************/
WINLIB_API int AnsiToTchar(const char *pChar,TCHAR **pptchar,int *ptcharsize);

#ifdef __cplusplus
};
#endif


#endif /*__WIN_UNI_ANSI_H__*/
