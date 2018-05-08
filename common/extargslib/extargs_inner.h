#ifndef __EXTARGS_INNER_H__
#define __EXTARGS_INNER_H__

#define __EXTARGS_VERSION__      "0.2.0"


#ifndef __EXTARGS_INNER_INCLUDE__
#error "can not be included from other source file outside of extargslib"
#endif

#if defined(_WIN32) || defined(_WIN64)

#if defined(EXTARGS_DLL_IMPORT)
#define EXTARGSLIB_API __declspec(dllimport) 
#elif defined(EXTARGS_DLL_EXPORT)
#define EXTARGSLIB_API __declspec(dllexport) 
#else
#define EXTARGSLIB_API
#endif

#ifndef __EXTARGS_WIN__
#define __EXTARGS_WIN__  1
#endif

#else


#define EXTARGSLIB_API 
#ifdef  __EXTARGS_WIN__
#undef  __EXTARGS_WIN__
#endif
#endif

#ifdef __EXTARGS_X86__
#undef __EXTARGS_X86__
#endif

#ifdef __EXTARGS_X64__
#undef __EXTARGS_X64__
#endif

/****now we should check whether it is x64 or not****/
#if defined(_WIN32) || defined(_WIN64)

#if defined(_WIN64)
#define __EXTARGS_X64__         1
#else
#define __EXTARGS_X86__         1
#endif

#elif defined(__GNUC__)

#if __SIZEOF_POINTER__ == 8
#define __EXTARGS_X64__         1
#elif __SIZEOF_POINTER__ == 4
#define __EXTARGS_X86__         1
#else
#error "not supported bit wide in gcc"
#endif

#else
#error "not supported compiler ,please use visual studio or gcc"
#endif

#endif /*__EXTARGS_INNER_H__*/