#pragma warning(push)

#pragma warning(disable:4514)
#pragma warning(disable:4820)
#pragma warning(disable:4668)

#include <win_output_debug.h>
#include <win_output_debug_cfg.h>
#include <win_uniansi.h>
#include <stdio.h>
#include <time.h>

#pragma warning(pop)

#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif

static int st_output_loglvl = BASE_LOG_DEFAULT;
static CRITICAL_SECTION st_outputcs;
static int st_output_inited = 0;
static HANDLE* st_output_hds = NULL; /**/
static int st_output_cnt = 0;
static int st_disableflag = 0;

#include "win_output_debug_cfg.cpp"

#if 0
#define _OUTPUT_DEBUG_ERROR(...)  do{fprintf(stderr,"[%s:%d]:",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\n");fflush(stderr);}while(0)
#else
#define _OUTPUT_DEBUG_ERROR(...)  do{}while(0)
#endif

typedef int (*output_func_t)(char* pbuf);

void __free_output_hds(void)
{
    int i;
    if (st_output_hds != NULL) {
        for (i = 0; i < st_output_cnt; i++) {
            CloseHandle(st_output_hds[i]);
            st_output_hds[i] = NULL;
        }
        free(st_output_hds);
        st_output_hds = NULL;
    }
    st_output_cnt = 0;
    return;
}

const char* _get_loglevel_note(int loglvl)
{
    if (loglvl < BASE_LOG_ERROR) {
        return "FATAL";
    } else if (loglvl >= BASE_LOG_ERROR && loglvl < BASE_LOG_WARN) {
        return "ERROR";
    } else if (loglvl >= BASE_LOG_WARN && loglvl < BASE_LOG_INFO) {
        return "WARN";
    } else if (loglvl >= BASE_LOG_INFO && loglvl < BASE_LOG_DEBUG) {
        return "INFO";
    } else if (loglvl >= BASE_LOG_DEBUG && loglvl < BASE_LOG_TRACE) {
        return "DEBUG";
    } 
    return "TRACE";    
}

int InnerDebug(char* pFmtStr)
{
    if (st_disableflag & WINLIB_DBWIN_DISABLED) {
        return 0;
    }

#ifdef UNICODE
    LPWSTR pWide = NULL;
    int len;
    BOOL bret;
    len = (int) strlen(pFmtStr) + 1;
    pWide = (wchar_t*)malloc((size_t)((len + 1) * 2));
    if (pWide == NULL) {
        return 0;
    }
    //pWide = new wchar_t[(len+1) * 2];
    bret = MultiByteToWideChar(CP_ACP, NULL, pFmtStr, -1, pWide, len * 2);
    if (bret) {
        OutputDebugStringW(pWide);
    } else {
        OutputDebugString(L"can not change fmt string");
    }
    //delete [] pWide;
    free(pWide);
#else
    //fprintf(stderr,"%s",pFmtStr);
    OutputDebugStringA(pFmtStr);
    //fprintf(stderr,"Out %s",pFmtStr);
#endif
    return len;
}

int __console_out(char* pFmtStr)
{
    int ret;
    if (st_disableflag & WINLIB_CONSOLE_DISABLED) {
        return 0;
    }
    ret = fprintf(stderr, "%s", pFmtStr);
    return ret;
}


int __output_hd_flush(HANDLE hd,char* pFmtStr,int len)
{
    BOOL bret;
    DWORD cbret;
    int ret;

    bret = WriteFile(hd,pFmtStr,(DWORD)len,&cbret,NULL);
    if (!bret) {
        GETERRNO(ret);
        goto fail;
    }

    if ((int)cbret != len) {
        ret = -ERROR_NOT_ALL_ASSIGNED;
        goto fail;
    }

    bret = FlushFileBuffers (hd);
    if (!bret) {
        GETERRNO(ret);
        goto fail;
    }

    return len;
fail:
    SETERRNO(ret);
    return ret;
}

int __file_output(char* pFmtStr)
{
    int i;
    int size=0;
    int retsize=0;
    if (st_disableflag & WINLIB_FILE_DISABLED || st_output_inited == 0) {
        return 0;
    }

    size = (int)strlen(pFmtStr);
    EnterCriticalSection(&st_outputcs);
    if (st_output_hds != NULL) {
        for (i=0;i<st_output_cnt;i++) {
            if (st_output_hds[i] != NULL) {
                __output_hd_flush(st_output_hds[i],pFmtStr,size);    
                retsize = size;
            }            
        }
    }
    LeaveCriticalSection(&st_outputcs);
    return retsize;
}

#define  MINI_FMT_SIZE           32

int __inner_time_format(int freed,char** ppfmt,size_t *pfmtsize)
{
    char* pretfmt=NULL;
    size_t retsize=0;
    int retlen = 0;
    int ret;
    size_t sret;
    struct tm nowtime;
    __time64_t nowt;
    if (freed) {
        if (ppfmt && *ppfmt) {
            free(*ppfmt);
            *ppfmt = NULL;
        }
        if (pfmtsize) {
            *pfmtsize = 0;
        }
        return 0;
    }
    if (ppfmt == NULL || pfmtsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    retsize = *pfmtsize;
    pretfmt = *ppfmt;

    if (pretfmt == NULL || retsize < MINI_FMT_SIZE) {
        if (retsize < MINI_FMT_SIZE) {
            retsize = MINI_FMT_SIZE;
        }
        pretfmt = (char*)malloc(retsize);
        if (pretfmt == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }

    memset(pretfmt , 0, retsize);

    _time64(&nowt);
    ret = _localtime64_s(&nowtime,&nowt);
    if (ret != 0) {
        GETERRNO(ret);
        goto fail;
    }
try_again:
    sret = strftime(pretfmt,retsize-1,"%Y-%m-%d %H:%M:%S",&nowtime);
    if (sret == 0) {
        retsize <<= 1;
        if (pretfmt && pretfmt != *ppfmt) {
            free(pretfmt);
        }
        pretfmt = NULL;
        pretfmt = (char*)malloc(retsize);
        if (pretfmt == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        goto try_again;
    }
    retlen = (int)sret;

    if (*ppfmt && *ppfmt != pretfmt) {
        free(*ppfmt);
    }
    *ppfmt = pretfmt;
    *pfmtsize = retsize;
    return retlen;
fail:
    /*no pretfmt here*/
    if (pretfmt != NULL && pretfmt != *ppfmt) {
        free(pretfmt);
    }
    pretfmt = NULL;
    SETERRNO(ret);
    return ret;
}

int __inner_output_console(int loglvl, const char* file, int lineno, const char* fmt,va_list ap,output_func_t outfunc,...)
{
    char* pFmt = NULL;
    char* pLine = NULL;
    char* pWhole = NULL;
    va_list oldap;
    size_t alloclen = 1024;
    int ret;
    char* fmttime=NULL;
    size_t timesize=0;
    va_list funcap;
    output_func_t pnextfn=NULL;
    int retsize=0;

    if (loglvl > st_output_loglvl) {
        /*nothing to output*/
        return 0;
    }
    va_copy(oldap,ap);

    ret = __inner_time_format(0,&fmttime,&timesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

try_again:
    va_copy(ap,oldap);
    if (pFmt) {
        //delete [] pFmt;
        free(pFmt);
    }
    pFmt = NULL;
    if (pLine) {
        //delete [] pLine;
        free(pLine);
    }
    pLine = NULL;
    if (pWhole) {
        //delete [] pWhole;
        free(pWhole);
    }
    pWhole = NULL;

    pFmt = (char*)malloc(alloclen);
    pLine = (char*)malloc(alloclen);
    pWhole = (char*)malloc((alloclen * 2));
    if (pFmt == NULL || pLine == NULL || pWhole == NULL) {
        goto out;
    }
    memset(pFmt, 0, alloclen);
    memset(pLine, 0, alloclen);
    memset(pWhole, 0, alloclen * 2);

    ret = _snprintf_s(pLine, alloclen, alloclen - 1, "%s:%d:time(0x%08x):%s<%s>\t", file, lineno, (unsigned int)GetTickCount(),fmttime,_get_loglevel_note(loglvl));
    if (ret < 0 || ret >= (int)(alloclen - 1)) {
        alloclen <<= 1;
        goto try_again;
    }
    ret = _vsnprintf_s(pFmt, alloclen, alloclen - 1, fmt, ap);
    if (ret < 0 || ret >= (int)(alloclen - 1)) {
        alloclen <<= 1;
        goto try_again;
    }
    strcpy_s(pWhole, alloclen * 2, pLine);
    strcat_s(pWhole, alloclen * 2, pFmt);
    strcat_s(pWhole, alloclen * 2, "\n");
    ret = (int) strlen(pWhole) + 1;
    if (ret >= (int)(alloclen * 2 - 1)) {
        alloclen <<= 1;
        goto try_again;
    }

    va_start(funcap,outfunc);
    pnextfn = outfunc;
    while(pnextfn != NULL) {
        ret = pnextfn(pWhole);
        if (retsize < ret) {
            retsize = ret;
        }
        pnextfn = (output_func_t) va_arg(funcap,output_func_t);
    }
out:
    if (pFmt) {
        //delete [] pFmt;
        free(pFmt);
    }
    pFmt = NULL;
    if (pLine) {
        //delete [] pLine;
        free(pLine);
    }
    pLine = NULL;
    if (pWhole) {
        //delete [] pWhole;
        free(pWhole);
    }
    pWhole = NULL;
    __inner_time_format(1,&fmttime,&timesize);
    return retsize;
}

int output_debug_string_handle(int loglvl, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    return __inner_output_console(loglvl, file, lineno, fmt,ap,InnerDebug,__console_out,__file_output,NULL);
}




#define FORMAT_SNPRINTF(...)                                                                      \
do {                                                                                              \
    ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, __VA_ARGS__);             \
    if (ret < 0 || ret >= ((int)(fmtlen - formedlen - 1))) {                                      \
        goto out;                                                                                 \
    }                                                                                             \
    pCur += ret;                                                                                  \
    formedlen += ret;                                                                             \
} while(0)

#define FLUSH_BUFFER()                                                                            \
do {                                                                                              \
    output_func_t _pnextfn=outfunc;                                                               \
    cursize = 0;                                                                                  \
    va_copy(funcap,funcoldap);                                                                    \
    while(_pnextfn != NULL) {                                                                     \
        ret =  _pnextfn(pLine);                                                                   \
        if (cursize < ret) {                                                                      \
            cursize = ret;                                                                        \
        }                                                                                         \
        _pnextfn = va_arg(funcap,output_func_t);                                                  \
    }                                                                                             \
    retsize += cursize;                                                                           \
    pCur = pLine;                                                                                 \
    formedlen = 0;                                                                                \
} while(0)



int __inner_out_buffer(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, va_list ap, output_func_t outfunc,...)
{
    size_t fmtlen = 2000;
    char*pLine = NULL, *pCur, *plastbuf = NULL, *pcurbuf = NULL;
    int formedlen;
    int ret;
    int i;
    char* fmttime=NULL;
    size_t timesize=0;
    int retsize=0,cursize=0;
    va_list funcap,funcoldap;

    if (loglvl > st_output_loglvl) {
        return 0;
    }

    va_start(funcap,outfunc);
    va_copy(funcoldap,funcap);

    pLine = new char[fmtlen];
    pCur = pLine;
    formedlen = 0;

    ret = __inner_time_format(0,&fmttime,&timesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    FORMAT_SNPRINTF("[%s:%d:time(0x%llx):%s]<%s>\tbuffer %p (%d)", file, lineno, GetTickCount64(),fmttime,_get_loglevel_note(loglvl), pBuffer, buflen);
    if (fmt) {
        ret = _vsnprintf_s(pCur, (size_t)(fmtlen - formedlen), (size_t)(formedlen - formedlen - 1), fmt, ap);
        if (ret < 0 || ret >= ((int)(fmtlen - formedlen - 1))) {
            goto out;
        }
        pCur += ret;
        formedlen += ret;
    }

    plastbuf = (char*)pBuffer;
    pcurbuf = (char*)pBuffer;
    for (i = 0; i < buflen; i++) {
        if ((formedlen + 100) > (int)fmtlen) {
            FLUSH_BUFFER();
        }
        if ((i % 16) == 0) {
            if (plastbuf != pcurbuf) {
                FORMAT_SNPRINTF("    ");
                while (plastbuf != pcurbuf) {
                    if (isprint(*plastbuf)) {
                        FORMAT_SNPRINTF("%c", *plastbuf);
                    } else {
                        FORMAT_SNPRINTF(".");
                    }
                    plastbuf ++;
                }
            }

            FORMAT_SNPRINTF("\n");
            FLUSH_BUFFER();
            FORMAT_SNPRINTF("[0x%08x]\t", i);
        }

        FORMAT_SNPRINTF("0x%02x ", pBuffer[i]);
        pcurbuf ++;
    }

    if (plastbuf != pcurbuf) {
        while ( ( i % 16) != 0) {
            FORMAT_SNPRINTF("     ");
            i ++;
        }

        FORMAT_SNPRINTF("    ");
        while (plastbuf != pcurbuf) {
            if (isprint(*plastbuf)) {
                FORMAT_SNPRINTF("%c", *plastbuf);
            } else {
                FORMAT_SNPRINTF(".");
            }
            plastbuf ++;
        }
    }

    FORMAT_SNPRINTF("\n");

    if (formedlen > 0) {
        FLUSH_BUFFER();
    }

out:
    __inner_time_format(1,&fmttime,&timesize);
    delete [] pLine;
    pLine = NULL;
    return retsize;
}


int output_buffer_fmt_handle(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    va_list ap = NULL;
    if (fmt != NULL) {
        va_start(ap,fmt);
    }
    return __inner_out_buffer(loglvl,file,lineno,pBuffer,buflen,fmt,ap,InnerDebug,__console_out,__file_output,NULL);
}


int error_out(const char* fmt, ...)
{
    va_list ap;
    int ret = 0;
    va_start(ap, fmt);
    ret += vfprintf(stderr, fmt, ap);
    ret += fprintf(stderr, "\n");
    return ret;
}


void __fini_output_cfg(void)
{
    __free_output_hds();
    DeleteCriticalSection(&st_outputcs);
}

HANDLE __open_output_debug(char* file, int appendmode)
{
    HANDLE hd = NULL;
    TCHAR* ptname = NULL;
    int tnamesize=0;
    int ret;

    ret = AnsiToTchar(file,&ptname,&tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        SETERRNO(ret);
        return NULL;
    }
    if (appendmode) {
        hd = CreateFile(ptname,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    } else {
        hd = CreateFile(ptname,GENERIC_WRITE,FILE_SHARE_READ,NULL,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if (hd == INVALID_HANDLE_VALUE) {
            GETERRNO(ret);
            if (ret == -ERROR_FILE_NOT_FOUND ) {
                hd = CreateFile(ptname,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            }
        }
    }
    if (hd == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        hd = NULL;
        goto fail;
    }

    AnsiToTchar(NULL,&ptname,&tnamesize);
    return hd;
fail:
    AnsiToTchar(NULL,&ptname,&tnamesize);
    SETERRNO(ret);
    return NULL;
}


#define  __OUTPUT_APPEND_HD(hd)                                                                   \
do{                                                                                               \
    if (tmpsize <= tmpcnt) {                                                                      \
        tmpsize <<= 1;                                                                            \
        if (tmpsize == 0) {                                                                       \
            tmpsize = 4;                                                                          \
        }                                                                                         \
        ptmphds = (HANDLE*)malloc(sizeof(*ptmphds) * tmpsize);                                    \
        if (ptmphds == NULL) {                                                                    \
            GETERRNO(ret);                                                                        \
            goto fail;                                                                            \
        }                                                                                         \
        memset(ptmphds, 0 ,sizeof(*ptmphds) * tmpsize);                                           \
        if (tmpcnt > 0) {                                                                         \
            memcpy(ptmphds, phds, sizeof(*ptmphds) * tmpcnt);                                     \
        }                                                                                         \
        if (phds) {                                                                               \
            free(phds);                                                                           \
        }                                                                                         \
        phds = ptmphds;                                                                           \
        ptmphds = NULL;                                                                           \
    }                                                                                             \
    phds[tmpcnt] = hd;                                                                            \
    tmpcnt ++;                                                                                    \
}while(0)

int __init_output_cfg(poutput_debug_cfg_t pcfg)
{
    int i;
    int tmpsize = 0, tmpcnt = 0;
    HANDLE hd = NULL;
    HANDLE *ptmphds = NULL, *phds = NULL;
    int ret;
    InitializeCriticalSection(&st_outputcs);
    __free_output_hds();
    st_disableflag = 0;
    if (pcfg != NULL) {
        if (pcfg->m_ppoutcreatefile) {
            for (i = 0; pcfg->m_ppoutcreatefile[i] != NULL; i++) {
                hd = __open_output_debug(pcfg->m_ppoutcreatefile[i], 0);
                if (hd == NULL) {
                    GETERRNO(ret);
                    InnerDebug("failed create file");
                    goto fail;
                }
                __OUTPUT_APPEND_HD(hd);
                hd = NULL;
            }
        }

        if (pcfg->m_ppoutappendfile) {
            for (i = 0; pcfg->m_ppoutappendfile[i] != NULL ; i++) {
                hd = __open_output_debug(pcfg->m_ppoutappendfile[i], 1);
                if (hd == NULL) {
                    GETERRNO(ret);
                    InnerDebug("failed append file");
                    goto fail;
                }
                __OUTPUT_APPEND_HD(hd);
                hd = NULL;

            }
        }

        st_disableflag = pcfg->m_disableflag;
    }

    if (phds) {
        st_output_hds = phds;
        phds = NULL;
    }
    st_output_cnt = tmpcnt;
    return 0;
fail:
    if (hd != NULL) {
        CloseHandle(hd);
    }
    hd = NULL;
    if (phds) {
        for (i=0;i<tmpcnt;i++) {
            if (phds[i] != NULL) {
                CloseHandle(phds[i]);
            }
            phds[i] = NULL;
        }
        free(phds);
    }
    phds = NULL;
    SETERRNO(ret);
    return ret;
}


int InitOutput(int loglvl)
{
    int ret;
    st_output_loglvl = loglvl;
    ret = __init_output_cfg(NULL);
    if (ret < 0) {
        GETERRNO(ret);
        __fini_output_cfg();
        SETERRNO(ret);
        return ret;
    }
    st_output_inited = 1;
    return 0;
}

void FiniOutput(void)
{
    __fini_output_cfg();
    return;
}



int InitOutputEx(int loglvl, poutput_debug_cfg_t pcfg)
{
    int ret;
    st_output_loglvl = loglvl;
    InitializeCriticalSection(&st_outputcs);
    ret = __init_output_cfg(pcfg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    st_output_inited = 1;
    return 0;
fail:
    __free_output_hds();
    SETERRNO(ret);
    return ret;
}

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif