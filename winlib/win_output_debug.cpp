
#include <win_output_debug.h>
#include <stdio.h>

static int st_output_loglvl = BASE_LOG_DEFAULT;

void InnerDebug(char* pFmtStr)
{

#ifdef UNICODE
    LPWSTR pWide = NULL;
    int len;
    BOOL bret;
    len = (int) strlen(pFmtStr) + 1;
    pWide = (wchar_t*)malloc((len + 1) * 2);
    if (pWide == NULL) {
        return ;
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
    return ;
}

void DebugOutString(int loglvl, const char* file, int lineno, const char* fmt, ...)
{
    char* pFmt = NULL;
    char* pLine = NULL;
    char* pWhole = NULL;
    va_list ap;
    size_t alloclen = 1024;
    int ret;

    if (loglvl > st_output_loglvl) {
        /*nothing to output*/
        return;
    }

try_again:
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

    ret = _snprintf_s(pLine, alloclen, alloclen - 1, "%s:%d:time(0x%08x)\t", file, lineno, (unsigned int)GetTickCount());
    if (ret < 0 || ret >= (int)(alloclen - 1)) {
        alloclen <<= 1;
        goto try_again;
    }
    va_start(ap, fmt);
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

    InnerDebug(pWhole);
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

    return ;
}

void ConsoleOutString(int loglvl, const char* file, int lineno, const char* fmt, ...)
{
    char* pFmt = NULL;
    char* pLine = NULL;
    char* pWhole = NULL;
    va_list ap;
    size_t alloclen = 1024;
    int ret;

    if (loglvl > st_output_loglvl) {
        return;
    }

try_again:
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

    ret = _snprintf_s(pLine, alloclen, alloclen - 1, "%s:%d:time(0x%08x)\t", file, lineno, (unsigned int)GetTickCount());
    if (ret < 0 || ret >= (int)(alloclen - 1)) {
        alloclen <<= 1;
        goto try_again;
    }
    va_start(ap, fmt);
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

    fprintf(stderr, "%s", pWhole);
    fflush(stderr);
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

    return ;
}

typedef void (*output_func_t)(char* pbuf);

#define FORMAT_SNPRINTF(...)  \
do {\
    ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, __VA_ARGS__); \
    if (ret < 0 || ret >= ((int)(fmtlen - formedlen - 1))) {\
        goto out;\
    }\
    pCur += ret;\
    formedlen += ret;\
} while(0)

#define FLUSH_BUFFER()  \
do {\
    outfunc(pLine);\
    pCur = pLine;\
    formedlen = 0;\
} while(0)

void __inner_out_buffer(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, va_list ap, output_func_t outfunc)
{
    size_t fmtlen = 2000;
    char*pLine = NULL, *pCur, *plastbuf = NULL, *pcurbuf = NULL;
    int formedlen;
    int ret;
    int i;

    if (loglvl > st_output_loglvl) {
        return;
    }

    pLine = new char[fmtlen];
    pCur = pLine;
    formedlen = 0;

    FORMAT_SNPRINTF("[%s:%d:time(0x%llx)]\tbuffer %p (%d)", file, lineno, GetTickCount64(), pBuffer, buflen);
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
    delete [] pLine;
    pLine = NULL;
    return ;
}


void DebugBufferFmt(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    va_list ap = NULL;
    if (fmt != NULL) {
        va_start(ap,fmt);
    }
    __inner_out_buffer(loglvl,file,lineno,pBuffer,buflen,fmt,ap,InnerDebug);
    return;
}

void __console_out(char* pFmtStr)
{
    fprintf(stderr,"%s",pFmtStr);
    return;
}

void ConsoleBufferFmt(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    va_list ap = NULL;
    if (fmt != NULL) {
        va_start(ap,fmt);
    }
    __inner_out_buffer(loglvl,file,lineno,pBuffer,buflen,fmt,ap,__console_out);
    return;
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

int InitOutput(int loglvl)
{
    st_output_loglvl = loglvl;
    return 0;
}

void FiniOutput(void)
{
    return;
}