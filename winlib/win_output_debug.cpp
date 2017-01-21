
#include <win_output_debug.h>
#include <stdio.h>



void InnerDebug(char* pFmtStr)
{

#ifdef UNICODE
    LPWSTR pWide = NULL;
    int len;
    BOOL bret;
    len = (int) strlen(pFmtStr) + 1;
    pWide = (wchar_t*)malloc((len+1)*2);
    if (pWide == NULL){
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

void DebugOutString(const char* file, int lineno, const char* fmt, ...)
{
    char* pFmt = NULL;
    char* pLine = NULL;
    char* pWhole = NULL;
    va_list ap;
    size_t alloclen = 1024;
    int ret;

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
    pWhole = (char*)malloc((alloclen*2));
    if (pFmt == NULL || pLine == NULL || pWhole == NULL){
        goto out;
    }
    memset(pFmt,0,alloclen);
    memset(pLine,0,alloclen);
    memset(pWhole,0,alloclen*2);

    ret = _snprintf_s(pLine, alloclen, alloclen - 1, "%s:%d:time(0x%08x)\t", file, lineno, GetTickCount());
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


void DebugBufferFmt(const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    size_t fmtlen = 2000;
    char*pLine = NULL, *pCur;
    int formedlen;
    int ret;
    int i;
    pLine = new char[fmtlen];
    pCur = pLine;
    formedlen = 0;

    ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, "[%s:%d:time(0x%08x)]\tbuffer %p (%d)", file, lineno, GetTickCount(), pBuffer, buflen);
    pCur += ret;
    formedlen += ret;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        ret = _vsnprintf_s(pCur, (size_t)(fmtlen - formedlen), (size_t)(formedlen - formedlen - 1), fmt, ap);
        pCur += ret;
        formedlen += ret;
    }

    for (i = 0; i < buflen; i++) {
        if ((formedlen + 100) > (int)fmtlen) {
            InnerDebug(pLine);
            pCur = pLine;
            formedlen = 0;
        }
        if ((i % 16) == 0) {
            ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, "\n");
            InnerDebug(pLine);
            pCur = pLine;
            formedlen = 0;
            ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, "[0x%08x]\t", i);
            pCur += ret;
            formedlen += ret;
        }

        ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, "0x%02x ", pBuffer[i]);
        pCur += ret;
        formedlen += ret;
    }
    ret = _snprintf_s(pCur, fmtlen - formedlen, fmtlen - formedlen - 1, "\n");
    pCur += ret;
    formedlen += ret;

    if (formedlen > 0) {
        InnerDebug(pLine);
        pCur = pLine;
        formedlen = 0;
    }

    delete [] pLine;
    pLine = NULL;
    return ;
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
