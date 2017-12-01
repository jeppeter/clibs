
#include <ux_strop.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ux_err.h>

int find_endof_inbuf(void* pbuf, int bufsize)
{
    int idx = 0;
    unsigned char* pptr = (unsigned char*)pbuf;

    for (idx = 0; idx < bufsize; idx++) {
        if (pptr[idx] == 0x0) {
            return idx;
        }
    }
    return -1;
}

int vsnprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, va_list ap)
{
    char* pRetBuf = *ppbuf;
    size_t retsize = (size_t)(*pbufsize);
    int nret;
    int ret;
    va_list oldap;
    va_copy(oldap,ap);

    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    if (pRetBuf == NULL || retsize < 32) {
        if (retsize < 32) {
            retsize = 32;
        }
        pRetBuf = (char*)malloc(retsize);
        if (pRetBuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
try_again:
    va_copy(ap,oldap);
    ret = vsnprintf(pRetBuf, retsize - 1, fmt, ap);
    if (ret == -1 || ret >= (int)(retsize - 1)) {
        retsize <<= 1;
        if (pRetBuf != *ppbuf) {
            free(pRetBuf);
        }
        pRetBuf = NULL;
        pRetBuf = (char*)malloc(retsize);
        if (pRetBuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        goto try_again;
    }

    nret = ret + 1;
    if (*ppbuf && *ppbuf != pRetBuf) {
        free(*ppbuf);
    }
    *ppbuf = pRetBuf;
    *pbufsize = (int)retsize;

    return nret;
fail:
    if (pRetBuf && pRetBuf != *ppbuf) {
        free(pRetBuf);
    }
    pRetBuf = NULL;
    retsize = 0;
    SETERRNO(-ret);
    return ret;
}

int snprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, ...)
{
    va_list ap;
    if (fmt == NULL){
        if (*ppbuf){
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    va_start(ap, fmt);
    return vsnprintf_safe(ppbuf,pbufsize,fmt,ap);
}

int append_vsnprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,va_list ap)
{
    char* pRetBuf = *ppbuf;
    char* pTmpBuf = NULL;
    char* pcurptr = NULL;
    size_t tmpsize;
    size_t retsize = (size_t)(*pbufsize);
    int nret, ret;
    size_t leftsize = retsize;
    size_t cntsize = 0;
    va_list oldap;
    va_copy(oldap, ap);

    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    if (pRetBuf == NULL || retsize < 32) {
        if (retsize < 32) {
            retsize = 32;
        }
        pRetBuf = (char*)malloc(retsize);
        if (pRetBuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (*ppbuf) {
        cntsize = strlen(*ppbuf);
    }

    if (cntsize > 0  ) {
        if (pRetBuf != *ppbuf) {
            memcpy(pRetBuf, *ppbuf, cntsize);
        }
        pRetBuf[cntsize] = 0x0;
        pcurptr = &(pRetBuf[cntsize]);
        leftsize = retsize - cntsize;
    } else {
        pcurptr = pRetBuf;
        leftsize = retsize;
    }

try_again:
    va_copy(ap,oldap);
    ret = vsnprintf(pcurptr, leftsize - 1, fmt, ap);
    if (ret == -1 || ret >= (int)(leftsize - 1)) {
        tmpsize = retsize << 1;
        pTmpBuf = (char*)malloc(tmpsize);
        if (pTmpBuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }

        if (cntsize > 0 && *ppbuf != NULL) {
            memcpy(pTmpBuf, *ppbuf, cntsize);
            pTmpBuf[cntsize] = 0x0;
            pcurptr = &(pTmpBuf[cntsize]);
            leftsize = tmpsize - cntsize;
        } else {
            pTmpBuf[0] = 0;
            pcurptr = pTmpBuf;
            leftsize = tmpsize;
        }

        if (pRetBuf && pRetBuf != *ppbuf) {
            free(pRetBuf);
        }
        pRetBuf = NULL;
        pRetBuf = pTmpBuf;
        pTmpBuf = NULL;
        retsize = tmpsize;
        tmpsize = 0;
        goto try_again;
    }

    nret = ret + 1;
    nret += (int)cntsize;

    if (pTmpBuf) {
        free(pTmpBuf);
    }
    pTmpBuf = NULL;
    tmpsize = 0;
    if (*ppbuf && *ppbuf != pRetBuf) {
        free(*ppbuf);
    }
    *ppbuf = pRetBuf;
    *pbufsize = (int)retsize;
    return nret;
fail:
    if (pTmpBuf) {
        free(pTmpBuf);
    }
    pTmpBuf = NULL;
    tmpsize = 0;
    if (pRetBuf && pRetBuf != *ppbuf) {
        free(pRetBuf);
    }
    pRetBuf = NULL;
    SETERRNO(-ret);
    return ret;
}

int append_snprintf_safe(char**ppbuf, int*pbufsize, const char* fmt, ...)
{
    va_list ap;
    if (fmt == NULL){
        if (*ppbuf){
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }
    va_start(ap,fmt);
    return append_vsnprintf_safe(ppbuf,pbufsize,fmt,ap);
}

void __make_lowercase(const char* pstr){
    char* pcurptr =(char*) pstr;

    while(pcurptr && *pcurptr != 0x0){
        if (*pcurptr >= 'A' && *pcurptr <= 'Z'){
            *pcurptr = *pcurptr - 'A' + 'a';
        }
        pcurptr ++;
    }
    return ;
}

void str_lower_case(const char* pstr)
{
    return __make_lowercase(pstr);
}

char* str_in_str(const char* pstr,const char *search)
{
    return (char*)strstr(pstr,search);
}

bool str_match_wildcard(const char* regpat,const char* str)
{
    bool bmatched=false;
    char* pcurstr=NULL;

    char* pcurpat=NULL,*pnextpat=NULL;
    char* pcopypat=NULL;
    char* pcopystr=NULL;
    size_t patlen,slen;
    int ret;
    addr_t curpatlen;
    char* pmatchstr=NULL;

    if (regpat == NULL || str == NULL){
        return false;
    } 

    /*now we copy the regular pattern*/
    patlen = strlen(regpat) + 1;
    pcopypat = (char*)malloc(patlen);
    if (pcopypat == NULL){
        GETERRNO(ret);
        goto out;
    }

    slen = strlen(str) + 1;
    pcopystr = (char*)malloc(slen);
    if (pcopystr == NULL){
        GETERRNO(ret);
        goto out;
    }
    memcpy(pcopypat,regpat,patlen);
    memcpy(pcopystr,str,slen);

    __make_lowercase(pcopypat);
    __make_lowercase(pcopystr);

    pcurstr = pcopystr;
    pcurpat = pcopypat;



    for (;*pcurpat != 0x0;){
        pnextpat = pcurpat;
        while (*pnextpat != 0x0 && *pnextpat != '*'){
            pnextpat ++;
        }

        curpatlen = (addr_t)pnextpat - (addr_t)pcurpat;
        if (curpatlen > 0){
            /*it means we have something in the pattern,so we should give it to match*/
            if (*pcurstr==0x0 || strlen(pcurstr) < curpatlen){
                /*nothing to match*/
                bmatched = false;
                goto out;
            } 
            /*now search for it*/
            if (*pnextpat == '*'){
                *pnextpat = 0x0;            
                pnextpat ++;
            }
            pmatchstr = strstr(pcurstr,pcurpat);
            if (pmatchstr == NULL){
                /*nothing match*/
                bmatched = false;
                goto out;
            }
            /*ok ,we match this skip this*/
            pcurstr = pmatchstr + curpatlen;
            pcurpat = pnextpat;

        }else {
            /*nothing to do*/
            if (*pnextpat == 0x0){
                break;
            }else if (*pnextpat == '*'){
                *pnextpat = 0x0;
                pnextpat ++;
                pcurpat = pnextpat;
                continue;
            }

        }
    }

    bmatched = true;

out:
    if (pcopypat){
        free(pcopypat);
    }
    pcopypat = NULL;
    if (pcopystr){
        free(pcopystr);
    }
    pcopystr = NULL;
    return bmatched;
}