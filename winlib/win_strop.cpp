
#include <win_strop.h>
#include <stdarg.h>
#include <stdlib.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <win_types.h>
#include <assert.h>

#pragma warning(disable:4996)

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
            ERROR_INFO("can not alloc(%d) error(%d)", retsize, ret);
            goto fail;
        }
    }
try_again:
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
            ERROR_INFO("can not alloc(%d) error(%d)", retsize, ret);
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
            ERROR_INFO("can not alloc(%d) error(%d)", retsize, ret);
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
    ret = vsnprintf(pcurptr, leftsize - 1, fmt, ap);
    if (ret == -1 || ret >= (int)(leftsize - 1)) {
        tmpsize = retsize << 1;
        pTmpBuf = (char*)malloc(tmpsize);
        if (pTmpBuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc(%d) error(%d)", tmpsize, ret);
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

int str_match_wildcard(const char* regpat,const char* str)
{
    int bmatched=0;
    char* pcurstr=NULL;

    char* pcurpat=NULL,*pnextpat=NULL;
    char* pcopypat=NULL;
    char* pcopystr=NULL;
    size_t patlen,slen;
    int ret;
    addr_t curpatlen;
    char* pmatchstr=NULL;

    if (regpat == NULL || str == NULL){
        return 0;
    } 

    /*now we copy the regular pattern*/
    patlen = strlen(regpat) + 1;
    pcopypat = (char*)malloc(patlen);
    if (pcopypat == NULL){
        GETERRNO(ret);
        ERROR_INFO("can alloc(%d) error(%d)",patlen,ret);
        goto out;
    }

    slen = strlen(str) + 1;
    pcopystr = (char*)malloc(slen);
    if (pcopystr == NULL){
        GETERRNO(ret);
        ERROR_INFO("can alloc(%d) error(%d)",slen,ret);
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
                bmatched = 0;
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
                bmatched = 0;
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

    bmatched = 1;

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


int quote_stringv(char** ppquotestr,int *psize,const char* pstr,va_list ap)
{
    char* pret=NULL;
    int retsize=0;
    char* ptmp=NULL;
    int tmpsize=0;
    int ret;
    int cnt;
    char* pcursrc=NULL, *pcurdst=NULL;;

    if (pstr == NULL) {
        if (ppquotestr && *ppquotestr) {
            free(*ppquotestr);
            *ppquotestr = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppquotestr == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pret = *ppquotestr;
    retsize = *psize;

    ret = vsnprintf_safe(&ptmp,&tmpsize, pstr,ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*we include the " at begin or end and the every two*/
    if (pret == NULL || retsize < ((ret * 2)+3))  {
        if (retsize < ((ret * 2)+3)) {
            retsize = ((ret * 2)+3);
        }
        pret = (char*) malloc((size_t)retsize);
        if (pret == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc [%d] error[%d]", retsize, ret);
            goto fail;
        }
    }


    memset(pret ,0 , (size_t)retsize);
    pcursrc = ptmp;
    pcurdst = pret;
    *pcurdst = '"';
    pcurdst ++;

    while(*pcursrc) {
        if (*pcursrc == '\\' || 
            *pcursrc == '"') {
            *pcurdst = '\\';
            pcurdst ++;
        }
        *pcurdst = *pcursrc;
        pcurdst ++;
        pcursrc ++;
    }

    *pcurdst = '"';
    pcurdst ++;
    /*at the end of the size*/
    *pcurdst = '\0';

    cnt = (int)(pcurdst - pret);
    assert(cnt < retsize);
    if (pret != *ppquotestr && *ppquotestr) {
        free(*ppquotestr);
    }

    *ppquotestr = pret;
    *psize = retsize;
    return cnt;
fail:
    if (pret != NULL && pret != *ppquotestr) {
        free(pret);
    }
    pret = NULL;
    retsize = 0;
    vsnprintf_safe(&ptmp,&tmpsize,NULL,ap);
    SETERRNO(ret);
    return ret;    
}

int quote_string(char** ppquotestr,int *psize,const char* pstr,...)
{
    va_list ap;
    if (pstr ==NULL) {
        if (ppquotestr && *ppquotestr) {
            free(*ppquotestr);
            *ppquotestr = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    va_start(ap, pstr);
    return quote_stringv(ppquotestr, psize,pstr, ap);
}

char* safe_strdup(const char* str)
{
    size_t len = strlen(str);
    char* pretstr = NULL;

    pretstr = (char*) malloc(len + 1);
    if (pretstr == NULL) {
        return NULL;
    }
    memcpy(pretstr, str, len + 1);
    return pretstr;
}

void __make_uppercase(const char* pstr)
{
    char* pcurptr = (char*) pstr;

    while (pcurptr && *pcurptr != 0x0) {
        if (*pcurptr >= 'a' && *pcurptr <= 'z') {
            *pcurptr = *pcurptr - 'a' + 'A';
        }
        pcurptr ++;
    }
    return ;
}

void str_upper_case(const char* pstr)
{
    __make_uppercase(pstr);
    return;
}

void __make_under_score(const char* pstr)
{
    char* pcurptr = (char*) pstr;

    while (pcurptr && *pcurptr != 0x0) {
        if (*pcurptr == '-') {
            *pcurptr = '_';
        }
        pcurptr ++;
    }
    return ;
}

void str_underscore_case(const char* pstr)
{
    __make_under_score(pstr);
    return;
}

int str_nocase_cmp(const char* pstr, const char* pcmpstr)
{
    return _stricmp(pstr,pcmpstr);
}

int str_case_cmp(const char* pstr, const char* pcmpstr)
{
    return strcmp(pstr,pcmpstr);
}