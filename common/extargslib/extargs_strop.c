#include <extargs_strop.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define VSNPRINTF vsnprintf

/*******************************************************
*  these are the option handle functions
*
*******************************************************/

char* extargs_safe_strdup(const char* str)
{
    int len = (int)strlen(str);
    char* pretstr = NULL;

    pretstr = (char*) malloc(len + 1);
    if (pretstr == NULL) {
        return NULL;
    }
    memcpy(pretstr, str, len + 1);
    return pretstr;
}


int extargs_find_endof_inbuf(void* pbuf, int bufsize)
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

int extargs_vsnprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, va_list ap)
{
    char* pRetBuf = *ppbuf;
    int retsize = *pbufsize;
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
            ret = -1;
            goto fail;
        }
    }
try_again:
    va_copy(ap,oldap);
    ret = VSNPRINTF(pRetBuf, retsize - 1, fmt, ap);
    if (ret == -1 || ret >= (retsize - 1)) {
        retsize <<= 1;
        if (pRetBuf != NULL && pRetBuf != *ppbuf) {
            free(pRetBuf);
        }
        pRetBuf = NULL;
        pRetBuf = (char*)malloc(retsize);
        if (pRetBuf == NULL) {
            ret = -1;
            goto fail;
        }
        goto try_again;
    }

    nret = ret + 1;
    if (*ppbuf && *ppbuf != pRetBuf) {
        free(*ppbuf);
    }
    *ppbuf = pRetBuf;
    *pbufsize = retsize;
    return nret;
fail:
    if (pRetBuf && pRetBuf != *ppbuf) {
        free(pRetBuf);
    }
    pRetBuf = NULL;
    retsize = 0;
    return ret;
}

int extargs_snprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, ...)
{
    va_list ap;
    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    va_start(ap, fmt);
    return extargs_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
}

int extargs_append_vsnprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, va_list ap)
{
    char* pRetBuf = *ppbuf;
    char* pTmpBuf = NULL;
    char* pcurptr = NULL;
    int tmpsize;
    int retsize = *pbufsize;
    int nret, ret;
    int leftsize = retsize;
    int cntsize = 0;
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
            ret = -1;
            goto fail;
        }
    }

    if (*ppbuf) {
        cntsize = (int)strlen(*ppbuf);
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
    ret = VSNPRINTF(pcurptr, leftsize - 1, fmt, ap);
    if (ret == -1 || ret >= (leftsize - 1)) {
        tmpsize = retsize << 1;
        pTmpBuf = (char*)malloc(tmpsize);
        if (pTmpBuf == NULL) {
            ret = -1;
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
    nret += cntsize;

    if (pTmpBuf) {
        free(pTmpBuf);
    }
    pTmpBuf = NULL;
    tmpsize = 0;
    if (*ppbuf && *ppbuf != pRetBuf) {
        free(*ppbuf);
    }
    *ppbuf = pRetBuf;
    *pbufsize = retsize;
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
    return ret;
}

int extargs_append_snprintf_safe(char**ppbuf, int*pbufsize, const char* fmt, ...)
{
    va_list ap;
    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }
    va_start(ap, fmt);
    return extargs_append_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
}

void __extargs_make_lowercase(const char* pstr)
{
    char* pcurptr = (char*) pstr;

    while (pcurptr && *pcurptr != 0x0) {
        if (*pcurptr >= 'A' && *pcurptr <= 'Z') {
            *pcurptr = *pcurptr - 'A' + 'a';
        }
        pcurptr ++;
    }
    return ;
}

void extargs_str_lower_case(const char* pstr)
{
    __extargs_make_lowercase(pstr);
    return;
}

void __extargs_make_uppercase(const char* pstr)
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

void extargs_str_upper_case(const char* pstr)
{
    __extargs_make_uppercase(pstr);
    return;
}

void __extargs_make_under_score(const char* pstr)
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

void extargs_str_underscore_case(const char* pstr)
{
    __extargs_make_under_score(pstr);
    return;
}

void __extargs_make_hiphen(const char* pstr)
{
    char* pcurptr = (char*) pstr;

    while (pcurptr && *pcurptr != 0x0) {
        if (*pcurptr == '_') {
            *pcurptr = '-';
        }
        pcurptr ++;
    }
    return ;
}


void extargs_str_hiphen_case(const char* pstr)
{
    __extargs_make_hiphen(pstr);
    return;
}

static int st_quoted_char[256] = {
    0,/*nul*/  0,/*soh*/  0,/*stx*/  0,/*etx*/  0,/*eot*/  0,/*enq*/  0,/*ack*/  0,/*bel*/
    2,/*bs */  0,/*ht */  2,/*nl */  0,/*vt */  0,/*np */  2,/*cr */  0,/*so */  0,/*si */
    0,/*dle*/  0,/*dc0*/  0,/*dc0*/  0,/*dc0*/  0,/*dc0*/  0,/*nak*/  0,/*syn*/  0,/*etb*/
    0,/*can*/  0,/*em */  0,/*sub*/  0,/*esc*/  0,/*fs */  0,/*gs */  0,/*rs */  0,/*us */
    0,/*sp */  0,/* ! */  1,/* " */  0,/* # */  0,/* $ */  0,/* % */  0,/* & */  1,/* ' */
    0,/* ( */  0,/* ) */  0,/* * */  0,/* + */  0,/* , */  0,/* - */  0,/* . */  1,/* / */
    0,/* 0 */  0,/* 1 */  0,/* 2 */  0,/* 3 */  0,/* 4 */  0,/* 5 */  0,/* 6 */  0,/* 7 */
    0,/* 8 */  0,/* 9 */  0,/* : */  0,/* ; */  0,/* < */  0,/* = */  0,/* > */  0,/* ? */
    0,/* @ */  0,/* A */  0,/* B */  0,/* C */  0,/* D */  0,/* E */  0,/* F */  0,/* G */
    0,/* H */  0,/* I */  0,/* J */  0,/* K */  0,/* L */  0,/* M */  0,/* N */  0,/* O */
    0,/* P */  0,/* Q */  0,/* R */  0,/* S */  0,/* T */  0,/* U */  0,/* V */  0,/* W */
    0,/* X */  0,/* Y */  0,/* Z */  0,/* [ */  0,/* \ */  0,/* ] */  0,/* ^ */  0,/* _ */
    0,/* ` */  0,/* a */  0,/* b */  0,/* c */  0,/* d */  0,/* e */  0,/* f */  0,/* g */
    0,/* h */  0,/* i */  0,/* j */  0,/* k */  0,/* l */  0,/* m */  0,/* n */  0,/* o */
    0,/* p */  0,/* q */  0,/* r */  0,/* s */  0,/* t */  0,/* u */  0,/* v */  0,/* w */
    0,/* x */  0,/* y */  0,/* z */  0,/* { */  0,/* | */  0,/* } */  0,/* ~ */  0,/*del*/
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0,         
    0,         0,         0,         0,         0,         0,         0,         0
};


char* extargs_str_quoted_case(const char* pstr)
{
    char* pretstr = NULL;
    int filllen = 0;
    int retsize = 0;
    const char* pptr;
    retsize = (int)strlen(pstr) + 1;
try_again:
    if (pretstr) {
        free(pretstr);
    }
    pretstr = NULL;
    pretstr = (char*)malloc(retsize);
    if (pretstr == NULL) {
        goto fail;
    }
    memset(pretstr, 0, retsize);
    filllen = 0;

    pptr = pstr;
    while (*pptr != '\0') {
        if (st_quoted_char[(*pptr) & 0xff] == 0) {
            if ((filllen + 1) >= retsize) {
                retsize <<= 1;
                goto try_again;
            }
            pretstr[filllen] = *pptr;
            filllen ++;
        } else if (st_quoted_char[(*pptr) & 0xff] == 1) {
            if ((filllen + 2) >= retsize) {
                retsize <<= 1;
                goto try_again;
            }
            pretstr[filllen] = '\\';
            filllen ++;
            pretstr[filllen] = *pptr;
            filllen ++;
        } else if (st_quoted_char[(*pptr) & 0xff] == 2) {
            if ((filllen + 2) >= retsize) {
                retsize <<= 1;
                goto try_again;
            }
            switch (*pptr) {
            case '\n':
                pretstr[filllen] = '\\';
                filllen ++;
                pretstr[filllen] = 'n';
                filllen ++;
                break;
            case '\r':
                pretstr[filllen] = '\\';
                filllen ++;
                pretstr[filllen] = 'r';
                filllen ++;
                break;
            case '\b':
                pretstr[filllen] = '\\';
                filllen ++;
                pretstr[filllen] = 'b';
                filllen ++;
                break;        
            }
        }
        pptr++;
    }

    return pretstr;
fail:
    if (pretstr != NULL) {
        free(pretstr);
    }
    pretstr = NULL;
    return NULL;
}

char* extargs_str_in_str(const char* pstr, const char *search)
{
    return (char*)strstr(pstr, search);
}

_Bool extargs_str_match_wildcard(const char* regpat, const char* str)
{
    _Bool bmatched = false;
    char* pcurstr = NULL;
    char* pcurpat = NULL, *pnextpat = NULL;
    char* pcopypat = NULL;
    char* pcopystr = NULL;
    int patlen, slen;
    unsigned long long curpatlen;
    char* pmatchstr = NULL;

    if (regpat == NULL || str == NULL) {
        return false;
    }

    /*now we copy the regular pattern*/
    patlen = (int)strlen(regpat) + 1;
    pcopypat = (char*)malloc(patlen);
    if (pcopypat == NULL) {
        bmatched = false;
        goto out;
    }

    slen = (int)strlen(str) + 1;
    pcopystr = (char*)malloc(slen);
    if (pcopystr == NULL) {
        bmatched = false;
        goto out;
    }
    memcpy(pcopypat, regpat, patlen);
    memcpy(pcopystr, str, slen);

    __extargs_make_lowercase(pcopypat);
    __extargs_make_lowercase(pcopystr);

    pcurstr = pcopystr;
    pcurpat = pcopypat;



    for (; *pcurpat != 0x0;) {
        pnextpat = pcurpat;
        while (*pnextpat != 0x0 && *pnextpat != '*') {
            pnextpat ++;
        }

        curpatlen = (unsigned long long)((uintptr_t)pnextpat) - (unsigned long long)((uintptr_t)pcurpat);
        if (curpatlen > 0) {
            /*it means we have something in the pattern,so we should give it to match*/
            if (*pcurstr == 0x0 || strlen(pcurstr) < curpatlen) {
                /*nothing to match*/
                bmatched = false;
                goto out;
            }
            /*now search for it*/
            if (*pnextpat == '*') {
                *pnextpat = 0x0;
                pnextpat ++;
            }
            pmatchstr = strstr(pcurstr, pcurpat);
            if (pmatchstr == NULL) {
                /*nothing match*/
                bmatched = false;
                goto out;
            }
            /*ok ,we match this skip this*/
            pcurstr = pmatchstr + curpatlen;
            pcurpat = pnextpat;

        } else {
            /*nothing to do*/
            if (*pnextpat == 0x0) {
                break;
            } else if (*pnextpat == '*') {
                *pnextpat = 0x0;
                pnextpat ++;
                pcurpat = pnextpat;
                continue;
            }

        }
    }

    bmatched = true;

out:
    if (pcopypat) {
        free(pcopypat);
    }
    pcopypat = NULL;
    if (pcopystr) {
        free(pcopystr);
    }
    pcopystr = NULL;
    return bmatched;
}