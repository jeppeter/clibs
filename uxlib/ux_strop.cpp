
#include <ux_strop.h>
#include <ux_err.h>
#include <ux_output_debug.h>
#include <ux_regex.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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


char* safe_strdup(const char* str)
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
try_again:
    va_copy(ap, oldap);
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
    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    va_start(ap, fmt);
    return vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
}

int append_vsnprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, va_list ap)
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
    va_copy(ap, oldap);
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
    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }
    va_start(ap, fmt);
    return append_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
}

void __make_lowercase(const char* pstr)
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

void str_lower_case(const char* pstr)
{
    return __make_lowercase(pstr);
}

char* str_in_str(const char* pstr, const char *search)
{
    return (char*)strstr(pstr, search);
}

int str_match_wildcard(const char* regpat, const char* str)
{
    int bmatched = 0;
    char* pcurstr = NULL;

    char* pcurpat = NULL, *pnextpat = NULL;
    char* pcopypat = NULL;
    char* pcopystr = NULL;
    size_t patlen, slen;
    addr_t curpatlen;
    char* pmatchstr = NULL;

    if (regpat == NULL || str == NULL) {
        return 0;
    }

    /*now we copy the regular pattern*/
    patlen = strlen(regpat) + 1;
    pcopypat = (char*)malloc(patlen);
    if (pcopypat == NULL) {
        goto out;
    }

    slen = strlen(str) + 1;
    pcopystr = (char*)malloc(slen);
    if (pcopystr == NULL) {
        goto out;
    }
    memcpy(pcopypat, regpat, patlen);
    memcpy(pcopystr, str, slen);

    __make_lowercase(pcopypat);
    __make_lowercase(pcopystr);

    pcurstr = pcopystr;
    pcurpat = pcopypat;



    for (; *pcurpat != 0x0;) {
        pnextpat = pcurpat;
        while (*pnextpat != 0x0 && *pnextpat != '*') {
            pnextpat ++;
        }

        curpatlen = (addr_t)pnextpat - (addr_t)pcurpat;
        if (curpatlen > 0) {
            /*it means we have something in the pattern,so we should give it to match*/
            if (*pcurstr == 0x0 || strlen(pcurstr) < curpatlen) {
                /*nothing to match*/
                bmatched = 0;
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
                bmatched = 0;
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

    bmatched = 1;

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

int quote_stringv(char** ppquotestr, int *psize, const char* pstr, va_list ap)
{
    char* pret = NULL;
    int retsize = 0;
    char* ptmp = NULL;
    int tmpsize = 0;
    int ret;
    int cnt;
    char* pcursrc = NULL, *pcurdst = NULL;;

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
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pret = *ppquotestr;
    retsize = *psize;

    ret = vsnprintf_safe(&ptmp, &tmpsize, pstr, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*we include the " at begin or end and the every two*/
    if (pret == NULL || retsize < ((ret * 2) + 3))  {
        if (retsize < ((ret * 2) + 3)) {
            retsize = ((ret * 2) + 3);
        }
        pret = (char*) malloc((size_t)retsize);
        if (pret == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc [%d] error[%d]", retsize, ret);
            goto fail;
        }
    }


    memset(pret , 0 , (size_t)retsize);
    pcursrc = ptmp;
    pcurdst = pret;
    *pcurdst = '"';
    pcurdst ++;

    while (*pcursrc) {
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
    vsnprintf_safe(&ptmp, &tmpsize, NULL, ap);
    SETERRNO(ret);
    return ret;
}

int quote_string(char** ppquotestr, int *psize, const char* pstr, ...)
{
    va_list ap;
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
    va_start(ap, pstr);
    return quote_stringv(ppquotestr, psize, pstr, ap);
}

int str_nocase_cmp(const char* pstr, const char* pcmpstr)
{
    return strcasecmp(pstr, pcmpstr);
}

int str_case_cmp(const char* pstr, const char* pcmpstr)
{
    return strcmp(pstr, pcmpstr);
}

#define MIN_STR_SIZE    0x100

int __get_basenum(char* ptr, unsigned char* pnum, int base)
{
    int i = 0;
    int ret;
    char* pcurptr = ptr;
    unsigned short cnum = 0;
    int maxbits = 0;
    if (pcurptr == NULL || pnum == NULL) {
        ret = -EINVAL;
        goto fail;
    }

    if (base == 8 ) {
        maxbits = 3;
    } else if (base == 10) {
        maxbits = 3;
    } else if (base == 16) {
        maxbits = 2;
    } else {
        ret = -EINVAL;
        goto fail;
    }

    cnum = 0;
    pcurptr = ptr;
    for (i = 0; i < maxbits; i++, pcurptr ++) {
        if (base == 8) {
            if (*pcurptr >= '0' && *pcurptr <= '7') {
                cnum *= 8;
                cnum += *pcurptr - '0';
            } else {
                break;
            }
        } else if (base == 10) {
            if (*pcurptr >= '0' && *pcurptr <= '9') {
                cnum *= 10;
                cnum += (*pcurptr - '0');
            } else {
                break;
            }
        } else if (base == 16) {
            if (*pcurptr >= '0' && *pcurptr <= '9') {
                cnum *= 16;
                cnum += (*pcurptr - '0');
            } else if (*pcurptr >= 'a' && *pcurptr <= 'f') {
                cnum *= 16;
                cnum += (*pcurptr - 'a');
            } else if (*pcurptr >= 'A' && *pcurptr <= 'F') {
                cnum *= 16;
                cnum += (*pcurptr - 'A');
            } else {
                break;
            }
        } else {
            ret = -EINVAL;
            goto fail;
        }
    }

    if (cnum > 255) {
        ret = -EINVAL;
        goto fail;
    }

    *pnum = cnum;
    return i;
fail:
    SETERRNO(ret);
    return ret;
}

int unquote_string(char** ppstr, int *psize, char* pinput)
{
    char* pretstr = NULL;
    int retsize = 0;
    char* ptmpbuf = NULL;
    int ret;
    int retlen = 0;
    char* pcurptr = pinput;
    int quoted = 0;
    unsigned char addnum = 0;

    if (pinput == NULL) {
        if (ppstr != NULL && *ppstr != NULL) {
            free(*ppstr);
            *ppstr = NULL;
        }
        if (psize != NULL) {
            *psize = 0;
        }
        return 0;
    }

    if (ppstr == NULL || psize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstr = *ppstr;
    retsize = *psize;

    if (retsize < MIN_STR_SIZE || pretstr == NULL) {
        if (retsize < MIN_STR_SIZE) {
            retsize = MIN_STR_SIZE;
        }
        pretstr = (char*) malloc(retsize);
        if (pretstr == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize, ret);
            goto fail;
        }
    }
    memset(pretstr, 0, retsize);
    retlen = 0;
    if (*pcurptr == '"') {
        quoted = 1;
        pcurptr ++;
    }

    while (*pcurptr != '\0') {
        if (retlen >= retsize) {
            retsize <<= 1;
            ptmpbuf = (char*) malloc(retsize);
            if (ptmpbuf == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize, ret);
                goto fail;
            }
            memset(ptmpbuf, 0 , retsize);
            if (retlen > 0) {
                memcpy(ptmpbuf, pretstr, retlen);
            }
            if (pretstr != NULL && pretstr != *ppstr) {
                free(pretstr);
            }
            pretstr = ptmpbuf;
            ptmpbuf = NULL;
        }

        if (*pcurptr != '\\') {
            if (quoted && *pcurptr == '"' && pcurptr[1] != '\0') {
                ret = -EINVAL;
                goto fail;
            } else if (quoted && *pcurptr == '"' && pcurptr[1] == '\0') {
                quoted = 0;
                break;
            }
            pretstr[retlen] = *pcurptr;
            pcurptr ++;
            retlen ++;
        } else if (quoted) {
            pcurptr ++;
            if (pcurptr[0] == 'b') {
                pretstr[retlen] = '\0';
                retlen --;
            } else if (pcurptr[0] == 't') {
                pretstr[retlen] = '\t';
                retlen ++;
            } else if (pcurptr[0] == 'n') {
                pretstr[retlen] = '\n';
                retlen ++;
            } else if (pcurptr[0] == 'r') {
                pretstr[retlen] = '\r';
                retlen ++;
            } else if (pcurptr[0] == 'x') {
                addnum = 0;
                pcurptr ++;
                ret = __get_basenum(pcurptr, &addnum, 16);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("parse error %s at [%s]", pinput, pcurptr);
                    goto fail;
                }
                pcurptr += ret;
                pretstr[retlen] = addnum;
                retlen ++;
                continue;
            } else if (pcurptr[0] == '0') {
                addnum = 0;
                ret = __get_basenum(pcurptr, &addnum, 8);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("parse %s error at [%s]", pinput, pcurptr);
                    goto fail;
                }
                pcurptr += ret;
                pretstr[retlen] = addnum;
                retlen ++;
                continue;
            } else if (pcurptr[0] == '"') {
                pretstr[retlen] = *pcurptr;
                retlen ++;
            } else if (pcurptr[0] >= '1' && pcurptr[0] <= '9') {
                addnum = 0;
                ret = __get_basenum(pcurptr, &addnum, 10) ;
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("parse %s error at [%s]", pinput, pcurptr);
                    goto fail;
                }
                pcurptr += ret;
                pretstr[retlen] = addnum;
                retlen ++;
                continue;
            } else if (pcurptr[0] == 'a') {
                pretstr[retlen] = '\a';
                retlen ++;
            } else if (pcurptr[0] == 'v') {
                pretstr[retlen] = '\v';
                retlen ++;
            }
            pcurptr ++;
        } else {
            pretstr[retlen] = *pcurptr;
            pcurptr ++;
            retlen ++;
        }
    }

    if (quoted) {
        ret = -EINVAL;
        ERROR_INFO("not close quote string [%s]", pinput);
        goto fail;
    }


    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (*ppstr != NULL && *ppstr != pretstr) {
        free(*ppstr);
    }
    *ppstr = pretstr;
    *psize = retsize;

    return retlen;
fail:
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;

    if (pretstr != NULL && pretstr != *ppstr) {
        free(pretstr);
    }
    pretstr = NULL;
    SETERRNO(ret);
    return ret;
}

int check_valid_simple_string(const char* value)
{
    int ret = 1;
    char* pcurptr = (char*)value;
    int quoted = 0;
    if (*pcurptr == '"') {
        quoted = 1;
        pcurptr ++;
    }
    for (; *pcurptr != '\0'; pcurptr ++) {
        if (*pcurptr >= '0' && *pcurptr <= '9') {
            continue;
        }
        if ( (*pcurptr >= 'a' && *pcurptr <= 'z') ||
                (*pcurptr >= 'A' && *pcurptr <= 'Z')) {
            continue;
        }
        if (*pcurptr == '_' || *pcurptr == '-' ||
                *pcurptr == ' ' || *pcurptr == '\t') {
            continue;
        }

        if (quoted && *pcurptr == '\\' && pcurptr[1] != '\0') {
            pcurptr ++;
            continue;
        }
        if (quoted && *pcurptr != '"') {
            continue;
        }

        if (quoted && *pcurptr == '"') {
            if (pcurptr[1] != '\0') {
                ret = 0;
                break;
            }
            quoted = 0;
            continue;
        }

        /*ok for the continue*/
        ret = 0;
        break;
    }

    if (quoted) {
        /*this means it is error*/
        return 0;
    }
    return ret;
}

int __inner_free(char*** ppplines, int *psize)
{
    char** pplines;
    int retsize;
    int i;
    if (ppplines != NULL && *ppplines != NULL && psize != NULL) {
        retsize = *psize;
        pplines = *ppplines;
        for (i = 0; i < retsize ; i ++) {
            if (pplines[i] != NULL) {
                free(pplines[i]);
                pplines[i] = NULL;
            }
        }
        free(pplines);
        *ppplines = NULL;
    }
    if (psize != NULL) {
        *psize = 0;
    }
    return 0;
}

int split_lines(const char* str, char*** ppplines, int *psize)
{
    int ret;
    size_t cursize = 0;
    int retsize = 0;
    int retlen = 0;
    char** ppretlines = NULL;
    char** pptmpbuf = NULL;
    char* pcurptr = NULL, *plastptr;
    char* pgetcurptr;
    int mustchk = 0;


    if (str == NULL) {
        return __inner_free(ppplines, psize);
    }

    if (ppplines == NULL || psize == NULL) {
        ret =  -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    /*now first to get lines number*/
    pcurptr = (char*)str;
    plastptr = pcurptr;


    retsize = 4;
    retlen = 0;
    ppretlines = (char**) malloc(sizeof(*ppretlines) * retsize);
    if (ppretlines == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*ppretlines)*retsize, ret);
        goto fail;
    }
    memset(ppretlines, 0 , sizeof(*ppretlines)*retsize);

    for (; *pcurptr != '\0'; pcurptr++) {
        if (*pcurptr == '\n') {
            pgetcurptr = pcurptr;
            pgetcurptr --;
            if (*pgetcurptr == '\r') {
                pgetcurptr --;
            }

            if (retlen >= retsize) {
                retsize <<= 1;
                pptmpbuf = (char**) malloc(sizeof(*ppretlines) * retsize);
                if (pptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", sizeof(*ppretlines)*retsize, ret);
                    goto fail;
                }
                memset(pptmpbuf, 0 , sizeof(*pptmpbuf)*retsize);
                if (retlen > 0) {
                    memcpy(pptmpbuf, ppretlines, sizeof(*ppretlines)*retlen);
                }
                if (ppretlines != NULL) {
                    free(ppretlines);
                }
                ppretlines = pptmpbuf;
                pptmpbuf = NULL;
            }

            cursize = (size_t)(pgetcurptr - plastptr) + 1;
            ppretlines[retlen] = (char*) malloc((cursize + 2));
            if (ppretlines[retlen] == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", cursize + 2, ret);
                goto fail;
            }
            memset(ppretlines[retlen], 0, cursize + 2);
            if (cursize > 0) {
                memcpy(ppretlines[retlen], plastptr, cursize);
            }
            plastptr = (pcurptr + 1);
            pgetcurptr = ppretlines[retlen];
            mustchk = 0;
            while (*pgetcurptr != '\0') {
                if (mustchk) {
                    if (*pgetcurptr != '\r' &&
                            *pgetcurptr != '\0') {
                        ret = -EDQUOT;
                        goto fail;
                    }
                } else if (*pgetcurptr == '\r') {
                    *pgetcurptr = '\0';
                    mustchk = 1;
                }
                pgetcurptr ++;
            }
            retlen ++;
        }
    }

    /*it is the last lines*/
    pgetcurptr = pcurptr;
    pgetcurptr --;
    if (*pgetcurptr == '\r') {
        pgetcurptr --;
    }

    if (retlen >= retsize) {
        retsize <<= 1;
        pptmpbuf = (char**) malloc(sizeof(*ppretlines) * retsize);
        if (pptmpbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", sizeof(*ppretlines)*retsize, ret);
            goto fail;
        }
        memset(pptmpbuf, 0 , sizeof(*pptmpbuf)*retsize);
        if (retlen > 0) {
            memcpy(pptmpbuf, ppretlines, sizeof(*ppretlines)*retlen);
        }
        if (ppretlines != NULL) {
            free(ppretlines);
        }
        ppretlines = pptmpbuf;
        pptmpbuf = NULL;
    }

    cursize = (size_t)(pgetcurptr - plastptr) + 1;
    ppretlines[retlen] = (char*) malloc(cursize + 2);
    if (ppretlines[retlen] == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", cursize + 2, ret);
        goto fail;
    }
    memset(ppretlines[retlen], 0, cursize + 2);
    if (cursize > 0) {
        memcpy(ppretlines[retlen], plastptr, cursize);
    }
    plastptr = (pcurptr + 1);
    pgetcurptr = ppretlines[retlen];
    mustchk = 0;
    while (*pgetcurptr != '\0') {
        if (mustchk) {
            if (*pgetcurptr != '\r' &&
                    *pgetcurptr != '\0') {
                ret = -EDQUOT;
                goto fail;
            }
        } else if (*pgetcurptr == '\r') {
            *pgetcurptr = '\0';
            mustchk = 1;
        }
        pgetcurptr ++;
    }
    retlen ++;

    if (pptmpbuf) {
        free(pptmpbuf);
    }
    pptmpbuf = NULL;
    __inner_free(ppplines, psize);
    *ppplines = ppretlines;
    *psize = retsize;
    return retlen;
fail:
    if (pptmpbuf) {
        free(pptmpbuf);
    }
    pptmpbuf = NULL;
    __inner_free(&ppretlines, &retsize);
    SETERRNO(ret);
    return ret;
}

int split_chars(const char* str, const char* sp, char*** ppparrs, int *psize)
{
    char** ppretarrs = NULL;
    char** pptmpbuf = NULL;
    int retsize = 0;
    int retlen = 0;
    int i;
    char* pcur = NULL, *plastptr = NULL;
    int curlen = 0;
    int cmplen = 0;
    int ret;

    if (str == NULL) {
        if (ppparrs && *ppparrs) {
            ppretarrs = *ppparrs;
            for (i = 0; ppretarrs[i]; i++) {
                free(ppretarrs[i]);
                ppretarrs[i] = NULL;
            }
            free(ppretarrs);
            *ppparrs = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppparrs == NULL || psize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    ppretarrs = *ppparrs;
    retsize = *psize;
    if (ppretarrs != NULL) {
        /*now free it*/
        for (i = 0; i < retsize; i++) {
            if (ppretarrs[i]) {
                free(ppretarrs[i]);
                ppretarrs[i] = NULL;
            }
        }
    }

    pcur = (char*)str;
    if (sp == NULL) {
        retlen = strlen(str);
        if (retlen >= retsize || ppretarrs == NULL) {
            if (retsize <= retlen) {
                retsize = retlen + 1;
            }
            ppretarrs = (char**)malloc(retsize * sizeof(*ppretarrs));
            if (ppretarrs == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize * sizeof(*ppretarrs), ret);
                goto fail;
            }
            memset(ppretarrs, 0, sizeof(*ppretarrs) * retsize);
        }

        for (i = 0; i < retlen; i++) {
            ASSERT_IF(ppretarrs[i] == NULL);
            ppretarrs[i] = (char*)malloc(2);
            if (ppretarrs[i] == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc 2 error[%d]", ret);
                goto fail;
            }
            memset(ppretarrs[i], 0 , 2);
            ppretarrs[i][0] = str[i];
        }
    } else {
        /*now to copy*/
        cmplen = strlen(sp);
        plastptr = pcur;
        while (*pcur != '\0') {
            if (strncmp(pcur, sp, cmplen) == 0) {
copy_one:
                if (retlen >= (retsize - 1) || ppretarrs == NULL) {
                    if (retsize < 2) {
                        retsize = 4;
                    } else {
                        retsize <<= 1;
                    }

                    pptmpbuf = (char**) malloc(retsize * sizeof(*pptmpbuf));
                    if (pptmpbuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", retsize * sizeof(*pptmpbuf), ret);
                        goto fail;
                    }
                    memset(pptmpbuf, 0 , retsize * sizeof(*pptmpbuf));
                    if (retlen > 0) {
                        memcpy(pptmpbuf, ppretarrs, retlen * sizeof(*pptmpbuf));
                    }
                    if (ppretarrs != NULL && ppretarrs != *ppparrs) {
                        free(ppretarrs);
                    }
                    ppretarrs = pptmpbuf;
                    pptmpbuf = NULL;
                }
                ppretarrs[retlen] = (char*)malloc(curlen + 1);
                if (ppretarrs[retlen] == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", curlen + 1, ret);
                    goto fail;
                }
                memset(ppretarrs[retlen], 0 , curlen + 1);
                memcpy(ppretarrs[retlen], plastptr, curlen);
                if (*pcur != '\0') {
                    pcur += cmplen;
                }
                plastptr = pcur;
                curlen = 0;
                retlen ++;
            } else {
                curlen ++;
                pcur ++;
            }
        }

        if (curlen > 0) {
            goto copy_one;
        }
    }

    if (*ppparrs && *ppparrs != ppretarrs) {
        free(*ppparrs);
    }
    *ppparrs = ppretarrs;
    *psize = retsize;
    return retlen;

fail:
    if (pptmpbuf != NULL) {
        free(pptmpbuf);
    }
    pptmpbuf = NULL;
    if (ppretarrs) {
        for (i = 0; ppretarrs[i] != NULL; i++) {
            free(ppretarrs[i]);
            ppretarrs[i] = NULL;
        }

        if (ppretarrs != *ppparrs) {
            free(ppretarrs);
        }
    }
    ppretarrs = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int split_chars_re(const char* str, const char* sp, int reflags, char*** ppparrs, int *psize)
{
    char** ppretarrs = NULL;
    char** pptmpbuf = NULL;
    int retsize = 0;
    int retlen = 0;
    int i;
    char* pcur = NULL;
    int curlen = 0;
    int ret;
    void* preg = NULL;
    int *pstartpos = NULL, *pendpos = NULL;
    int resize = 0;
    int cend = 0;

    if (str == NULL) {
        if (ppparrs && *ppparrs) {
            ppretarrs = *ppparrs;
            for (i = 0; ppretarrs[i]; i++) {
                free(ppretarrs[i]);
                ppretarrs[i] = NULL;
            }
            free(ppretarrs);
            *ppparrs = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppparrs == NULL || psize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    ppretarrs = *ppparrs;
    retsize = *psize;
    if (ppretarrs != NULL) {
        /*now free it*/
        for (i = 0; i < retsize; i++) {
            if (ppretarrs[i]) {
                free(ppretarrs[i]);
                ppretarrs[i] = NULL;
            }
        }
    }

    ret = regex_compile(sp, reflags, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pcur = (char*)str;
    while (*pcur != '\0') {
        ret = regex_exec(preg, pcur, &pstartpos, &pendpos, &resize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        } else if (ret == 0) {
            curlen = strlen(pcur);
            cend = strlen(pcur);
        } else {
            curlen = pstartpos[0];
            cend = pendpos[0];
        }
        if (retlen >= (retsize - 1) || ppretarrs == NULL) {
            if (retsize < 2) {
                retsize = 4;
            } else {
                retsize <<= 1;
            }

            pptmpbuf = (char**) malloc(retsize * sizeof(*pptmpbuf));
            if (pptmpbuf == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize * sizeof(*pptmpbuf), ret);
                goto fail;
            }
            memset(pptmpbuf, 0 , retsize * sizeof(*pptmpbuf));
            if (retlen > 0) {
                memcpy(pptmpbuf, ppretarrs, retlen * sizeof(*pptmpbuf));
            }
            if (ppretarrs != NULL && ppretarrs != *ppparrs) {
                free(ppretarrs);
            }
            ppretarrs = pptmpbuf;
            pptmpbuf = NULL;
        }
        ppretarrs[retlen] = (char*)malloc(curlen + 1);
        if (ppretarrs[retlen] == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", curlen + 1, ret);
            goto fail;
        }
        memset(ppretarrs[retlen], 0 , curlen + 1);
        memcpy(ppretarrs[retlen], pcur, curlen);
        pcur += cend;
        curlen = 0;
        retlen ++;
    }

    regex_exec(NULL,NULL, &pstartpos, &pendpos, &resize);
    regex_compile(NULL, 0, &preg);

    if (*ppparrs && *ppparrs != ppretarrs) {
        free(*ppparrs);
    }
    *ppparrs = ppretarrs;
    *psize = retsize;
    return retlen;

fail:
    regex_exec(NULL,NULL, &pstartpos, &pendpos, &resize);
    regex_compile(NULL, 0, &preg);
    if (pptmpbuf != NULL) {
        free(pptmpbuf);
    }
    pptmpbuf = NULL;
    if (ppretarrs) {
        for (i = 0; ppretarrs[i] != NULL; i++) {
            free(ppretarrs[i]);
            ppretarrs[i] = NULL;
        }

        if (ppretarrs != *ppparrs) {
            free(ppretarrs);
        }
    }
    ppretarrs = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}