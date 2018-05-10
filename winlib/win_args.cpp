
#include <win_args.h>
#include <win_uniansi.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <win_strop.h>

void free_args(char*** pppargs)
{
    int i;
    char **ppargs;
    int lensize = 0;
    if (pppargs == NULL) {
        return;
    }

    ppargs = *pppargs;
    if (ppargs == NULL) {
        return ;
    }
    for (i = 0; ppargs[i]; i++) {
        lensize = (int)strlen(ppargs[i]);
        lensize ++;
        TcharToAnsi(NULL, &(ppargs[i]), &lensize);
    }

    free(ppargs);
    *pppargs = NULL;
    return;
}

char** copy_args(int argc, TCHAR *argv[])
{
    int i;
    int ret;
    char** ppargs = NULL;
    size_t argssize = 0;
    int cursize = 0;

    /*we include the end to indicate*/
    argssize = sizeof(ppargs[0]) * (argc + 1);

    ppargs = (char**) malloc(argssize);
    if (ppargs == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc(%d) error(%d)", argssize, ret);
        goto fail;
    }
    memset(ppargs, 0, argssize);

    for (i = 0; i < argc; i++) {
        cursize = 0;
        ret = TcharToAnsi(argv[i], &(ppargs[i]), &cursize);
        if (ret < 0) {
            ERROR_INFO("can not convert[%d] args error(%d)", i, ret);
            goto fail;
        }
    }

    return ppargs;
fail:
    free_args(&ppargs);
    SETERRNO(-ret);
    return NULL;
}

int  parse_number(char* str, uint64_t *pnum, char** ppend)
{
    int ret;
    int base = 10;
    char* pcurptr = str;
    char* pretptr = str;
    uint64_t val;

    if (_strnicmp(str, "x", 1) == 0) {
        pcurptr ++;
        base = 16;
    } else if (_strnicmp(str, "0x", 2) == 0) {
        pcurptr += 2;
        base = 16;
    }

    val = strtoull(pcurptr, &pretptr, base);
    if (val == 0) {
        if (pretptr == pcurptr) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
    } else if (val == ULLONG_MAX) {
        if (pretptr > (pcurptr + 32)) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
    }

    *pnum = val;
    if (ppend) {
        *ppend = pretptr;
    }
    return 1;
fail:
    SETERRNO(-ret);
    return ret;
}

int  parse_int(char* str, int64_t* pnum, char**ppend)
{
    int ret;
    int base = 10;
    char* pcurptr = str;
    char* pretptr = str;
    int64_t val;


    val = strtoll(pcurptr, &pretptr, base);
    if (val == 0) {
        if (pretptr == pcurptr) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
    } else if (val == ULLONG_MAX) {
        if (pretptr > (pcurptr + 32)) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
    }

    *pnum = val;
    if (ppend) {
        *ppend = pretptr;
    }
    return 1;
fail:
    SETERRNO(-ret);
    return ret;
}

int  parse_long_double(char* str, long double *pdbl, char** ppend)
{
    int ret;
    long double retdbl;
    char* pretstr = NULL;

    if (pdbl == NULL || str == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    errno = 0;
    retdbl = strtold(str, &pretstr);
    if (retdbl == 0.0 && str == pretstr) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    } else if (errno == ERANGE) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }
    *pdbl = retdbl;
    if (ppend) {
        *ppend = pretstr;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}