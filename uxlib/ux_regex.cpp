#include <ux_regex.h>
#include <ux_err.h>
#include <ux_output_debug.h>

#include <regex.h>
#include <string.h>

#define  REGEX_MAGIC   0xddc2d203

typedef struct __ex_regex_t {
    uint32_t m_magic;
    int m_flags;
    regex_t *m_regex;
} ex_regex_t, *pex_regex_t;


void __free_regex(pex_regex_t* ppreg)
{
    pex_regex_t pregex = NULL;
    if (ppreg && *ppreg) {
        pregex = *ppreg;
        ASSERT_IF(pregex->m_magic == REGEX_MAGIC);
        if (pregex->m_regex) {
            regfree(pregex->m_regex);
            free(pregex->m_regex);
        }
        pregex->m_regex = NULL;
        pregex->m_flags = 0;
        pregex->m_magic = 0;
        free(pregex);
        *ppreg = NULL;
    }
    return;
}

pex_regex_t __alloc_regex()
{
    pex_regex_t pregex = NULL;
    int ret;
    pregex = (pex_regex_t)malloc(sizeof(*pregex));
    if (pregex == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pregex, 0, sizeof(*pregex));
    pregex->m_magic = REGEX_MAGIC;
    pregex->m_regex = NULL;
    pregex->m_flags = 0;
    return pregex;
fail:
    __free_regex(&pregex);
    SETERRNO(ret);
    return NULL;
}

int regex_compile(const char* restr, int flags, void**ppreg)
{
    pex_regex_t pretreg = NULL;
    int ret;
    int cflags = REG_EXTENDED;
    if (restr == NULL) {
        __free_regex((pex_regex_t*) ppreg);
        return 0;
    }

    if (ppreg == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }
    pretreg = (pex_regex_t) * ppreg;
    if (pretreg == NULL) {
        pretreg = __alloc_regex();
    }
    if (pretreg == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    if (pretreg->m_regex != NULL) {
        regfree(pretreg->m_regex);
    } else {
        pretreg->m_regex = (regex_t*)malloc(sizeof(regex_t));
        if (pretreg->m_regex == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        memset(pretreg->m_regex, 0 , sizeof(regex_t));
    }

    if (flags & REGEX_IGNORE_CASE) {
        cflags |= REG_ICASE;
    }

    pretreg->m_flags = cflags;
    ret = regcomp(pretreg->m_regex, restr, cflags);
    if (ret != 0) {
        GETERRNO(ret);
        ERROR_INFO("compile [%s] error[%d]", restr, ret);
        goto fail;
    }

    if (*ppreg && *ppreg != pretreg) {
        __free_regex((pex_regex_t*)ppreg);
    }

    *ppreg = pretreg;
    return 0;
fail:
    if (pretreg && pretreg != *ppreg) {
        __free_regex(&pretreg);
    }
    pretreg = NULL;
    SETERRNO(ret);
    return ret;
}

int regex_exec(void* preg, const char* instr, int** ppstartpos, int **ppendpos, int * psize)
{
    pex_regex_t pregex = (pex_regex_t) preg;
    int ret;
    int* pretstart = NULL;
    int* pretend = NULL;
    int retsize = 0;
    int retlen = 0;
    int i;
    regmatch_t* pmatches = NULL;
    int matchsize = 4;
    if (preg == NULL) {
        if (ppstartpos && *ppstartpos) {
            free(*ppstartpos);
            *ppstartpos = NULL;
        }
        if (ppendpos && *ppendpos) {
            free(*ppendpos);
            *ppendpos = NULL;
        }

        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (pregex->m_magic != REGEX_MAGIC ||
            pregex->m_regex == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    if (ppstartpos == NULL ||
            ppendpos == NULL ||
            psize == NULL) {
        ret  = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstart = *ppstartpos;
    pretend = *ppendpos;
    retsize = *psize;

try_again:
    if (pmatches) {
        free(pmatches);
    }
    pmatches = NULL;
    pmatches = (regmatch_t*)malloc(sizeof(*pmatches) * matchsize);
    if (pmatches == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pmatches, 0 , sizeof(*pmatches) * matchsize);

    ret = regexec(pregex->m_regex, instr, matchsize, pmatches, 0);
    if (ret != 0) {
    	if (ret == REG_NOMATCH) {
    		/*nothing to match*/
    		retlen = 0;
    		goto succ;
    	}
        ERROR_INFO("can not match [%s] error[%d]", instr, ret);
        if (ret > 0 ){
        	ret = -ret;
        }
        if (ret == 0) {
        	ret = -1;
        }
        goto fail;
    }

    retlen = 0;
    for (i=0;i<matchsize;i++) {
    	if (pmatches[i].rm_so == -1 &&
    		pmatches[i].rm_eo == -1) {
    		break;
    	}
    }
    retlen = i;

    if (retlen == matchsize) {
    	matchsize <<= 1;
    	goto try_again;
    }

    if (retlen > retsize || pretstart == NULL || pretend == NULL) {
        if (retsize < retlen) {
            retsize = retlen;
        }
        pretstart = (int*)malloc(sizeof(*pretstart) * retsize);
        if (pretstart == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        pretend = (int*)malloc(sizeof(*pretend) * retsize);
        if (pretend == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
    memset(pretend, 0 , sizeof(*pretend) * retsize);
    memset(pretstart, 0 , sizeof(*pretstart) * retsize);
    for (i=0;i<retlen;i++) {
    	pretstart[i] = pmatches[i].rm_so;
    	pretend[i] = pmatches[i].rm_eo;
    }

succ:
    if (pmatches) {
        free(pmatches);
    }
    pmatches = NULL;
    matchsize = 0;

    if (*ppstartpos && *ppstartpos != pretstart) {
        free(*ppstartpos);
    }
    *ppstartpos = pretstart;
    if (*ppendpos && *ppendpos != pretend) {
        free(*ppendpos);
    }
    *ppendpos = pretend;
    *psize = retsize;
    return retlen;
fail:
    if (pmatches) {
        free(pmatches);
    }
    pmatches = NULL;
    matchsize = 0;
    if (pretstart && pretstart != *ppstartpos) {
        free(pretstart);
    }
    pretstart = NULL;
    if (pretend && pretend != *ppendpos) {
        free(pretend);
    }
    pretend = NULL;
    SETERRNO(ret);
    return ret;
}