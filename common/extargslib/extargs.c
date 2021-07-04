#include <extargs.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <jvalue.h>
#include <cmn_strop.h>

#ifdef EXTARGS_VERBOSE
#include <debug_jvalue.h>
#define DEBUG_JVALUE(value,...)   do{if (st_extargs_loglevel >= EXTARGS_LOG_DEBUG) {debug_jvalue(stderr,value,FILE,LINE,__VA_ARGS__);}}while(0)
#define EXTARGS_DEBUG_BUFFER(ptr,size,...) do{if (st_extargs_loglevel >= EXTARGS_LOG_DEBUG) {EXTARGS_DEBUG_BUFFER(stderr,(ptr),(size),FILE,LINE,__VA_ARGS__);}}while(0)
#else
#define DEBUG_JVALUE(...)
#define EXTARGS_DEBUG_BUFFER(...)
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif


#ifdef __EXTARGS_WIN__
/*this is windows defined*/
#define STRNCASECMP _strnicmp
#define GETENV(envkey) getenv(envkey)

#else
/*this is not windows defined*/
#define STRNCASECMP strncasecmp
#define GETENV      getenv
#include <strings.h>
#endif


#define STRNCMP   strncmp

#ifndef ULLONG_MAX
#define ULLONG_MAX  (0xffffffffffffffffULL)
#endif

#define EXTARGS_LOG_FATAL     0
#define EXTARGS_LOG_ERROR     1
#define EXTARGS_LOG_WARN      2
#define EXTARGS_LOG_INFO      3
#define EXTARGS_LOG_DEBUG     4

#define EXTARGS_HASH_NUM      127
#define EXTARGS_HASH_INITSIZE 4


static int st_extargs_loglevel = EXTARGS_LOG_WARN;
static extargs_options_t st_default_extargs_options = {
    sizeof(extargs_options_t)              /*default size to handle*/,
    0                                      /*default m_nohelp 0*/,
    NULL                                   /*default m_argv0 for argv[0]*/,
    EXTARGS_FLAG_DEFAULT                   /*default has json */,
    EXTARGS_DEFAULT_SCREENWIDTH            /*default screen width 80*/,
    EXTARGS_DEFAULT_LONGPREFIX             /*default long prefix --*/,
    EXTARGS_DEFAULT_SHORTPREFIX            /*default short prefix -*/,
    EXTARGS_DEFAULT_JSONLONG               /*default jsonlong json*/
};

typedef struct extargs_inner_state {
    unsigned int m_innersize;
    extargs_options_t m_options;
    popt_cmd_t m_pmaincmd;
} extargs_inner_state_t, *pextargs_inner_state_t;

static extargs_inner_state_t st_extargs_inner_state ;


typedef int (*opt_func_base_t)(char* key,char* value,void** ppdestopt);


#define EXTARGS_PRINTF(...)  \
    do {\
        fprintf(stderr,"[%s:%d] ",__FILE__,__LINE__);\
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");\
        fflush(stderr);\
    } while(0)

#define EXTARGS_LEVEL_PRINTF(level,...) \
    do {\
        if (st_extargs_loglevel >= level) {\
            EXTARGS_PRINTF(__VA_ARGS__);\
        }\
    }while(0)


#define EXTARGS_DEBUG(...)  EXTARGS_LEVEL_PRINTF(EXTARGS_LOG_DEBUG,__VA_ARGS__)
#define EXTARGS_ERROR(...)  EXTARGS_LEVEL_PRINTF(EXTARGS_LOG_ERROR,__VA_ARGS__)
#define EXTARGS_WARN(...)   EXTARGS_LEVEL_PRINTF(EXTARGS_LOG_WARN,__VA_ARGS__)
#define EXTARGS_INFO(...)   EXTARGS_LEVEL_PRINTF(EXTARGS_LOG_INFO,__VA_ARGS__)
#define EXTARGS_FATAL(...)  EXTARGS_LEVEL_PRINTF(EXTARGS_LOG_FATAL,__VA_ARGS__)


void free_extargs_inner_state(extargs_inner_state_t* pinnerstate)
{
    unsigned int size;
    if (pinnerstate != NULL) {
        size = pinnerstate->m_options.m_optionsize;
        if (size > OPTION_OFFSET(extargs_options_t, m_argv0) &&  pinnerstate->m_options.m_argv0 != NULL) {
            free(pinnerstate->m_options.m_argv0);
            pinnerstate->m_options.m_argv0 = NULL;
        }
        if (size > OPTION_OFFSET(extargs_options_t, m_nohelp)) {
            pinnerstate->m_options.m_nohelp = 0;
        }
        if (size > OPTION_OFFSET(extargs_options_t, m_optionsize)) {
            pinnerstate->m_options.m_optionsize = 0;
        }
        if (size > OPTION_OFFSET(extargs_options_t, m_flags)) {
            pinnerstate->m_options.m_flags = EXTARGS_FLAG_DEFAULT;
        }

        if (size > OPTION_OFFSET(extargs_options_t, m_screenwidth)) {
            pinnerstate->m_options.m_screenwidth = EXTARGS_DEFAULT_SCREENWIDTH;
        }
        if (size > OPTION_OFFSET(extargs_options_t, m_longprefix)) {
            if (pinnerstate->m_options.m_longprefix != NULL) {
                free(pinnerstate->m_options.m_longprefix);
            }
            pinnerstate->m_options.m_longprefix = NULL;
        }

        if (size > OPTION_OFFSET(extargs_options_t, m_shortprefix)) {
            if (pinnerstate->m_options.m_shortprefix != NULL) {
                free(pinnerstate->m_options.m_shortprefix);
            }
            pinnerstate->m_options.m_shortprefix = NULL;
        }

        if (size > OPTION_OFFSET(extargs_options_t,m_jsonlong)) {
            if (pinnerstate->m_options.m_jsonlong != NULL) {
                free(pinnerstate->m_options.m_jsonlong);
            }
            pinnerstate->m_options.m_jsonlong = NULL;
        }
        /*now to set the innerstate size 0*/
        pinnerstate->m_pmaincmd = NULL;
        pinnerstate->m_innersize = 0;
    }
    return;
}

int _normalize_strdup(const char* penv, char** ppout)
{
    int ret = 0;
    int retlen = 0;
    int i,j;
    const char* psrc=NULL; 
    char* pdst = NULL;
    if (penv == NULL) {
        if (ppout && *ppout) {
            free(*ppout);
            *ppout = NULL;
        }
        return 0;
    }

    if (ppout== NULL) {
        ret = -EXTARGS_INVAL_PARAM;
        return ret;
    }

    if (*ppout !=NULL) {
        free(*ppout);
        *ppout = NULL;
    }

    retlen = (int) strlen(penv);
    retlen += 1;
    *ppout = (char*)malloc(retlen);
    if (*ppout == NULL) {
        ret = -EXTARGS_NO_MEM;
    } else {
        j = 0;
        pdst = *ppout;
        for (i=0,psrc=penv;*psrc != '\0';i++,psrc ++) {
            if (*psrc == '\\' || *psrc == '/') {
                *pdst = *psrc;
                pdst ++;
                j ++;
            } else if (*psrc >= '0' && *psrc <= '9') {
                *pdst = *psrc;
                pdst ++;
                j ++;
            } else if (*psrc >= 'a' && *psrc <= 'z') {
                *pdst = *psrc;
                pdst ++;
                j ++;                
            } else if (*psrc >= 'A' && *psrc <= 'Z') {
                *pdst = *psrc;
                pdst ++;
                j ++;                
            } else if (*psrc == ' ' || *psrc == '_') {
                *pdst = *psrc;
                pdst ++;
                j ++;
            } else {
                ret = -EXTARGS_INVAL_PARAM;
                goto fail;
            }
        }
        ret = j;
    }    
    return ret;
fail:
    if (ppout && *ppout) {
        free(*ppout);
        *ppout = NULL;
    }
    return ret;
}

int init_extargs_inner_state(int argc, char* argv[], popt_cmd_t pmaincmd, extargs_options_t* pextopt)
{
    extargs_options_t* pptropt = pextopt;
    int ret;
    int optionsize = 0;
    if (pptropt == NULL) {
        pptropt = &(st_default_extargs_options);
    }
    free_extargs_inner_state(&st_extargs_inner_state);

    optionsize = pptropt->m_optionsize;
    memset(&st_extargs_inner_state, 0, sizeof(st_extargs_inner_state));
    st_extargs_inner_state.m_innersize = sizeof(st_extargs_inner_state);
    st_extargs_inner_state.m_options.m_optionsize = sizeof(st_extargs_inner_state.m_options);
    if (optionsize > OPTION_OFFSET(extargs_options_t, m_argv0)) {
        if (pptropt->m_argv0 == NULL) {
            if (argv != NULL && argc > 0) {
                st_extargs_inner_state.m_options.m_argv0 = safe_strdup(argv[0]);
            } else {
                st_extargs_inner_state.m_options.m_argv0 = safe_strdup("program");
            }
        } else {
            st_extargs_inner_state.m_options.m_argv0 = safe_strdup(pptropt->m_argv0);
        }
    } else {
        st_extargs_inner_state.m_options.m_argv0 = safe_strdup(pptropt->m_argv0);
    }
    if (st_extargs_inner_state.m_options.m_argv0 == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }
    if (optionsize > OPTION_OFFSET(extargs_options_t, m_nohelp)) {
        st_extargs_inner_state.m_options.m_nohelp = pptropt->m_nohelp;
    }

    if (optionsize > OPTION_OFFSET(extargs_options_t, m_flags)) {
        st_extargs_inner_state.m_options.m_flags = pptropt->m_flags;
    } else {
        st_extargs_inner_state.m_options.m_flags = EXTARGS_FLAG_DEFAULT;
    }

    if (optionsize > OPTION_OFFSET(extargs_options_t, m_screenwidth)) {
        if (pptropt->m_screenwidth < EXTARGS_MIN_SCREENWIDTH) {
            st_extargs_inner_state.m_options.m_screenwidth = EXTARGS_MIN_SCREENWIDTH;
        } else {
            st_extargs_inner_state.m_options.m_screenwidth = pptropt->m_screenwidth;
        }
    } else {
        st_extargs_inner_state.m_options.m_screenwidth = EXTARGS_DEFAULT_SCREENWIDTH;
    }

    if (optionsize > OPTION_OFFSET(extargs_options_t, m_longprefix)) {
        if (pptropt->m_longprefix != NULL) {
            st_extargs_inner_state.m_options.m_longprefix = safe_strdup(pptropt->m_longprefix);
        } else {
            st_extargs_inner_state.m_options.m_longprefix = safe_strdup(EXTARGS_DEFAULT_LONGPREFIX);
        }
    } else {
        st_extargs_inner_state.m_options.m_longprefix = safe_strdup(EXTARGS_DEFAULT_LONGPREFIX);
    }
    if (st_extargs_inner_state.m_options.m_longprefix == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    if (optionsize > OPTION_OFFSET(extargs_options_t, m_shortprefix)) {
        if (pptropt->m_longprefix != NULL) {
            st_extargs_inner_state.m_options.m_shortprefix = safe_strdup(pptropt->m_shortprefix);
        } else {
            st_extargs_inner_state.m_options.m_shortprefix = safe_strdup(EXTARGS_DEFAULT_SHORTPREFIX);
        }
    } else {
        st_extargs_inner_state.m_options.m_shortprefix = safe_strdup(EXTARGS_DEFAULT_SHORTPREFIX);
    }
    if (st_extargs_inner_state.m_options.m_shortprefix == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    if (optionsize > OPTION_OFFSET(extargs_options_t,m_jsonlong)) {
        if (pptropt->m_jsonlong != NULL) {
            st_extargs_inner_state.m_options.m_jsonlong = safe_strdup(pptropt->m_jsonlong);
        } else {
            st_extargs_inner_state.m_options.m_jsonlong = safe_strdup(EXTARGS_DEFAULT_JSONLONG);
        }
    } else {
        st_extargs_inner_state.m_options.m_jsonlong = safe_strdup(EXTARGS_DEFAULT_JSONLONG);
    }

    if (st_extargs_inner_state.m_options.m_jsonlong == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    if (strcmp(st_extargs_inner_state.m_options.m_shortprefix, st_extargs_inner_state.m_options.m_longprefix) == 0) {
        /*it means that the no bundle for -v -default*/
        st_extargs_inner_state.m_options.m_flags |= EXTARGS_FLAG_NO_BUNDLE;
    } else {
        st_extargs_inner_state.m_options.m_flags &= (~EXTARGS_FLAG_NO_BUNDLE);
    }

    st_extargs_inner_state.m_pmaincmd = pmaincmd;
    return 0;
fail:
    free_extargs_inner_state(&st_extargs_inner_state);
    return ret;
}

int  inner_parse_number(char* str, unsigned long long *pnum, char** ppend)
{
    int ret;
    int base = 10;
    char* pcurptr = str;
    char* pretptr = str;
    unsigned long long val;

    if (STRNCASECMP(str, "x", 1) == 0) {
        pcurptr ++;
        base = 16;
    } else if (STRNCASECMP(str, "0x", 2) == 0) {
        pcurptr += 2;
        base = 16;
    }

    val = strtoull(pcurptr, &pretptr, base);
    if (val == 0) {
        if (pretptr == pcurptr) {
            ret = -EXTARGS_INVAL_PARAM;
            goto fail;
        }
    } else if (val == ULLONG_MAX) {
        if (pretptr > (pcurptr + 32)) {
            ret = -EXTARGS_INVAL_PARAM;
            goto fail;
        }
    }

    *pnum = val;
    if (ppend) {
        *ppend = pretptr;
    }
    return 1;
fail:
    return ret;
}


int true_opt_func_base(char* key, char* value, void** ppdestopt)
{
    int** bopt = (int**)ppdestopt;
    char* dummy = key;
    dummy = dummy;
    EXTARGS_DEBUG("[%s] value [%s]", key, value);
    if (value && strcmp(value, "true") == 0) {
        (**bopt) = 1;
    } else {
        (**bopt) = 0;
    }
    return 0;
}

int false_opt_func_base(char* key, char* value, void** ppdestopt)
{
    int** bopt = (int**)ppdestopt;
    char* dummy = key;
    dummy = dummy;
    if (value && strcmp(value, "false") == 0) {
        (**bopt) = 0;
    } else {
        (**bopt) = 1;
    }
    return 0;
}

int string_opt_func_base(char* key, char* value, void** ppdestopt)
{
    char*** ppchardest = (char***)ppdestopt;
    char* pretval = NULL;
    char* dummy = key;
    dummy = dummy;
    /*we free the string first */
    if (**ppchardest != NULL) {
        EXTARGS_DEBUG("ppchardest %p *ppchardest (%p) **ppchardest (%p):%s",
                      ppchardest, *ppchardest, **ppchardest, **ppchardest);
        free(**ppchardest);
        **ppchardest = NULL;
    }
    if (value != NULL) {
        pretval = safe_strdup(value);
        if (pretval == NULL) {
            return -EXTARGS_NO_MEM;
        }
        EXTARGS_DEBUG("**(%p) %s(%p) => %s(%p) ", ppdestopt, **ppchardest , **ppchardest, pretval, pretval);
        assert(**ppchardest == NULL);
        (**ppchardest) = pretval;
    }

    return 1;
}

int list_opt_func_base(char* key, char* value, void** ppdestopt)
{
    char**** pppc = (char****) ppdestopt;
    char** oldpc ;
    char** newpc = NULL;
    int ret;
    int cnt = 0;
    int i;
    key = key;

    if (pppc == NULL || *pppc == NULL) {
        return -EXTARGS_INVAL_PARAM;
    }

    oldpc = **pppc;
    EXTARGS_DEBUG("pppc %p *pppc %p **pppc %p", pppc, *pppc, **pppc);
    if (oldpc) {
        while (oldpc[cnt] != NULL) {
            cnt ++;
        }
    }

    if (value != NULL) {
        /*one for new item ,one for end null*/
        newpc = (char**)malloc(sizeof(*newpc) *  (cnt + 2));
        if (newpc == NULL) {
            ret = -EXTARGS_NO_MEM;
            return ret;
        }
        memset(newpc, 0, sizeof(*newpc) * (cnt + 2));
        for (i = 0; i < cnt; i++) {
            newpc[i] = oldpc[i];
        }
        newpc[cnt] = safe_strdup(value);
        if (newpc[cnt] == NULL) {
            free(newpc);
            newpc = NULL;
            return -EXTARGS_NO_MEM;
        }
    } else {
        /*we free the memory*/
        if (oldpc) {
            for (i=0;;i++) {
                if (oldpc[i] == NULL) {
                    break;
                }
                free(oldpc[i]);
                oldpc[i] = NULL;
            }
        }
    }
    if (oldpc) {
        free(oldpc);
    }
    (**pppc) = newpc;
    return 1;
}

int inc_opt_func_base(char* key, char* value, void** ppdestopt)
{
    int** intptr = (int**)ppdestopt;
    char* dummy1 = key;
    char* dummy2 = value;
    dummy1 = dummy1;
    dummy2 = dummy2;
    (**intptr) ++;
    return 0;
}

int cmd_opt_func_base(char* key, char* value, void** ppdestopt)
{
    int ret;
    ret = string_opt_func_base(key, value, ppdestopt);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

int arg_opt_func_base(char* key, char* value, void** ppdestopt)
{
    return list_opt_func_base(key, value, ppdestopt);
}

int dict_opt_func_base(char* key, char* value, void** ppdestopt)
{
    void** dummy3 = ppdestopt;
    char* dummy1 = key;
    char* dummy2 = value;
    dummy1 = dummy1;
    dummy2 = dummy2;
    dummy3 = dummy3;

    return -EXTARGS_NOT_SUPPORTED;
}

int int_opt_func_base(char* key, char* value, void** ppdestopt)
{
    int** intptr = (int**)ppdestopt;
    unsigned long long num;
    char* pendptr = NULL;
    int ret;
    char* dummy = key;
    dummy = dummy;

    ret = inner_parse_number(value, &num, &pendptr);
    if (ret < 0) {
        return ret;
    }

    if (*pendptr != '\0') {
        return -1;
    }
    (**intptr) = (int) num;
    return 1;
}

int double_opt_func_base(char* key, char* value, void** ppdestopt)
{
    double** ppdouble = (double**)ppdestopt;
    double tmpd;
    char* pendptr;
    char* dummy = key;
    dummy = dummy;
    if (value == NULL) {
        return -EXTARGS_INVAL_PARAM;
    }
    tmpd = strtod(value, &pendptr);
    if (*pendptr != '\0') {
        return -EXTARGS_INVAL_PARAM;
    }
    (**ppdouble) = tmpd;
    return 1;
}

int ll_opt_func_base(char* key, char* value, void** ppdestopt)
{
    long long** ppll = (long long**)ppdestopt;
    unsigned long long num;
    int ret;
    char* pendptr;
    char* dummy = key;
    dummy = dummy;

    ret = inner_parse_number(value, &num, &pendptr);
    if (ret < 0) {
        return -EXTARGS_INVAL_PARAM;
    }
    if (*pendptr != '\0') {
        return -EXTARGS_INVAL_PARAM;
    }
    (**ppll) = (long long)num;
    return 1;
}

int ull_opt_func_base(char* key, char* value, void** ppdestopt)
{
    unsigned long long** ppull = (unsigned long long**)ppdestopt;
    unsigned long long num;
    int ret;
    char* pendptr;
    char* dummy = key;
    dummy = dummy;

    ret = inner_parse_number(value, &num, &pendptr);
    if (ret < 0) {
        return -EXTARGS_INVAL_PARAM;
    }
    if (*pendptr != '\0') {
        return -EXTARGS_INVAL_PARAM;
    }
    (**ppull) = (unsigned long long)num;
    return 1;
}

int jsonfile_opt_func_base(char* key, char* value, void** ppdestopt)
{
    EXTARGS_DEBUG("jsonfile[%s]",value);
    return string_opt_func_base(key, value, ppdestopt);
}

int help_opt_func_base(char* key, char* value, void** ppdestopt)
{
    char* dummy1 = key;
    void** dummy2 = ppdestopt;
    dummy1 = dummy1;
    dummy2 = dummy2;
    if (st_extargs_inner_state.m_options.m_argv0 != NULL) {
        default_help_function(st_extargs_inner_state.m_options.m_argv0, value, 0, st_extargs_inner_state.m_pmaincmd, NULL);
    } else {
        default_help_function("prog", value, 0, st_extargs_inner_state.m_pmaincmd, NULL);
    }
    return 0;
}

#define MAKE_LONGOPT_KEY(keyname,keysizename)  \
    do{\
        if (st_extargs_inner_state.m_options.m_longprefix != NULL){\
           ret = snprintf_safe(&keyname,&keysizename,"%s%s",st_extargs_inner_state.m_options.m_longprefix,popthelp->m_longopt);\
        } else {\
            ret = snprintf_safe(&keyname,&keysizename,"%s%s",EXTARGS_DEFAULT_LONGPREFIX,popthelp->m_longopt);\
        }\
        if (ret < 0) {\
            goto fail;\
        }\
    } while(0)


/**********************************************************
* this is function exported
**********************************************************/
int true_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    char* pkey=NULL,*pvalue=NULL;
    int keysize =0,valuesize=0;
    int ret;
    int step =0;
    argv = argv;

    if (validx > argc) {
        return -EXTARGS_INVAL_PARAM;
    }
    MAKE_LONGOPT_KEY(pkey,keysize);
    ret = snprintf_safe(&pvalue,&valuesize,"true");
    if (ret < 0) {
        goto fail;
    }
    step = true_opt_func_base(pkey,pvalue,ppdestopt);
    if (step < 0) {
        ret = step;
        goto fail;
    }
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return step;
fail:
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return ret;
}

int false_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    char* key=NULL,*pvalue=NULL;
    int keysize =0,valuesize=0;
    int ret;
    int step =0;

    argv = argv;
    if (validx > argc) {
        return -EXTARGS_INVAL_PARAM;
    }
    MAKE_LONGOPT_KEY(key,keysize);
    ret = snprintf_safe(&pvalue,&valuesize,"false");
    if (ret < 0) {
        goto fail;
    }
    step = false_opt_func_base(key,pvalue,ppdestopt);
    if (step < 0) {
        ret = step;
        goto fail;
    }
    snprintf_safe(&key,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return step;
fail:
    snprintf_safe(&key,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return ret;
}

#define OPT_FUNC_WITH_ONE_ARG(optfunc)                                  \
    char* pkey=NULL,*pvalue=NULL;                                       \
    int keysize =0,valuesize=0;                                         \
    int ret;                                                            \
    int step =0;                                                        \
                                                                        \
    if ((validx+1) > argc) {                                            \
        return -EXTARGS_INVAL_PARAM;                                    \
    }                                                                   \
    MAKE_LONGOPT_KEY(pkey,keysize);                                     \
    ret = snprintf_safe(&pvalue,&valuesize,"%s",argv[validx]);  \
    if (ret < 0) {                                                      \
        goto fail;                                                      \
    }                                                                   \
    step = optfunc(pkey,pvalue,ppdestopt);                              \
    if (step < 0) {                                                     \
        ret = step;                                                     \
        goto fail;                                                      \
    }                                                                   \
    snprintf_safe(&pkey,&keysize,NULL);                         \
    snprintf_safe(&pvalue,&valuesize,NULL);                     \
    return step;                                                        \
fail:                                                                   \
    snprintf_safe(&pkey,&keysize,NULL);                         \
    snprintf_safe(&pvalue,&valuesize,NULL);                     \
    return ret;                                                         \


int string_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(string_opt_func_base)
}

int list_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(list_opt_func_base)
}

int inc_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    char* pkey=NULL,*pvalue=NULL;
    int keysize =0,valuesize=0;
    int ret;
    int step =0;

    argv = argv;
    if ((validx) > argc) {
        return -EXTARGS_INVAL_PARAM;
    }
    MAKE_LONGOPT_KEY(pkey,keysize);
    step = inc_opt_func_base(pkey,pvalue,ppdestopt);
    if (step < 0) {
        ret = step;
        goto fail;
    }
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return step;
fail:
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return ret;
}

int cmd_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    char* pkey=NULL,*pvalue=NULL;
    int keysize =0,valuesize=0;
    int ret;
    int step =0;

    popthelp = popthelp;
    if ((validx) > argc || validx <= 0) {
        return -EXTARGS_INVAL_PARAM;
    }

    ret = snprintf_safe(&pvalue,&valuesize,"%s",argv[validx-1]);
    if (ret < 0) {
        goto fail;
    }

    step = cmd_opt_func_base(pkey,pvalue,ppdestopt);
    if (step < 0) {
        ret = step;
        goto fail;
    }
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return step;
fail:
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return ret;
}

int arg_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    char* pkey=NULL,*pvalue=NULL;
    int keysize =0,valuesize=0;
    int ret;
    int step =0;

    popthelp = popthelp;
    if ((validx+1) > argc) {
        return -EXTARGS_INVAL_PARAM;
    }

    ret = snprintf_safe(&pvalue,&valuesize,"%s",argv[validx]);
    if (ret < 0) {
        goto fail;
    }
    
    step = arg_opt_func_base(pkey,pvalue,ppdestopt);
    if (step < 0) {
        ret = step;
        goto fail;
    }
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return step;
fail:
    snprintf_safe(&pkey,&keysize,NULL);
    snprintf_safe(&pvalue,&valuesize,NULL);
    return ret;
}

int dict_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    ppdestopt = ppdestopt;
    popthelp = popthelp;
    validx = validx;
    argv = argv;
    argc = argc;
    return -EXTARGS_NOT_SUPPORTED;
}

int int_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(int_opt_func_base)
}


int double_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(double_opt_func_base)
}

int ll_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(ll_opt_func_base)
}

int ull_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(ull_opt_func_base)
}

int jsonfile_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt)
{
    OPT_FUNC_WITH_ONE_ARG(jsonfile_opt_func_base)
}

/*******************************************************
* these are the jsonfunc to handle
*******************************************************/
#define JSONFUNC_WITH_ONE_ARG(optfunc)                               \
    char* value=(char*)pvalue;                                       \
    char* key=NULL;                                                  \
    int keysize=0;                                                   \
    int ret;                                                         \
                                                                     \
    MAKE_LONGOPT_KEY(key,keysize);                                   \
    ret = optfunc(key,value,ppdestopt);                              \
    if (ret < 0) {                                                   \
        goto fail;                                                   \
    }                                                                \
                                                                     \
    snprintf_safe(&key,&keysize,NULL);                       \
    return ret;                                                      \
                                                                     \
fail:                                                                \
    snprintf_safe(&key,&keysize,NULL);                       \
    return ret;                                                                     


int true_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(true_opt_func_base)
}

int false_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(false_opt_func_base)
}

int string_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(string_opt_func_base)
}

int list_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    char** ppvalue=(char**)pvalue;
    char* key=NULL;
    int keysize=0;
    int ret;
    int i;
    int cnt = 0;

    MAKE_LONGOPT_KEY(key,keysize);
    if (ppvalue != NULL){
        for (i=0;;i++){
            if (ppvalue[i] == NULL) {
                break;
            }
            ret = list_opt_func_base(key,ppvalue[i],ppdestopt);
            if (ret < 0) {
                goto fail;
            }
            cnt ++;
        }
        /*nothing to add ,so we free it*/
        if (cnt == 0) {
            ret = list_opt_func_base(key,NULL,ppdestopt);
            if (ret < 0) {
                goto fail;
            }
        }
    } else {
        ret = list_opt_func_base(key,NULL,ppdestopt);
        if (ret < 0) {
            goto fail;
        }
    }

    snprintf_safe(&key,&keysize,NULL);
    return cnt;

fail:
    snprintf_safe(&key,&keysize,NULL);
    return ret;
}

int inc_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(int_opt_func_base)
}

int cmd_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    popthelp=popthelp;
    pvalue = pvalue;
    ppdestopt = ppdestopt;
    /*we do not supported this*/
    return -EXTARGS_NOT_SUPPORTED;
}

int arg_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    popthelp=popthelp;
    pvalue = pvalue;
    ppdestopt = ppdestopt;
    /*we do not supported this*/
    return -EXTARGS_NOT_SUPPORTED;
}

int dict_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    popthelp=popthelp;
    pvalue = pvalue;
    ppdestopt = ppdestopt;
    /*we do not supported this*/
    return -EXTARGS_NOT_SUPPORTED;
}

int int_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(int_opt_func_base)
}

int double_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(double_opt_func_base)
}

int ll_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(ll_opt_func_base)
}

int ull_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(ull_opt_func_base)
}


int jsonfile_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt)
{
    JSONFUNC_WITH_ONE_ARG(jsonfile_opt_func_base)
}


/*******************************************************
*  this args handle options
*******************************************************/

typedef struct parse_cmd_state {
    char* m_jsonfile;
    popt_help_t m_opthelp;
    popt_cmd_t m_optcmd;
} parse_cmd_state_t, *pparse_cmd_state_t;

pparse_cmd_state_t alloc_parse_cmd_state(popt_cmd_t pcmd)
{
    pparse_cmd_state_t pcmdstate = NULL;
    pcmdstate = (pparse_cmd_state_t)malloc(sizeof(*pcmdstate));
    if (pcmdstate == NULL) {
        return NULL;
    }
    memset(pcmdstate, 0, sizeof(*pcmdstate));
    pcmdstate->m_optcmd = pcmd;
    pcmdstate->m_opthelp = pcmd->m_cmdopts;
    pcmdstate->m_jsonfile = NULL;
    return pcmdstate;
}

void dealloc_parse_cmd_state(pparse_cmd_state_t* ppcmdstate)
{
    pparse_cmd_state_t pcmdstate;
    if (ppcmdstate && *ppcmdstate) {
        pcmdstate = *ppcmdstate;
        if (pcmdstate->m_jsonfile) {
            free(pcmdstate->m_jsonfile);
        }
        pcmdstate->m_jsonfile = NULL;
        free(pcmdstate);
        *ppcmdstate = NULL;
    }
    return;
}

typedef struct extargs_hashbucket {
    void** m_list;
    int m_size;
    int m_num;
} extargs_hashbucket_t, *pextargs_hashbucket_t;

typedef struct extargs_hashmap {
    pextargs_hashbucket_t m_hashbucks;
    int m_maxbucks;
} extargs_hashmap_t, *pextargs_hashmap_t;

void free_extargs_hashbucket(pextargs_hashbucket_t pbucket)
{
    if (pbucket != NULL) {
        if (pbucket->m_list) {
            free(pbucket->m_list);
        }
        pbucket->m_list = NULL;
        pbucket->m_size = 0;
        pbucket->m_num = 0;
    }
    return;
}

void free_extargs_hashmap(pextargs_hashmap_t* pphashmap)
{
    pextargs_hashmap_t phashmap;
    int i;
    if (pphashmap && *pphashmap) {
        phashmap = *pphashmap;
        if (phashmap->m_hashbucks) {
            for (i = 0; i < phashmap->m_maxbucks; i++) {
                free_extargs_hashbucket(&(phashmap->m_hashbucks[i]));
            }
        }
        free(phashmap->m_hashbucks);
        phashmap->m_hashbucks = NULL;
        phashmap->m_maxbucks = 0;
        free(phashmap);
        *pphashmap = NULL;
    }
    return ;
}



typedef struct parse_state {
    int m_curidx;
    int m_curcharidx;
    int m_keyidx;
    int m_validx;
    int m_shortcharhasidx;
    int m_longopthasidx;
    int m_ended;
    extargs_priority_t* m_priorities;
    pparse_cmd_state_t *m_cmdstates;
    int m_cmdsize;
    int m_cmdnum;
    pparse_cmd_state_t *m_dummystates;
    int m_dummysize;
    int m_dummynum;
    pextargs_hashmap_t m_poptsetmap;
    char** m_leftargs;
} parse_state_t, *pparse_state_t;

int extargs_hashnum(void* ptr)
{
    unsigned char* pchar = (unsigned char*) ptr;
    int i;
    int hashnum = 0;
    for (i = 0; i < sizeof(ptr); i++, pchar++) {
        hashnum += *pchar;
    }
    return (hashnum % EXTARGS_HASH_NUM);
}

int is_opt_setted(pparse_state_t pstate, popt_help_t popt)
{
    int hashnum = extargs_hashnum((void*)popt);
    int i;
    void** plist;
    int num;
    if (pstate->m_poptsetmap == NULL) {
        return 0;
    }

    if (pstate->m_poptsetmap->m_hashbucks[hashnum].m_list == NULL) {
        return 0;
    }
    num = pstate->m_poptsetmap->m_hashbucks[hashnum].m_num;
    plist = pstate->m_poptsetmap->m_hashbucks[hashnum].m_list;
    for (i = 0; i < num; i++) {
        if (popt == plist[i]) {
            return 1;
        }
    }
    return 0;
}

int insert_opt_setted(pparse_state_t pstate, popt_help_t popt)
{
    pextargs_hashbucket_t pbucks = NULL;
    void** plist = NULL, **ptmplist = NULL;
    int posnum = 0;
    int hashnum;
    int tmpsize;
    int i;
    if (pstate->m_poptsetmap == NULL) {
        pstate->m_poptsetmap = malloc(sizeof(*(pstate->m_poptsetmap)));
        if (pstate->m_poptsetmap == NULL) {
            return -EXTARGS_NO_MEM;
        }
        memset(pstate->m_poptsetmap, 0, sizeof(*(pstate->m_poptsetmap)));
        pstate->m_poptsetmap->m_maxbucks = 0;
    }

    hashnum = extargs_hashnum(popt);
    if (pstate->m_poptsetmap->m_hashbucks == NULL) {
        pbucks = malloc( sizeof(pbucks[0]) * EXTARGS_HASH_NUM);
        if (pbucks == NULL) {
            return -EXTARGS_NO_MEM;
        }
        memset(pbucks, 0, sizeof(pbucks[0])*EXTARGS_HASH_NUM);
        pstate->m_poptsetmap->m_hashbucks = pbucks;
        pstate->m_poptsetmap->m_maxbucks = EXTARGS_HASH_NUM;
    }

    pbucks = pstate->m_poptsetmap->m_hashbucks;
    assert(hashnum < pstate->m_poptsetmap->m_maxbucks);
    if (pbucks[hashnum].m_list == NULL) {
        pbucks[hashnum].m_size = EXTARGS_HASH_INITSIZE;
        pbucks[hashnum].m_num = 0;
        plist = malloc(sizeof(plist[0]) * EXTARGS_HASH_INITSIZE);
        if (plist == NULL) {
            pbucks[hashnum].m_size = 0;
            return -EXTARGS_NO_MEM;
        }
        memset(plist, 0, sizeof(*(plist))* EXTARGS_HASH_INITSIZE);
        pbucks[hashnum].m_list = plist;
    }
    plist = pbucks[hashnum].m_list;
    posnum = pbucks[hashnum].m_num;

    for (i = 0; i < posnum; i++) {
        if (plist[i] == popt) {
            return 0;
        }
    }

    if (pbucks[hashnum].m_num < pbucks[hashnum].m_size) {
        plist[posnum] = popt;
        pbucks[hashnum].m_num ++;
        return 1;
    }

    tmpsize = pbucks[hashnum].m_size << 1;
    ptmplist = malloc(sizeof(ptmplist[0]) * tmpsize);
    if (ptmplist == NULL) {
        return -EXTARGS_NO_MEM;
    }

    memset(ptmplist, 0, sizeof(ptmplist[0])*tmpsize);
    for (i = 0; i < posnum; i++) {
        ptmplist[i] = plist[i];
    }

    ptmplist[posnum] = popt;
    if (plist) {
        free(plist);
    }

    pbucks[hashnum].m_list = ptmplist;
    pbucks[hashnum].m_num = posnum + 1;
    pbucks[hashnum].m_size = tmpsize;
    return 2;
}

int step_one_cmd(int argc, char* argv[] , pparse_state_t pstate)
{
    int dummy1 = argc;
    char** dummy2 = argv;
    dummy1 = dummy1;
    dummy2 = dummy2;
    EXTARGS_DEBUG("m_curidx [%d] => [%d]",pstate->m_curidx,pstate->m_curidx + 1);
    pstate->m_curidx ++;
    pstate->m_curcharidx = -1;
    pstate->m_shortcharhasidx = -1;
    pstate->m_longopthasidx = -1;
    pstate->m_keyidx = -1;
    pstate->m_validx = -1;
    return 0;
}


opt_help_t* find_opt_idx(int argc, char* argv[], pparse_state_t pstate, int *error)
{
    int oldidx = pstate->m_curidx;
    int oldcharidx = pstate->m_curcharidx;
    int i, j;
    char* pptr;
    char* longprefix = NULL, *shortprefix = NULL;
    int bundlemode = 1;
    size_t longlen = 0, shortlen = 0;
    pparse_cmd_state_t* pcmdstate = NULL;
    popt_help_t poptions = NULL;
    if (error != NULL) {
        *error = 0;    
    }    
    longprefix = st_extargs_inner_state.m_options.m_longprefix;
    shortprefix = st_extargs_inner_state.m_options.m_shortprefix;
    if ((st_extargs_inner_state.m_options.m_flags & EXTARGS_FLAG_NO_BUNDLE)) {
        bundlemode = 0;
    }
    if (longprefix != NULL) {
        longlen = strlen(longprefix);    
    } else {
        longlen = 0;
    }
    
    if (shortprefix != NULL) {
        shortlen = strlen(shortprefix);    
    } else {
        shortlen = 0;
    }
    
    EXTARGS_DEBUG("m_longopthasidx [%d]",pstate->m_longopthasidx);
    if (pstate->m_longopthasidx >= 0) {
        oldidx += pstate->m_longopthasidx;
        pstate->m_longopthasidx = -1;
        pstate->m_shortcharhasidx = -1;
        pstate->m_curcharidx = -1;
        oldcharidx = -1;
    }
search_opt_begin:
    if (oldidx >= argc || pstate->m_ended != 0) {
        pstate->m_curidx = oldidx;
        pstate->m_curcharidx = -1;
        pstate->m_keyidx = -1;
        pstate->m_validx = -1;
        pstate->m_shortcharhasidx = -1;
        pstate->m_longopthasidx = -1;
        if (error != NULL) {
            *error = 0;    
        }        
        return NULL;
    }
    if (strcmp(argv[oldidx], "--") == 0) {
        oldidx ++;
        pstate->m_curidx = oldidx;
        pstate->m_curcharidx = -1;
        pstate->m_ended = 1;
        pstate->m_shortcharhasidx = -1;
        pstate->m_longopthasidx = -1;
        if (error) {
            *error = 0;
        }
        return NULL;
    }

    EXTARGS_DEBUG("search for [%d]%s oldcharidx(%d) m_shortcharhasidx[%d]", oldidx, argv[oldidx], oldcharidx,pstate->m_shortcharhasidx);
    if (bundlemode) {
        if (oldcharidx < 0) {
            if (longprefix != NULL && STRNCMP(argv[oldidx], longprefix, longlen) == 0) {
                /*it is long opt,so we should compare*/
                pptr = &(argv[oldidx][longlen]);
                /*we search for the help of sub command first*/
                j = pstate->m_cmdnum - 1;
                pcmdstate = pstate->m_cmdstates;
                EXTARGS_DEBUG("search for pptr(%s) j[%d] ", pptr,j);
                while (1) {
                    if (pcmdstate == NULL || j < 0) {
                        EXTARGS_DEBUG("[%d] pcmdstate [%p]",j,pcmdstate);
                        break;
                    }
                    poptions = pcmdstate[j]->m_opthelp;
                    if (poptions == NULL) {
                        EXTARGS_DEBUG(" ");
                        break;
                    }
                    for (i = 0; poptions[i].m_longopt != NULL ; i ++) {
                        EXTARGS_DEBUG("[%d] longopt[%s] pptr[%s]",i,poptions[i].m_longopt,pptr);
                        if (strcmp(pptr, poptions[i].m_longopt) == 0) {
                            pstate->m_keyidx = oldidx;
                            oldidx ++;
                            pstate->m_validx = oldidx;
                            /*we pointer to the next for will handle over*/
                            pstate->m_curidx = oldidx;
                            pstate->m_curcharidx = -1;
                            assert(pstate->m_longopthasidx < 0);
                            assert(pstate->m_shortcharhasidx < 0);
                            EXTARGS_DEBUG("[%d] return",i);
                            return &(poptions[i]);
                        }
                    }
                    j --;
                }
                EXTARGS_DEBUG(" ");
                pstate->m_curidx = oldidx;
                pstate->m_validx = -1;
                pstate->m_keyidx = -1;
                pstate->m_curcharidx = -1;
                pstate->m_longopthasidx = -1;
                pstate->m_shortcharhasidx = -1;
                if (error){
                    *error = EXTARGS_NO_OPTS;
                }
                return NULL;
            } else if ( shortprefix != NULL && STRNCMP(argv[oldidx], shortprefix, shortlen) == 0) {
                oldcharidx = (int)shortlen;
find_short_opt_bundle:
                if (argv[oldidx][oldcharidx] == '\0') {
                    /*it is end of char ,so we should give this ok*/
                    EXTARGS_DEBUG("oldidx %d => %d", oldidx ,
                                  pstate->m_shortcharhasidx >= 0 ? (oldidx + pstate->m_shortcharhasidx + 1) : (oldidx + 1));
                    oldidx ++;
                    if (pstate->m_shortcharhasidx >= 0) {
                        /*we have passed the options ,so skip this*/
                        oldidx += pstate->m_shortcharhasidx;
                    }
                    pstate->m_shortcharhasidx = -1;
                    oldcharidx = -1;
                    assert(pstate->m_longopthasidx < 0);
                    goto  search_opt_begin;
                }
                j = pstate->m_cmdnum - 1;
                EXTARGS_DEBUG("search for [%d][%d] %c (%s)", oldidx, oldcharidx, argv[oldidx][oldcharidx], argv[oldidx]);
                pcmdstate = pstate->m_cmdstates;
                while (1) {
                    if (pcmdstate == NULL || j < 0) {
                        break;
                    }
                    poptions = pcmdstate[j]->m_opthelp;
                    assert(poptions != NULL);
                    for (i = 0; poptions[i].m_longopt != NULL ; i ++) {
                        if (poptions[i].m_shortopt != '\0') {
                            EXTARGS_DEBUG("[%d] shortopt [%c] argv[%d][%d] [%c]", i, poptions[i].m_shortopt, oldidx, oldcharidx, argv[oldidx][oldcharidx]);
                            if (poptions[i].m_shortopt == argv[oldidx][oldcharidx]) {
                                oldcharidx ++;
                                pstate->m_curidx = oldidx;
                                pstate->m_curcharidx = oldcharidx;
                                pstate->m_keyidx = oldidx;
                                pstate->m_validx = (oldidx + 1);
                                EXTARGS_DEBUG("get options (%s)", poptions[i].m_longopt);
                                assert(pstate->m_longopthasidx < 0);
                                return &(poptions[i]);
                            }
                        }
                    }
                    j --;
                }
                /*we can not find the jobs*/
                EXTARGS_DEBUG(" ");
                pstate->m_curidx = oldidx;
                pstate->m_validx = -1;
                pstate->m_keyidx = -1;
                pstate->m_curcharidx = -1;
                pstate->m_longopthasidx = -1;
                pstate->m_shortcharhasidx = -1;
                if (error){
                    *error = EXTARGS_NO_OPTS;
                }
                return NULL;
            }
            /*that is like subnargs or args or sub command*/
            if (error) {
                *error = 0;
            }
            pstate->m_curidx = oldidx;
            pstate->m_validx = -1;
            pstate->m_keyidx = -1;
            pstate->m_curcharidx = -1;
            pstate->m_longopthasidx = -1;
            pstate->m_shortcharhasidx = -1;
            return NULL;
        }
        /*we come here is oldcharidx > 0 so we should goto the find_short_opt_bundle*/
        goto find_short_opt_bundle;
    } else {
        /*this is bundle time ,so we should make this ok*/
        assert(oldcharidx < 0);
        if (pstate->m_shortcharhasidx >= 0) {
            /*we step for short char idx*/
            oldidx += pstate->m_shortcharhasidx;
            pstate->m_shortcharhasidx = -1;
        }
        if (oldidx >= argc) {
            pstate->m_curidx = oldidx;
            pstate->m_curcharidx = -1;
            pstate->m_longopthasidx = -1;
            pstate->m_shortcharhasidx = -1;
            pstate->m_keyidx = -1;
            pstate->m_validx = -1;
            if (error) {
                *error = 0;
            }
            return NULL;
        }

        if (longprefix && STRNCMP(argv[oldidx], longprefix, longlen) == 0) {
            pptr = &(argv[oldidx][longlen]);
            /*we search for the help of sub command first*/
            j = pstate->m_cmdnum - 1;
            pcmdstate = pstate->m_cmdstates;
            while (1) {
                if (pcmdstate == NULL || j < 0) {
                    break;
                }
                poptions = pcmdstate[j]->m_opthelp;
                if (poptions == NULL) {
                    break;
                }
                for (i = 0; poptions[i].m_longopt != NULL ; i ++) {
                    if (strcmp(pptr, poptions[i].m_longopt) == 0) {
                        pstate->m_keyidx = oldidx;
                        oldidx ++;
                        pstate->m_validx = oldidx;
                        /*we pointer to the next for will handle over*/
                        pstate->m_curidx = oldidx;
                        pstate->m_curcharidx = -1;
                        assert(pstate->m_longopthasidx < 0);
                        assert(pstate->m_shortcharhasidx < 0);
                        return &(poptions[i]);
                    }
                }
                j --;
            }
        }

        if (shortprefix != NULL && STRNCMP(argv[oldidx], shortprefix, shortlen) == 0 && strlen(argv[oldidx]) == (shortlen + 1)) {
            oldcharidx = (int)shortlen;
            j = pstate->m_cmdnum - 1;
            EXTARGS_DEBUG("search for [%d][%d] %c (%s)", oldidx, oldcharidx, argv[oldidx][oldcharidx], argv[oldidx]);
            pcmdstate = pstate->m_cmdstates;
            while (1) {
                if (pcmdstate == NULL || j < 0) {
                    break;
                }
                poptions = pcmdstate[j]->m_opthelp;
                assert(poptions != NULL);
                for (i = 0; poptions[i].m_longopt != NULL ; i ++) {
                    if (poptions[i].m_shortopt != '\0') {
                        EXTARGS_DEBUG("[%d] shortopt [%c] argv[%d][%d] [%c]", i, poptions[i].m_shortopt, oldidx, oldcharidx, argv[oldidx][oldcharidx]);
                        if (poptions[i].m_shortopt == argv[oldidx][oldcharidx]) {
                            assert(pstate->m_shortcharhasidx < 0);
                            assert(pstate->m_longopthasidx < 0);
                            pstate->m_keyidx = oldidx;
                            oldidx ++;
                            pstate->m_curidx = oldidx;
                            pstate->m_curcharidx = -1;
                            pstate->m_validx = oldidx;
                            EXTARGS_DEBUG("get options (%s)", poptions[i].m_longopt);
                            return &(poptions[i]);
                        }
                    }
                }
                j --;
            }
        }

        if (longprefix && STRNCMP(argv[oldidx],longprefix,longlen) == 0) {
            pstate->m_curidx = oldidx;
            pstate->m_validx = -1;
            pstate->m_keyidx = -1;
            pstate->m_curcharidx = -1;
            pstate->m_longopthasidx = -1;
            pstate->m_shortcharhasidx = -1;
            if (error){
                *error = EXTARGS_NO_OPTS;
            }
            return NULL;
        }
    }
    /*that is like subnargs or args or sub command*/
    if (error) {
        *error = 0;    
    }    
    pstate->m_curidx = oldidx;
    pstate->m_validx = -1;
    pstate->m_keyidx = -1;
    pstate->m_curcharidx = -1;
    pstate->m_longopthasidx = -1;
    pstate->m_shortcharhasidx = -1;
    return NULL;
}


int get_opt_name(popt_help_t popthelp, char** ppname, int *pnamesize)
{
    int ret = 0;
    if (popthelp) {
        if (popthelp->m_longopt) {
            if (st_extargs_inner_state.m_options.m_longprefix != NULL) {
                ret = snprintf_safe(ppname, pnamesize, "%s%s", st_extargs_inner_state.m_options.m_longprefix , popthelp->m_longopt);
            } else {
                ret = snprintf_safe(ppname,pnamesize,"%s%s",EXTARGS_DEFAULT_LONGPREFIX,popthelp->m_longopt);
            }
            if (ret >= 0 && popthelp->m_shortopt != 0x0) {
                if (st_extargs_inner_state.m_options.m_shortprefix != NULL) {
                    ret = append_snprintf_safe(ppname, pnamesize, "|%s%c" , st_extargs_inner_state.m_options.m_shortprefix,popthelp->m_shortopt);
                } else {
                    ret = append_snprintf_safe(ppname,pnamesize,"|%s%c",EXTARGS_DEFAULT_SHORTPREFIX,popthelp->m_shortopt);
                }
            }
        } else {
            snprintf_safe(ppname, pnamesize, NULL);
        }

    } else {
        snprintf_safe(ppname, pnamesize, NULL);
    }
    return ret;
}

int get_opt_argname(popt_help_t popthelp, char** ppargname, int *pargnamesize)
{
    int ret = 0;
    if (popthelp) {
        if (popthelp->m_longopt) {
            if (popthelp->m_argname) {
                ret = snprintf_safe(ppargname, pargnamesize, "%s", popthelp->m_argname);
            } else {
                ret = snprintf_safe(ppargname, pargnamesize, "");
            }
        } else {
            snprintf_safe(ppargname, pargnamesize, NULL);
        }
    } else {
        snprintf_safe(ppargname, pargnamesize, NULL);
    }
    return ret;
}

int get_opt_helpinfo(popt_help_t popthelp, char** pphelpinfo, int* phelpsize)
{
    int ret = 0;
    char* ptr;
    char** pptr;
    int i;
    float *pfltptr;
    char* prethelp=NULL;
    if (popthelp) {
        if (popthelp->m_longopt) {
            if (popthelp->m_optsize > OPTION_OFFSET(opt_help_t,m_helpfunc) && popthelp->m_helpfunc != NULL) {
                prethelp = popthelp->m_helpfunc(popthelp);
                if (prethelp != NULL) {
                    ret = snprintf_safe(pphelpinfo,phelpsize,"%s",prethelp);
                } else {
                    ret = -EXTARGS_INVAL_RETURN;
                }
            } else if (popthelp->m_helpinfo) {
                ret = snprintf_safe(pphelpinfo, phelpsize, "%s", popthelp->m_helpinfo);
            } else {
                if (popthelp->m_opttype != OPT_ARG_TYPE &&
                        popthelp->m_opttype != OPT_CMD_TYPE &&
                        popthelp->m_opttype != OPT_HELP_TYPE &&
                        popthelp->m_opttype != OPT_JSONFILE_TYPE) {
                    ret = snprintf_safe(pphelpinfo, phelpsize, "set %s ", popthelp->m_longopt);
                    if (ret >= 0) {
                        switch (popthelp->m_opttype) {
                        case OPT_TRUE_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(false)");
                            break;
                        case OPT_FALSE_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(true)");
                            break;
                        case OPT_STRING_TYPE:
                            ptr = (char*) ((uintptr_t)popthelp->m_defvalue);
                            if (ptr == NULL) {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(NULL)");
                            } else {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(%s)", ptr);
                            }
                            break;
                        case OPT_LIST_TYPE:
                            pptr = (char**)((uintptr_t)popthelp->m_defvalue);
                            if (pptr != NULL) {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default([");
                                for (i = 0;; i++) {
                                    if (pptr[i] == NULL || ret < 0) {
                                        break;
                                    }
                                    if (i > 0) {
                                        ret = append_snprintf_safe(pphelpinfo, phelpsize, ",");
                                    }
                                    if (ret >= 0) {
                                        ret = append_snprintf_safe(pphelpinfo, phelpsize, "%s", pptr[i]);
                                    }
                                }
                                if (ret >= 0) {
                                    ret = append_snprintf_safe(pphelpinfo, phelpsize, "])");
                                }
                            } else {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default([])");
                            }
                            break;
                        case OPT_INC_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(0)");
                            break;
                        case OPT_DICT_TYPE:
                            ret = -EXTARGS_INVAL_PARAM;
                            break;
                        case OPT_INT_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(%d)", (int)popthelp->m_defvalue);
                            break;
                        case OPT_DOUBLE_TYPE:
                            pfltptr = (float*)((uintptr_t)popthelp->m_defvalue);
                            if (pfltptr != NULL) {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(%f)", (float) * pfltptr);
                            } else {
                                ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(0.0)");
                            }
                            break;
                        case OPT_LL_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(%lld)", (long long)popthelp->m_defvalue);
                            break;
                        case OPT_ULL_TYPE:
                            ret = append_snprintf_safe(pphelpinfo, phelpsize, "default(%lld)", (unsigned long long)popthelp->m_defvalue);
                            break;
                        default:
                            EXTARGS_ERROR("unrecognize optype %d", popthelp->m_opttype);
                            ret = -EXTARGS_INVAL_PARAM;
                            break;
                        }
                    }
                } else if (popthelp->m_opttype == OPT_ARG_TYPE) {
                    ret = snprintf_safe(pphelpinfo, phelpsize, "");
                } else if (popthelp->m_opttype == OPT_CMD_TYPE) {
                    ret = -EXTARGS_INVAL_PARAM;
                } else if (popthelp->m_opttype == OPT_HELP_TYPE) {
                    ret = snprintf_safe(pphelpinfo, phelpsize, "to display this help information");
                } else if (popthelp->m_opttype == OPT_JSONFILE_TYPE) {
                    ret = snprintf_safe(pphelpinfo, phelpsize, "to specify json for set args");
                }
            }
        } else {
            snprintf_safe(pphelpinfo, phelpsize, NULL);
        }
    } else {
        snprintf_safe(pphelpinfo, phelpsize, NULL);
    }

    if (prethelp != NULL) {
        free(prethelp);
    }
    prethelp = NULL;
    return ret;
}


int calc_opt_size(popt_help_t popthelp, int *pmaxnamesize, int *pmaxargsize, int *pmaxhelpsize)
{
    int maxnamesize = *pmaxnamesize;
    int maxargsize = *pmaxargsize;
    int maxhelpsize = *pmaxhelpsize;
    char* pdummystr = NULL;
    int dummysize = 0;
    int ret = 0;
    int i, clen;
    popt_help_t pcurhelp;

    if (popthelp == NULL) {
        ret = 0;
        goto out;
    }

    for (i = 0; popthelp[i].m_longopt != NULL; i++) {
        if (pdummystr != NULL) {
            memset(pdummystr, 0, dummysize);
        }
        pcurhelp = &(popthelp[i]);

        if (pcurhelp->m_opttype == OPT_ARG_TYPE) {
            continue;
        }

        ret = get_opt_name(pcurhelp, &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int) strlen(pdummystr);
        if (clen >= maxnamesize) {
            maxnamesize = (clen + 1);
        }

        ret = get_opt_argname(pcurhelp, &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int) strlen(pdummystr);
        if (clen >= maxargsize) {
            maxargsize = (clen + 1);
        }

        ret = get_opt_helpinfo(pcurhelp, &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int)strlen(pdummystr);
        if (clen >= maxhelpsize) {
            maxhelpsize = (clen + 1);
        }
    }

    ret = i;
    *pmaxnamesize = maxnamesize;
    *pmaxargsize = maxargsize;
    *pmaxhelpsize = maxhelpsize;
out:
    snprintf_safe(&pdummystr, &dummysize, NULL);
    return ret;
}

int get_cmd_name(popt_cmd_t pcmd, char** ppcmd, int *pcmdsize)
{
    int ret = 0;
    if (pcmd) {
        if (pcmd->m_cmd) {
            ret = snprintf_safe(ppcmd, pcmdsize, "[%s]", pcmd->m_cmd);
        } else {
            snprintf_safe(ppcmd, pcmdsize, NULL);
        }
    } else {
        snprintf_safe(ppcmd, pcmdsize, NULL);
    }
    return ret;
}

int get_cmd_expr(popt_cmd_t pcmd, char** ppexpr, int *pexprsize)
{
    int ret = 0;
    if (pcmd) {
        if (pcmd->m_cmdepxr) {
            ret = snprintf_safe(ppexpr, pexprsize, "%s", pcmd->m_cmdepxr);
        } else if (pcmd->m_cmd != NULL) {
            ret = snprintf_safe(ppexpr, pexprsize, "");
        } else {
            snprintf_safe(ppexpr, pexprsize, NULL);
        }
    } else {
        snprintf_safe(ppexpr, pexprsize, NULL);
    }
    return ret;
}

int get_cmd_help(popt_cmd_t pcmd, char** ppcmdhelp, int* pcmdhelpsize)
{
    int ret = 0;
    if (pcmd) {
        if (pcmd->m_cmdhelp) {
            ret = snprintf_safe(ppcmdhelp, pcmdhelpsize, "%s", pcmd->m_cmdhelp);
        } else if (pcmd->m_cmd != NULL) {
            ret = snprintf_safe(ppcmdhelp, pcmdhelpsize, "%s handler", pcmd->m_cmd);
        } else {
            snprintf_safe(ppcmdhelp, pcmdhelpsize, NULL);
        }
    } else {
        snprintf_safe(ppcmdhelp, pcmdhelpsize, NULL);
    }
    return ret;
}

int calc_cmd_size(popt_cmd_t pcmd[], int *pmaxname, int* pmaxexpr, int*pmaxhelp)
{
    int maxname = *pmaxname;
    int maxexpr = *pmaxexpr;
    int maxhelp = *pmaxhelp;
    char* pdummystr = NULL;
    int dummysize = 0;
    int ret = 0;
    int i, clen;

    if (pcmd == NULL) {
        ret = 0;
        goto out;
    }

    for (i = 0;; i++) {
        EXTARGS_DEBUG("[%d] %p", i, pcmd[i]);
        if (pcmd[i] == NULL) {
            break;
        }

        ret = get_cmd_name(pcmd[i], &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int)strlen(pdummystr);
        if (clen >= maxname) {
            maxname = (clen + 1);
        }

        ret = get_cmd_expr(pcmd[i], &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int)strlen(pdummystr);
        if (clen >= maxexpr) {
            maxexpr = (clen + 1);
        }

        ret = get_cmd_help(pcmd[i], &pdummystr, &dummysize);
        if (ret < 0) {
            goto out;
        }
        clen = (int)strlen(pdummystr);
        if (clen >= maxhelp) {
            maxhelp = (clen + 1);
        }
    }


    ret = i;
    EXTARGS_DEBUG("ret %d", ret);
    *pmaxname = maxname;
    *pmaxexpr = maxexpr;
    *pmaxhelp = maxhelp;
out:
    snprintf_safe(&pdummystr, &dummysize, NULL);
    return ret;
}

popt_cmd_t find_cmd(popt_cmd_t pmaincmd, const char* subcmd)
{
    popt_cmd_t pcurcmd = NULL;
    popt_cmd_t pfindcmd = NULL;
    int i;
    char* firstname = NULL;
    int firstnamesize = 0;
    char* pdotchar = NULL;

    if (subcmd == NULL || strlen(subcmd) == 0) {
        pfindcmd = pmaincmd;
        goto out;
    }
    if (pmaincmd == NULL) {
        goto out;
    }

    pdotchar = strchr(subcmd, '.');
    if (pdotchar != NULL) {
        if (pmaincmd->m_subcmds != NULL) {
            firstnamesize = (int) ((uintptr_t)pdotchar - (uintptr_t)subcmd + 1);
            firstname = (char*) malloc(firstnamesize);
            if (firstname == NULL) {
                EXTARGS_ERROR("can not alloc %d", firstnamesize);
                goto out;
            }
            memset(firstname, 0, firstnamesize);
            memcpy(firstname, subcmd, firstnamesize - 1);
            /*to skip for the char*/
            pdotchar ++;
            for (i = 0;; i++) {
                pcurcmd = pmaincmd->m_subcmds[i];
                if (pcurcmd->m_cmd == NULL) {
                    break;
                }

                if (strcmp(pcurcmd->m_cmd, firstname) == 0) {
                    pfindcmd = find_cmd(pcurcmd, pdotchar);
                    if (pfindcmd != NULL) {
                        break;
                    }
                }
            }
        }

    } else {
        if (pmaincmd->m_subcmds != NULL) {
            for (i = 0;; i++) {
                pcurcmd = pmaincmd->m_subcmds[i];
                if (pcurcmd->m_cmd == NULL) {
                    break;
                }
                if (strcmp(pcurcmd->m_cmd, subcmd) == 0) {
                    pfindcmd = pcurcmd;
                    break;
                }
            }
        }
    }

out:
    if (firstname) {
        free(firstname);
    }
    firstname = NULL;
    firstnamesize = 0;
    return pfindcmd;
}

#define APPEND_STRING(...)   \
    do {\
        ret = append_snprintf_safe(&poutbuffer,&outbuffersize,__VA_ARGS__); \
        if (ret < 0) {\
         ret = -EXTARGS_NO_MEM; goto fail;\
        }\
    } while(0)

#define APPEND_SPACE(indent)  \
    do{\
        int curi=0;\
        for (curi=0;curi<(indent);curi ++) {\
            if (dsti >= (retsize-1)) {\
                retsize <<= 1;\
                goto try_again;\
            }\
            *pcurdst = ' ';\
            pcurdst ++;\
            dsti ++;\
            curdstwidth ++;\
        }\
    }while(0)


#define APPEND_CHAR(ch)  \
    do {\
        if (dsti >= (retsize-1)) {\
            retsize <<= 1;\
            goto try_again;\
        }\
        *pcurdst = ch;\
        dsti ++;\
        pcurdst ++;\
        curdstwidth ++;\
        if (ch == '\n') { \
            curdstwidth = 0;\
        }\
    }while(0)


char* format_indent_string(char* pstring, int preindent, int maxwidth)
{
    char* pretstr = NULL;
    int retsize = maxwidth;
    char* pcursrc = NULL;
    char* pcurdst = NULL;
    int dsti, srci;
    int curdstwidth;

try_again:
    if (pretstr) {
        free(pretstr);
    }
    pretstr = NULL;
    pretstr = malloc(retsize);
    if (pretstr == NULL) {
        goto fail;
    }
    memset(pretstr, 0, retsize);

    dsti = 0;
    srci = 0;
    pcursrc = pstring;
    pcurdst = pretstr;
    curdstwidth = 0;
    APPEND_SPACE(preindent);

    while (*pcursrc != '\0') {
        if (*pcursrc == ' ' ||
                *pcursrc == '\t') {
            if (curdstwidth >= maxwidth) {
                APPEND_CHAR('\n');
                pcursrc ++;
                srci ++;
                APPEND_SPACE(preindent);
                continue;
            }
        }
        APPEND_CHAR(*pcursrc);
        pcursrc ++ ;
        srci ++;
    }
    /*at the end of string */
    APPEND_CHAR('\n');
    return pretstr;
fail:
    if (pretstr) {
        free(pretstr);
    }
    pretstr = NULL;
    return NULL;
}

char* __help_usagev(const char* arg0, const char* subcmd , popt_cmd_t pmaincmd, const char* fmt, va_list ap)
{
    int i;
    char* poptname = NULL;
    int optnamesize = 0;
    char* poptargname = NULL;
    int optargnamesize = 0;
    char* popthelp = NULL;
    int opthelpsize = 0;
    char* pcmdname = NULL;
    int cmdnamesize = 0;
    char* pcmdexpr = NULL;
    int cmdexprsize = 0;
    char* pcmdhelp = NULL;
    int cmdhelpsize = 0;
    int maxcmdnamelen = 0;
    int maxcmdexprlen = 0;
    int maxcmdhelplen = 0;
    int maxoptnamelen = 0;
    int maxopthelplen = 0;
    int maxoptarglen = 0;
    char* poutbuffer = NULL;
    int outbuffersize = 0;
    int ret;
    int curopthelplen = 0;
    popt_cmd_t phelpcmd = NULL, pcursubcmd;
    popt_help_t popts, pcuropt;
    char* pindentstr = NULL;
    int preindent;

    if (st_extargs_inner_state.m_options.m_nohelp != 0) {
        /*we delete help information*/
        ret = append_snprintf_safe(&poutbuffer, &outbuffersize, "no help output\n");
        if (ret < 0) {
            ret = -EXTARGS_NO_MEM;
            goto fail;
        }
        goto out;
    }

    if (fmt != NULL) {
        ret = append_vsnprintf_safe(&poutbuffer, &outbuffersize, fmt, ap);
        if (ret < 0) {
            ret = -EXTARGS_NO_MEM;
            goto fail;
        }
        APPEND_STRING("\n");
    }

    phelpcmd = find_cmd(pmaincmd, subcmd);
    if (phelpcmd == NULL) {
        APPEND_STRING("can not find (%s) command help\n", subcmd ? subcmd : "NULL");
        goto out;
    }

    maxoptnamelen = 1;
    maxopthelplen = 1;
    maxoptarglen = 1;
    if (phelpcmd->m_cmdopts != NULL) {
        ret = calc_opt_size(phelpcmd->m_cmdopts, &maxoptnamelen, &maxoptarglen, &maxopthelplen);
        if (ret < 0) {
            goto fail;
        }
    }

    maxcmdnamelen = 1;
    maxcmdexprlen = 1;
    maxcmdhelplen = 1;
    if (phelpcmd->m_subcmds != NULL) {
        ret = calc_cmd_size(phelpcmd->m_subcmds, &maxcmdnamelen, &maxcmdexprlen, &maxcmdhelplen);
        if (ret < 0) {
            goto fail;
        }
    }

    if (phelpcmd == pmaincmd) {
        APPEND_STRING("%s [OPTIONS]", arg0);
        if (phelpcmd->m_subcmds != NULL) {
            APPEND_STRING(" [SUBCOMMANDS] ...\n");
        } else {
            APPEND_STRING(" ...\n");
        }
    } else {

        APPEND_STRING("%s  %s", arg0, subcmd);
        if (phelpcmd->m_cmdhelp != NULL) {
            APPEND_STRING(" %s\n", phelpcmd->m_cmdhelp);
        } else {
            if (phelpcmd->m_subcmds != NULL) {
                APPEND_STRING(" [SUBCOMMANDS] ...\n");
            } else {
                APPEND_STRING(" ...\n");
            }            
        }
    }


    if (phelpcmd->m_cmdopts != NULL) {
        popts = phelpcmd->m_cmdopts;
        APPEND_STRING("[OPTIONS]\n");
        for (i = 0; ; i ++) {
            if (popts[i].m_longopt == NULL) {
                break;
            }
            pcuropt = &(popts[i]);
            if (pcuropt->m_opttype == OPT_ARG_TYPE) {
                continue;
            }
            ret = get_opt_name(pcuropt, &poptname, &optnamesize);
            if (ret < 0) {
                goto fail;
            }

            ret = get_opt_argname(pcuropt, &poptargname, &optargnamesize);
            if (ret < 0) {
                goto fail;
            }
            ret = get_opt_helpinfo(pcuropt, &popthelp, &opthelpsize);
            if (ret < 0) {
                goto fail;
            }

            curopthelplen = (int)strlen(popthelp);
            if ((maxoptnamelen + maxoptarglen + curopthelplen + 2) > st_extargs_inner_state.m_options.m_screenwidth) {
                APPEND_STRING("\t%-*s %-*s\n", maxoptnamelen, poptname, maxoptarglen, poptargname);
                if (pindentstr) {
                    free(pindentstr);
                }
                pindentstr = NULL;
                preindent = st_extargs_inner_state.m_options.m_screenwidth / 3;
                pindentstr = format_indent_string(popthelp, preindent, st_extargs_inner_state.m_options.m_screenwidth);
                if (pindentstr == NULL) {
                    goto fail;
                }
                APPEND_STRING("%s", pindentstr);
                free(pindentstr);
                pindentstr = NULL;
            } else {
                APPEND_STRING("\t%-*s %-*s %s\n", maxoptnamelen, poptname, maxoptarglen, poptargname, popthelp);
            }

        }
        APPEND_STRING("\n");
    }


    if (phelpcmd->m_subcmds != NULL) {
        APPEND_STRING("[SUBCOMMAND]\n");
        for (i = 0;; i++) {
            if (phelpcmd->m_subcmds[i] == NULL) {
                break;
            }
            pcursubcmd = phelpcmd->m_subcmds[i];
            ret = get_cmd_name(pcursubcmd, &pcmdname, &cmdnamesize);
            if (ret < 0) {
                goto fail;
            }
            ret = get_cmd_expr(pcursubcmd, &pcmdexpr, &cmdexprsize);
            if (ret < 0) {
                goto fail;
            }
            ret = get_cmd_help(pcursubcmd, &pcmdhelp, &cmdhelpsize);
            if (ret < 0) {
                goto fail;
            }
            curopthelplen = (int) strlen(pcmdhelp);
            if ((maxcmdnamelen + maxcmdexprlen + curopthelplen + 2) > st_extargs_inner_state.m_options.m_screenwidth) {
                APPEND_STRING("\t%-*s %-*s\n", maxcmdnamelen, pcmdname, maxcmdexprlen, pcmdexpr);
                if (pindentstr != NULL) {
                    free(pindentstr);
                }
                pindentstr = NULL;
                preindent = st_extargs_inner_state.m_options.m_screenwidth / 3;
                pindentstr = format_indent_string(pcmdhelp, preindent, st_extargs_inner_state.m_options.m_screenwidth);
                if (pindentstr == NULL) {
                    goto fail;
                }
                APPEND_STRING("%s", pindentstr);
                free(pindentstr);
                pindentstr = NULL;
            } else {
                APPEND_STRING("\t%-*s %-*s %s\n", maxcmdnamelen, pcmdname, maxcmdexprlen, pcmdexpr, pcmdhelp);
            }
        }
        APPEND_STRING("\n");
    }

out:
    snprintf_safe(&popthelp, &opthelpsize, NULL);
    snprintf_safe(&poptname, &optnamesize, NULL);
    snprintf_safe(&poptargname, &optargnamesize, NULL);
    snprintf_safe(&pcmdname, &cmdnamesize, NULL);
    snprintf_safe(&pcmdexpr, &cmdexprsize, NULL);
    snprintf_safe(&pcmdhelp, &cmdhelpsize, NULL);
    if (pindentstr != NULL) {
        free(pindentstr);
    }
    pindentstr = NULL;
    return poutbuffer;
fail:
    snprintf_safe(&popthelp, &opthelpsize, NULL);
    snprintf_safe(&poptname, &optnamesize, NULL);
    snprintf_safe(&poptargname, &optargnamesize, NULL);
    snprintf_safe(&pcmdname, &cmdnamesize, NULL);
    snprintf_safe(&pcmdexpr, &cmdexprsize, NULL);
    snprintf_safe(&pcmdhelp, &cmdhelpsize, NULL);
    if (pindentstr != NULL) {
        free(pindentstr);
    }
    pindentstr = NULL;

    /*free buffer out*/
    snprintf_safe(&poutbuffer, &outbuffersize, NULL);
    return NULL;
}

char* help_usagev(const char* arg0, const char* subcmd, popt_cmd_t pmaincmd,  const char* fmt, va_list ap)
{
    return __help_usagev(arg0, subcmd, pmaincmd , fmt, ap);
}

char* help_usage(const char* arg0, const char* subcmd, popt_cmd_t pmaincmd, const char* fmt, ...)
{
#ifdef __EXTARGS_WIN__
    va_list ap = NULL;
#else
    va_list ap;
#endif
    if (fmt == NULL) {
        va_start(ap, fmt);
    }
    return help_usagev(arg0, subcmd, pmaincmd, fmt, ap);
}

void default_help_functionv(const char* arg0, const char* subcmd, int ec, popt_cmd_t pmaincmd,  const char* fmt, va_list ap)
{
    char* usage = NULL;
    FILE* fp = stderr;
    int ret;

    if (ec == 0) {
        fp = stdout;
    }
    usage = help_usagev(arg0, subcmd, pmaincmd, fmt, ap);
    if (usage == NULL) {
        ret = -EXTARGS_NO_MEM;
        fprintf(fp, "can not format usage error(%d)\n", ret);
    } else {
        fprintf(fp, "%s", usage);
    }

    if (usage) {
        free(usage);
    }
    exit(ec);
    return;
}

void default_help_function(const char* arg0, const char* subcmd, int ec, popt_cmd_t pmaincmd,  const char* fmt, ...)
{
#ifdef __EXTARGS_WIN__
    va_list ap = NULL;
#else
    va_list ap;
#endif
    if (fmt != NULL) {
        va_start(ap, fmt);
    }
    default_help_functionv(arg0, subcmd, ec, pmaincmd, fmt, ap);
    return;
}

int expand_opts_array(pparse_state_t pstate, popt_cmd_t addcmd)
{
    int ret = 0;
    int cmdsize = pstate->m_cmdsize;
    int cmdnum = pstate->m_cmdnum;
    pparse_cmd_state_t pcmdstate = NULL;
    pparse_cmd_state_t* pcmdstates = pstate->m_cmdstates;
    if (pcmdstates == NULL || cmdsize == 0 || cmdsize <= (cmdnum + 1)) {
        if (cmdsize == 0) {
            cmdsize = 4;
        } else {
            cmdsize <<= 1;
        }
        pcmdstates = (pparse_cmd_state_t*) malloc(sizeof(*pcmdstates) * cmdsize);
        if (pcmdstates == NULL) {
            ret = -EXTARGS_NO_MEM;
            goto fail;
        }
        memset(pcmdstates, 0, sizeof(*pcmdstates)*cmdsize);
        if (cmdnum > 0) {
            memcpy(pcmdstates, pstate->m_cmdstates, cmdnum * sizeof(*pcmdstates));
        }
        ret = 1;
    }
    pcmdstate = alloc_parse_cmd_state(addcmd);
    if (pcmdstate == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    pcmdstates[cmdnum] = pcmdstate;
    cmdnum ++;
    pstate->m_cmdsize = cmdsize;
    pstate->m_cmdnum = cmdnum;
    if (pstate->m_cmdstates && pstate->m_cmdstates != pcmdstates) {
        free(pstate->m_cmdstates);
    }
    pstate->m_cmdstates = pcmdstates;
    return ret;
fail:
    if (pcmdstate != NULL) {
        free(pcmdstate);
    }
    pcmdstate = NULL;
    if (pcmdstates != NULL && pcmdstates != pstate->m_cmdstates) {
        free(pcmdstates);
    }
    pcmdstates = NULL;
    return ret;
}

char* get_command_subcommand_name(pparse_state_t pstate)
{
    char* poutbuffer = NULL;
    int outbuffersize = 0;
    int ret;
    int i;

    /*we make sure the less*/
    ret = snprintf_safe(&poutbuffer, &outbuffersize, "");
    if (ret < 0) {
        ret =  -EXTARGS_NO_MEM;
        goto fail;
    }

    if (pstate->m_cmdnum > 1) {
        for (i = 1; i < pstate->m_cmdnum; i++) {
            if (ret > 1)    {
                ret = append_snprintf_safe(&poutbuffer, &outbuffersize, ".");
                if (ret < 0) {
                    ret = -EXTARGS_NO_MEM;
                    goto fail;
                }
            }
            ret = append_snprintf_safe(&poutbuffer, &outbuffersize, "%s", pstate->m_cmdstates[i]->m_optcmd->m_cmd);
            if (ret < 0) {
                ret = -EXTARGS_NO_MEM;
                goto fail;
            }
        }
    }

    return poutbuffer;
fail:
    snprintf_safe(&poutbuffer, &outbuffersize, NULL);
    return NULL;
}

pparse_cmd_state_t find_cmd_state_by_opt_inner(pparse_cmd_state_t* ppstates, popt_help_t pgethelp)
{
    popt_cmd_t pcurcmd = NULL;
    int i, j;
    popt_help_t pcurhelp = NULL;
    pparse_cmd_state_t pfindstate = NULL;

    if (ppstates != NULL) {
        for (i = 0;; i++) {
            if (ppstates[i] == NULL) {
                break;
            }
            pcurcmd = ppstates[i]->m_optcmd;
            if (pcurcmd->m_cmdopts) {
                for (j = 0;; j++) {
                    pcurhelp = &(pcurcmd->m_cmdopts[j]);
                    if (pcurhelp->m_longopt == NULL) {
                        break;
                    }
                    if (pcurhelp == pgethelp) {
                        pfindstate = (ppstates[i]);
                        return pfindstate;
                    }
                }
            }
        }
    }
    return pfindstate;
}


pparse_cmd_state_t find_cmd_state_by_opt(pparse_state_t pstate, popt_help_t pgethelp)
{
    return find_cmd_state_by_opt_inner(pstate->m_cmdstates, pgethelp);
}

popt_cmd_t check_help_cmd_inner(popt_cmd_t pmaincmd, popt_help_t pgethelp)
{
    int i;
    popt_cmd_t pcurcmd = NULL, pfindcmd = NULL;
    if (pmaincmd->m_subcmds != NULL) {
        for (i = 0;; i++) {
            if (pmaincmd->m_subcmds[i] == NULL) {
                break;
            }
            pcurcmd = pmaincmd->m_subcmds[i];
            pfindcmd = check_help_cmd_inner(pcurcmd, pgethelp);
            if (pfindcmd != NULL) {
                return pfindcmd;
            }
        }
    }

    for (i = 0;; i++) {
        if (pmaincmd->m_cmdopts[i].m_longopt == NULL) {
            break;
        }
        if ((&(pmaincmd->m_cmdopts[i])) == pgethelp) {
            return pmaincmd;
        }
    }
    return NULL;
}

pparse_cmd_state_t find_dummy_state_by_opt_by_add(pparse_state_t pstate, popt_help_t pgethelp)
{
    pparse_cmd_state_t pfindstate = NULL;
    pparse_cmd_state_t* ptmpdummy = NULL;
    popt_cmd_t pfindcmd = NULL;
    pparse_cmd_state_t pstatedummy = NULL;
    int newsize = 4;


    pfindstate = find_cmd_state_by_opt_inner(pstate->m_dummystates, pgethelp);
    if (pfindstate != NULL) {
        return pfindstate;
    }

    pfindcmd = check_help_cmd_inner(pstate->m_cmdstates[0]->m_optcmd, pgethelp);
    if (pfindcmd == NULL) {
        return NULL;
    }

    pstatedummy = malloc(sizeof(*pstatedummy));
    if (pstatedummy == NULL) {
        goto fail;
    }

    memset(pstatedummy, 0, sizeof(*pstatedummy));
    pstatedummy->m_optcmd = pfindcmd;

    if (pstate->m_dummysize <= pstate->m_dummynum) {
        newsize = pstate->m_dummysize << 1;
        if (newsize <= 0) {
            newsize = 4;
        }
        ptmpdummy = malloc(sizeof(*ptmpdummy) * newsize);
        if (ptmpdummy == NULL) {
            goto fail;
        }
        memset(ptmpdummy, 0, sizeof(ptmpdummy[0]) * newsize);
        if (pstate->m_dummynum > 0) {
            memcpy(ptmpdummy, pstate->m_dummystates, sizeof(*ptmpdummy)*pstate->m_dummynum);
        }
        if (pstate->m_dummystates) {
            free(pstate->m_dummystates);
        }
        pstate->m_dummystates = ptmpdummy;
        ptmpdummy = NULL;
        pstate->m_dummysize = newsize;
    }

    pstate->m_dummystates[pstate->m_dummynum] = pstatedummy;
    pstate->m_dummynum ++;
    return pstatedummy;
fail:

    if (pstatedummy) {
        free(pstatedummy);
    }
    pstatedummy = NULL;
    return NULL;
}

int add_jsonfile_value(pparse_state_t pstate, popt_help_t pgethelp, char* jsonname)
{
    pparse_cmd_state_t pfindstate = NULL;
    char* pdup = NULL;

    pfindstate = find_cmd_state_by_opt(pstate, pgethelp);
    if (pfindstate != NULL) {
        /*now first to find out the get help*/
        pdup = safe_strdup(jsonname);
        if (pdup == NULL) {
            return -EXTARGS_NO_MEM;
        }
        if (pfindstate->m_jsonfile != NULL) {
            free(pfindstate->m_jsonfile);
        }
        pfindstate->m_jsonfile = pdup;
        return 1;
    }

    pfindstate = find_dummy_state_by_opt_by_add(pstate, pgethelp);
    if (pfindstate != NULL) {
        /*now first to find out the get help*/
        pdup = safe_strdup(jsonname);
        if (pdup == NULL) {
            return -EXTARGS_NO_MEM;
        }
        if (pfindstate->m_jsonfile != NULL) {
            free(pfindstate->m_jsonfile);
        }
        pfindstate->m_jsonfile = pdup;
        return 1;
    }

    return -EXTARGS_NO_OPTS;
}

int init_parse_state(pparse_state_t pstate)
{
    memset(pstate, 0, sizeof(*pstate));
    pstate->m_curidx = 1;
    pstate->m_curcharidx = -1;
    pstate->m_keyidx = -1;
    pstate->m_validx = -1;
    pstate->m_shortcharhasidx = -1;
    pstate->m_longopthasidx = -1;
    pstate->m_ended = 0;
    pstate->m_priorities = NULL;
    pstate->m_cmdstates = NULL;
    pstate->m_cmdsize = 0;
    pstate->m_cmdnum = 0;
    pstate->m_dummystates = NULL;
    pstate->m_dummysize = 0;
    pstate->m_dummynum = 0;
    pstate->m_poptsetmap = NULL;
    pstate->m_leftargs = NULL;
    return 0;
}


void deinitialize_state(pparse_state_t pstate)
{
    int i;
    EXTARGS_DEBUG("m_leftargs [%p]",pstate->m_leftargs);
    if (pstate->m_leftargs != NULL) {
        for (i = 0; ; i++) {
            if (pstate->m_leftargs[i] == NULL) {
                break;
            }
            EXTARGS_DEBUG("[%d]free (%s) [%p]",i,pstate->m_leftargs[i],pstate->m_leftargs[i]);
            free(pstate->m_leftargs[i]);
            pstate->m_leftargs[i] = NULL;
        }
        free(pstate->m_leftargs);
    }
    pstate->m_leftargs = NULL;

    free_extargs_hashmap(&(pstate->m_poptsetmap));
    if (pstate->m_cmdstates != NULL) {
        for (i = 0; i < pstate->m_cmdsize; i++) {
            dealloc_parse_cmd_state(&(pstate->m_cmdstates[i]));
        }
        free(pstate->m_cmdstates);
    }

    if (pstate->m_dummystates != NULL) {
        for (i = 0; i < pstate->m_dummysize; i++) {
            dealloc_parse_cmd_state(&(pstate->m_dummystates[i]));
        }
        free(pstate->m_dummystates);
    }


    if (pstate->m_priorities) {
        free(pstate->m_priorities);
    }
    pstate->m_curidx = 1;
    pstate->m_curcharidx = -1;
    pstate->m_keyidx = -1;
    pstate->m_validx = -1;
    pstate->m_shortcharhasidx = -1;
    pstate->m_longopthasidx = -1;
    pstate->m_ended = 0;
    pstate->m_priorities = NULL;
    pstate->m_cmdstates = NULL;
    pstate->m_cmdsize = 0;
    pstate->m_dummystates = NULL;
    pstate->m_dummysize = 0;
    pstate->m_dummynum = 0;
    pstate->m_cmdnum = 0;
    return;
}

int init_parse_prio(pparse_state_t pstate, int* prior)
{
    int ret = 0;
    int i, cnt;
    /*now first to check for the priority*/
    if (prior == NULL) {
        ret = -EXTARGS_INVAL_PARAM;
        goto out;
    }
    cnt = 0;
    for (i = 0;; i++, cnt++) {
        if (prior[i] == EXTARGS_PRIO_NONE) {
            break;
        }
        switch (prior[i]) {
        case EXTARGS_PRIO_SUBCMD_JSON:
        case EXTARGS_PRIO_CMD_JSON:
        case EXTARGS_PRIO_ENV_SUBCMD_JSON:
        case EXTARGS_PRIO_ENV_CMD_JSON:
        case EXTARGS_PRIO_ENV_CMD:
            break;
        default:
            EXTARGS_ERROR("[%d] prior %d", i, prior[i]);
            ret = -EXTARGS_INVAL_PARAM;
            goto out;
        }
    }
    /*for the end*/
    cnt ++;

    /*now to check for the prio*/
    if (pstate->m_priorities) {
        free(pstate->m_priorities);
    }
    pstate->m_priorities = NULL;
    pstate->m_priorities = (int*) malloc(sizeof(pstate->m_priorities[0]) * cnt);
    if (pstate->m_priorities == NULL) {
        EXTARGS_DEBUG(" ");
        ret = -EXTARGS_NO_MEM;
        goto out;
    }
    for (i = 0;; i++) {
        pstate->m_priorities[i] = prior[i];
        if (prior[i] == EXTARGS_PRIO_NONE) {
            break;
        }
    }
    ret = 0;
out:
    return ret;
}

popt_cmd_t get_setted_cmd(pparse_state_t pstate, int idx)
{
    popt_cmd_t pfindcmd = NULL;
    if (pstate->m_cmdstates != NULL) {
        if (idx < 0) {
            idx += pstate->m_cmdnum;
        }
        if ( idx >= 0 && idx < pstate->m_cmdnum) {
            pfindcmd = pstate->m_cmdstates[idx]->m_optcmd;
        }
    }
    return pfindcmd;
}

typedef struct opt_jsonfunc_array {
    int m_opttype;
    opt_jsonfunc_t m_optfunc;
} opt_jsonfunc_array_t,*popt_jsonfunc_array_t;

static opt_jsonfunc_array_t st_opt_jsonfunc_default[] = {
    {OPT_TRUE_TYPE            , (opt_jsonfunc_t) true_opt_jsonfunc},
    {OPT_FALSE_TYPE           , (opt_jsonfunc_t) false_opt_jsonfunc},
    {OPT_STRING_TYPE          , (opt_jsonfunc_t) string_opt_jsonfunc},
    {OPT_LIST_TYPE            , (opt_jsonfunc_t) list_opt_jsonfunc},
    {OPT_INC_TYPE             , (opt_jsonfunc_t) inc_opt_jsonfunc},
    {OPT_CMD_TYPE             , (opt_jsonfunc_t) cmd_opt_jsonfunc},
    {OPT_ARG_TYPE             , (opt_jsonfunc_t) arg_opt_jsonfunc},
    {OPT_DICT_TYPE            , (opt_jsonfunc_t) dict_opt_jsonfunc},
    {OPT_INT_TYPE             , (opt_jsonfunc_t) int_opt_jsonfunc},
    {OPT_DOUBLE_TYPE          , (opt_jsonfunc_t) double_opt_jsonfunc},
    {OPT_LL_TYPE              , (opt_jsonfunc_t) ll_opt_jsonfunc},
    {OPT_ULL_TYPE             , (opt_jsonfunc_t) ull_opt_jsonfunc},
    {OPT_JSONFILE_TYPE        , (opt_jsonfunc_t) jsonfile_opt_jsonfunc},
    { -1                      , (opt_jsonfunc_t) NULL}
};

opt_jsonfunc_t find_opt_jsonfunc(opt_jsonfunc_array_t array[], int type)
{
    int i;
    opt_jsonfunc_t pretfunc = NULL;
    for (i = 0;; i++) {
        if (array == NULL) {
            break;
        }
        if (array[i].m_optfunc == NULL) {
            break;
        }

        if (array[i].m_opttype == type) {
            pretfunc = array[i].m_optfunc;
            break;
        }
    }
    return pretfunc;
}

int call_jsonfunc_function(popt_help_t popthelp,void* value,void* popt)
{
    int ret = 0;
    opt_jsonfunc_t pfunc = NULL;
    void** ppdest;
    uint8_t* ptr;

    if (popthelp->m_offset >= 0 ) {
        if (popthelp->m_optsize > OPTION_OFFSET(opt_help_t,m_jsonfunc) && popthelp->m_jsonfunc != NULL) {
            pfunc = popthelp->m_jsonfunc;
        }
        if (pfunc == NULL) {
            pfunc = find_opt_jsonfunc(st_opt_jsonfunc_default, popthelp->m_opttype);
        }

        EXTARGS_DEBUG("%s function %p", popthelp->m_longopt, pfunc);
        ptr = (uint8_t*) popt;
        ptr += popthelp->m_offset;
        ppdest = (void*)&ptr;
        if (pfunc != NULL) {
            return pfunc(popthelp,value,ppdest);
        }
    }
    EXTARGS_DEBUG("%s func %p ret %d", popthelp->m_longopt, pfunc, ret);
    return ret;
}


typedef struct opt_func_array {
    int m_opttype;
    opt_func_t m_optfunc;
} opt_func_array_t, *popt_func_array_t;

static opt_func_array_t st_opt_func_default[] = {
    {OPT_TRUE_TYPE            , (opt_func_t) true_opt_func},
    {OPT_FALSE_TYPE           , (opt_func_t) false_opt_func},
    {OPT_STRING_TYPE          , (opt_func_t) string_opt_func},
    {OPT_LIST_TYPE            , (opt_func_t) list_opt_func},
    {OPT_INC_TYPE             , (opt_func_t) inc_opt_func},
    {OPT_CMD_TYPE             , (opt_func_t) cmd_opt_func},
    {OPT_ARG_TYPE             , (opt_func_t) arg_opt_func},
    {OPT_DICT_TYPE            , (opt_func_t) dict_opt_func},
    {OPT_INT_TYPE             , (opt_func_t) int_opt_func},
    {OPT_DOUBLE_TYPE          , (opt_func_t) double_opt_func},
    {OPT_LL_TYPE              , (opt_func_t) ll_opt_func},
    {OPT_ULL_TYPE             , (opt_func_t) ull_opt_func},
    {OPT_JSONFILE_TYPE        , (opt_func_t) jsonfile_opt_func},
    { -1                      , (opt_func_t)NULL}
};

opt_func_t find_opt_func(opt_func_array_t array[], int type)
{
    int i;
    opt_func_t pretfunc = NULL;
    for (i = 0;; i++) {
        if (array == NULL) {
            break;
        }
        if (array[i].m_optfunc == NULL) {
            break;
        }

        if (array[i].m_opttype == type) {
            pretfunc = array[i].m_optfunc;
            break;
        }
    }
    return pretfunc;
}


int call_optparse_function(int argc,char* argv[],int validx,popt_help_t pcuropt,void* popt)
{
    int ret = 0;
    opt_func_t pfunc = NULL;
    void** ppdest;
    uint8_t* ptr;

    if (pcuropt->m_offset >= 0 ) {
        pfunc = pcuropt->m_optfunc;
        if (pfunc == NULL) {
            pfunc = find_opt_func(st_opt_func_default, pcuropt->m_opttype);
        }

        EXTARGS_DEBUG("%s function %p", pcuropt->m_longopt, pfunc);
        ptr = (uint8_t*) popt;
        ptr += pcuropt->m_offset;
        ppdest = (void*)&ptr;
        if (pfunc != NULL) {
            return pfunc(argc,argv,validx,pcuropt,ppdest);
        }
    }
    EXTARGS_DEBUG("%s func %p ret %d", pcuropt->m_longopt, pfunc, ret);
    return ret;
}


int extargs_log_init(void)
{
    char* penv = NULL;
    int loglvl = EXTARGS_LOG_WARN;

    penv = GETENV("EXTARGSPARSE_LOGLEVEL");
    if (penv) {
        loglvl = atoi(penv);
    }
    st_extargs_loglevel = loglvl;
    return 0;
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


int set_jsonvalue_not_defined(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt, const char* cmdprefix, const char* key, jvalue* val)
{
    popt_cmd_t pcurcmd = NULL;
    char* pcurcmdprefix = NULL;
    int curcmdprefixsize = 0;
    int ret;
    int cnt = 0;
    popt_help_t pcuropt = NULL;
    char* valuestr = NULL;
    int valuesize = 0;
    unsigned int arraysize;
    int idx;
    jvalue* itemval;
    int error;
    int i, j;
    char* pkeyopt = NULL;
    int keyoptsize = 0;
    char** parraystr=NULL;


    if (pmaincmd == NULL) {
        ret = cnt;
        goto out;
    }

    EXTARGS_DEBUG("cmdprefix (%s)", cmdprefix);

    if (pmaincmd->m_subcmds) {
        /*now we should make sure this is the ok one*/
        for (i = 0;; i++) {
            pcurcmd = pmaincmd->m_subcmds[i];
            if (pcurcmd == NULL) {
                break;
            }

            ret = set_jsonvalue_not_defined(pcurcmd, pstate, popt, cmdprefix, key, val);
            if (ret < 0) {
                goto out;
            }
            cnt += ret;
        }
    }

    if (cmdprefix != NULL && strlen(cmdprefix) > 0) {
        ret = snprintf_safe(&pkeyopt, &keyoptsize, "%s_%s", cmdprefix, key);
    } else {
        ret = snprintf_safe(&pkeyopt, &keyoptsize, "%s", key);
    }
    if (ret < 0) {
        goto out;
    }

    extargs_str_hiphen_case(pkeyopt);
    EXTARGS_DEBUG("pkeyopt (%s)", pkeyopt);

    if (pmaincmd->m_cmdopts) {
        for (i = 0;; i++) {
            pcuropt = &(pmaincmd->m_cmdopts[i]);
            if (pcuropt->m_longopt == NULL) {
                break;
            }
            if (parraystr) {
                for (j=0;;j++) {
                    if (parraystr[j] == NULL) {
                        break;
                    }
                    free(parraystr[j]);
                    parraystr[j] = NULL;
                }
                free(parraystr);
                parraystr = NULL;
            }
            /*to set the value string*/
            snprintf_safe(&valuestr,&valuesize,NULL);
            EXTARGS_DEBUG("pkeyopt %s longopt %s", pkeyopt, pcuropt->m_longopt);
            if (strcmp(pkeyopt, pcuropt->m_longopt) == 0 ) {
                if (is_opt_setted(pstate, pcuropt) == 0) {
                    /*this is option we find ,check if setted*/
                    switch (pcuropt->m_opttype) {
                    case OPT_TRUE_TYPE:
                    case OPT_FALSE_TYPE:
                        if (val->type != JBOOL) {
                            EXTARGS_WARN("opt %s not match bool value(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            if (pcuropt->m_opttype == OPT_TRUE_TYPE) {
                                ret = snprintf_safe(&valuestr, &valuesize, "true");
                            } else {
                                ret = snprintf_safe(&valuestr, &valuesize, "false");
                            }
                            if (ret < 0) {
                                goto out;
                            }
                            ret = call_jsonfunc_function(pcuropt,valuestr,popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret >= 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_JSONFILE_TYPE:
                        if (val->type != JSTRING) {
                            EXTARGS_WARN("opt %s not match string value(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            ret = snprintf_safe(&valuestr, &valuesize, "%s", val->_string.value);
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("[%s] jsonfile(%s)",pcuropt->m_longopt, valuestr);
                            ret = add_jsonfile_value(pstate, pcuropt, valuestr);
                            if (ret < 0) {
                                EXTARGS_ERROR("add jsonfile %s error(%d)", valuestr, ret);
                                goto out;
                            }
                        }
                    /* pass throug for the jsonfile is the same sa string*/
                    case OPT_STRING_TYPE:
                        if (val->type != JSTRING && val->type != JNULL) {
                            EXTARGS_WARN("opt %s not match string value(%d)", pcuropt->m_longopt, val->type);
                        } else if (val->type == JSTRING) {
                            ret = snprintf_safe(&valuestr, &valuesize, "%s", val->_string.value);
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("%s %s", pcuropt->m_longopt, valuestr);
                            ret = call_jsonfunc_function(pcuropt,valuestr,popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret >= 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        } else if (val->type == JNULL) {
                            EXTARGS_DEBUG("%s NULL", pcuropt->m_longopt);
                            ret = call_jsonfunc_function(pcuropt,NULL,popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret >= 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_LIST_TYPE:
                        if (val->type != JARRAY) {
                            EXTARGS_WARN("opt %s not match array value(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            assert(parraystr == NULL);
                            arraysize = jarray_size(val);
                            if (arraysize > 0) {
                                parraystr = malloc(sizeof(*parraystr) * (arraysize+1));
                                if (parraystr == NULL) {
                                    ret = -EXTARGS_NO_MEM;
                                    goto out;
                                }
                                memset(parraystr,0,sizeof(*parraystr)*(arraysize+1));
                            }
                            idx = 0;
                            while (idx < (int)arraysize) {
                                assert(valuestr == NULL);
                                valuesize = 0;
                                itemval = jarray_get(val, idx, &error);
                                if (itemval == NULL) {
                                    EXTARGS_WARN("%s[%d] error(%d)", pcuropt->m_longopt, idx, error);
                                    ret = -EXTARGS_INVALID_JSON;
                                    goto out;
                                }
                                switch (itemval->type) {
                                case JSTRING:
                                    ret = snprintf_safe(&valuestr, &valuesize, "%s", itemval->_string.value);
                                    break;
                                case JINT:
                                    ret = snprintf_safe(&valuestr, &valuesize, "%d", itemval->_integer.value);
                                    break;
                                case JINT64:
                                    ret = snprintf_safe(&valuestr, &valuesize, "%lld", itemval->_integer64.value);
                                    break;
                                case JREAL:
                                    ret = snprintf_safe(&valuestr, &valuesize, "%f", itemval->_integer64.value);
                                    break;
                                default:
                                    EXTARGS_WARN("unknown item[%d] %d", idx, itemval->type);
                                    ret = snprintf_safe(&valuestr,&valuesize,"");
                                    break;
                                }
                                if (ret < 0) {
                                    goto out;
                                }
                                EXTARGS_DEBUG("[%s][%d] %s",pcuropt->m_longopt,idx, valuestr);
                                parraystr[idx] = valuestr;
                                /*we make sure this will not free again*/
                                valuestr = NULL;
                                valuesize = 0;
                                idx++;
                            }
                            ret = call_jsonfunc_function(pcuropt,parraystr,popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret >= 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_INC_TYPE:
                        if (val->type != JINT) {
                            EXTARGS_WARN("opt %s not match int value(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            ret = snprintf_safe(&valuestr,&valuesize,"%d",val->_integer.value);
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("%s %s",pcuropt->m_longopt,valuestr);
                            ret = call_jsonfunc_function(pcuropt, valuestr,popt);
                            if (ret < 0) {
                                goto out;
                            }
                            ret = insert_opt_setted(pstate, pcuropt);
                            if (ret >= 0) {
                                cnt ++;
                            }
                        }
                        break;
                    case OPT_INT_TYPE:
                        if (val->type != JINT) {
                            EXTARGS_WARN("opt %s not match int value(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            ret = snprintf_safe(&valuestr, &valuesize, "%d", val->_integer.value);
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("%s %s", pcuropt->m_longopt, valuestr);
                            ret = call_jsonfunc_function(pcuropt, valuestr,popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret >= 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_DICT_TYPE:
                        EXTARGS_WARN("%s get dict opt", pcuropt->m_longopt);
                        break;
                    case OPT_DOUBLE_TYPE:
                        if (val->type != JREAL) {
                            EXTARGS_WARN("%s not match real number(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            ret = snprintf_safe(&valuestr, &valuesize, "%f", val->_real.value);
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("%s %s", pcuropt->m_longopt, valuestr);
                            ret = call_jsonfunc_function(pcuropt, valuestr, popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret > 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_LL_TYPE:
                    case OPT_ULL_TYPE:
                        if (val->type != JINT && val->type != JINT64) {
                            EXTARGS_WARN("%s not match int or int64(%d)", pcuropt->m_longopt, val->type);
                        } else {
                            if (val->type == JINT) {
                                ret = snprintf_safe(&valuestr, &valuesize, "%d", val->_integer.value);
                            } else {
                                ret = snprintf_safe(&valuestr, &valuesize, "%lld", val->_integer64.value);
                            }
                            if (ret < 0) {
                                goto out;
                            }
                            EXTARGS_DEBUG("%s %s", pcuropt->m_longopt, valuestr);
                            ret = call_jsonfunc_function(pcuropt, valuestr, popt);
                            if (ret < 0) {
                                goto out;
                            } else if (ret > 0) {
                                ret = insert_opt_setted(pstate, pcuropt);
                                if (ret >= 0) {
                                    cnt ++;
                                }
                            }
                        }
                        break;
                    case OPT_CMD_TYPE:
                    case OPT_ARG_TYPE:
                    case OPT_HELP_TYPE:
                        /*nothing to handle*/
                        break;
                    default:
                        EXTARGS_WARN("unknown type (%s) %d", pcuropt->m_longopt, pcuropt->m_opttype);
                        break;
                    }
                } else {
                    EXTARGS_DEBUG("%s has defined", pkeyopt);
                    break;
                }
            }
        }
    }
    ret = cnt;

out:
    snprintf_safe(&valuestr, &valuesize, NULL);
    snprintf_safe(&pcurcmdprefix, &curcmdprefixsize, NULL);
    snprintf_safe(&pkeyopt, &keyoptsize, NULL);
    if (parraystr != NULL) {
        for (i=0;;i++) {
            if (parraystr[i] == NULL) {
                break;
            }
            free(parraystr[i]);
            parraystr[i] = NULL;
        }
        free(parraystr);        
    }
    parraystr = NULL;
    return ret;
}

int load_jsonvalue(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt, const char* prefix, jvalue* jsonval)
{
    jentry** entries = NULL, *pcurentry;
    unsigned int entriesizes = 0;
    int i;
    char* pcurprefix = NULL;
    int curprefixsize = 0;
    int cnt = 0;
    int ret;
    /*now we should get the entry*/
    DEBUG_JVALUE(jsonval, "enter");
    jentries_destroy(&entries);
    entriesizes = 0;
    entries = jobject_entries(jsonval, &entriesizes);
    if (entries != NULL) {
        for (i = 0; i < (int)entriesizes; i++) {
            pcurentry = entries[i];
            DEBUG_JVALUE(jsonval, "[%d] value key %s", i, pcurentry->key);
            if (pcurentry->value->type == JOBJECT) {
                if (prefix != NULL && strlen(prefix) > 0) {
                    ret = snprintf_safe(&pcurprefix, &curprefixsize, "%s_%s", prefix, pcurentry->key);
                } else {
                    ret = snprintf_safe(&pcurprefix, &curprefixsize, "%s", pcurentry->key);
                }
                if (ret < 0) {
                    goto out;
                }
                EXTARGS_DEBUG("%s %s dict value", pcurentry->key, pcurprefix);
                ret = load_jsonvalue(pmaincmd, pstate, popt, pcurprefix, pcurentry->value);
                if (ret < 0) {
                    goto out;
                }
                cnt += ret;
            } else {
                EXTARGS_DEBUG("%s key prefix(%s)", pcurentry->key, prefix);
                ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, prefix, pcurentry->key, pcurentry->value);
                if (ret < 0) {
                    goto out;
                }
                cnt += ret;
            }
        }
    }

    ret = cnt;

out:
    snprintf_safe(&pcurprefix, &curprefixsize, NULL);
    jentries_destroy(&entries);
    return ret;
}

int load_value_from_json(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt, const char* jsonfile, const char* prefix)
{
    FILE* fp = NULL;
    int ret = 0;
    char* pbuffer = NULL, *ptmpbuf = NULL;
    int bufsize = 4096, bufnum = 0;
    unsigned int numread;
    jvalue* jval = NULL;

    EXTARGS_DEBUG("load file (%s) with prefix (%s)", jsonfile, prefix);
    fp = fopen(jsonfile, "rb");
    if (fp == NULL) {
        /*we can not read*/
        ret = 0;
        EXTARGS_WARN("can not open(%s) for jsonfile", jsonfile);
        goto out;
    }
try_again:
    assert(ptmpbuf == NULL);
    ptmpbuf = (char*)malloc(bufsize);
    if (ptmpbuf == NULL) {
        ret =  -EXTARGS_NO_MEM;
        goto out;
    }
    memset(ptmpbuf, 0, bufsize);

    if (bufnum > 0) {
        assert(pbuffer != NULL);
        memcpy(ptmpbuf, pbuffer, bufnum);
    }
    if (pbuffer) {
        free(pbuffer);
    }
    pbuffer = ptmpbuf;
    ptmpbuf = NULL;

    while (1) {
        ret = (int)fread(&(pbuffer[bufnum]), 1, (bufsize - bufnum), fp);
        if (ret < 0) {
            if (feof(fp)) {
                break;
            }
            ret = -EXTARGS_IO_ERROR;
            goto out;
        } else if (ret == 0) {
            break;
        }
        bufnum += ret;
        if (bufnum == bufsize) {
            bufsize <<= 1;
            goto try_again;
        }
    }

    /*now all is ok so we should set 0 at end of file*/
    pbuffer[bufnum] = 0x0;
    numread = bufnum + 1;
    EXTARGS_DEBUG("(%s) (%s)", jsonfile, pbuffer);
    EXTARGS_DEBUG_BUFFER(pbuffer, numread, NULL);
    jval = jvalue_read(pbuffer, &numread);
    if (jval == NULL) {
        ret = 0;
        EXTARGS_WARN("can not parse (%s)file", jsonfile);
        goto out;
    }
    EXTARGS_DEBUG_BUFFER(pbuffer, numread, NULL);
    DEBUG_JVALUE(jval, NULL);
    ret = load_jsonvalue(pmaincmd, pstate, popt, prefix, jval);
out:
    if (jval) {
        jvalue_destroy(jval);
    }
    jval = NULL;

    if (pbuffer) {
        free(pbuffer);
    }
    pbuffer = NULL;
    bufsize = 0;
    bufnum = 0;

    if (ptmpbuf) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;

    if (fp) {
        fclose(fp);
    }
    fp = NULL;
    return ret;
}

int format_cmd_prefix(pparse_state_t pstate, int idx, char** pprefix, int *psize)
{
    int ret = 0, nret;
    int i;
    pparse_cmd_state_t pcurcmdstate = NULL;

    if (pstate == NULL) {
        snprintf_safe(pprefix, psize, NULL);
        return 0;
    }

    if (idx <= 0 || idx >= pstate->m_cmdnum) {
        ret = -EXTARGS_INVAL_RETURN;
        goto fail;
    }

    ret = snprintf_safe(pprefix, psize, "");
    if (ret < 0) {
        goto fail;
    }
    nret = ret;

    for (i = 1; i <= idx; i++) {
        if (i > 1) {
            ret = append_snprintf_safe(pprefix, psize, "_");
            if (ret < 0) {
                goto fail;
            }
        }
        pcurcmdstate = pstate->m_cmdstates[i];
        ret = append_snprintf_safe(pprefix, psize, "%s", pcurcmdstate->m_optcmd->m_cmd);
        if (ret < 0) {
            goto fail;
        }
        nret = ret;
    }

    return nret;
fail:
    /*we do not free so we should do this ok*/
    return ret;
}


int set_subcmd_json_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    int i;
    int cnt = 0;
    int ret;
    char* prefix = NULL;
    int prefixsize = 0;
    popt_cmd_t dummy1 = pmaincmd;
    pparse_cmd_state_t pcurcmdstate = NULL;
    dummy1 = dummy1;
    if (pstate->m_cmdstates != NULL && pstate->m_cmdnum > 1) {
        for (i = pstate->m_cmdnum - 1; i > 0; i--) {
            pcurcmdstate = pstate->m_cmdstates[i];
            if (pcurcmdstate->m_jsonfile != NULL) {
                ret = format_cmd_prefix(pstate, i, &prefix, &prefixsize);
                if (ret < 0) {
                    goto out;
                }
                ret = load_value_from_json(pcurcmdstate->m_optcmd, pstate, popt, pcurcmdstate->m_jsonfile, prefix);
                if (ret < 0) {
                    goto out;
                }
                cnt += ret;
            }
        }
    }
    ret = cnt;
out:
    format_cmd_prefix(NULL, 0, &prefix, &prefixsize);
    return ret;
}

int set_cmd_json_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    int cnt = 0;
    int ret;
    pparse_cmd_state_t pcurcmdstate = NULL;
    if (pstate->m_cmdstates != NULL && pstate->m_cmdnum > 0) {
        pcurcmdstate = pstate->m_cmdstates[0];
        if (pcurcmdstate->m_jsonfile != NULL) {
            /*for the command json as prefix ""*/
            ret = load_value_from_json(pmaincmd, pstate, popt, pcurcmdstate->m_jsonfile, "");
            if (ret < 0) {
                goto out;
            }
            cnt += ret;
        }
    }
    ret = cnt;
out:
    return ret;
}

int set_env_subcmd_json_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    int i;
    int cnt = 0;
    int ret;
    pparse_cmd_state_t pcurcmdstate = NULL;
    char* pjsonenvkey = NULL;
    int jsonenvkeysize = 0;
    char* pjsonenvval = NULL;
    char* prefix = NULL;
    int prefixsize = 0;
    char* copyenv=NULL;
    popt_cmd_t dummy1 = pmaincmd;
    dummy1 = dummy1;

    if (pstate->m_cmdstates != NULL && pstate->m_cmdnum > 1) {
        for (i = pstate->m_cmdnum - 1; i > 0; i--) {
            pcurcmdstate = pstate->m_cmdstates[i];
            if (pcurcmdstate->m_optcmd != NULL &&
                    pcurcmdstate->m_optcmd->m_cmd != NULL &&
                    strlen(pcurcmdstate->m_optcmd->m_cmd) > 0) {
                if (st_extargs_inner_state.m_options.m_jsonlong != NULL) {
                    ret = snprintf_safe(&pjsonenvkey,&jsonenvkeysize,"%s_%s",pcurcmdstate->m_optcmd->m_cmd,st_extargs_inner_state.m_options.m_jsonlong);
                } else {
                    ret = snprintf_safe(&pjsonenvkey,&jsonenvkeysize,"%s_%s",pcurcmdstate->m_optcmd->m_cmd,EXTARGS_DEFAULT_JSONLONG);
                }
                if (ret < 0) {
                    goto out;
                }
                str_upper_case(pjsonenvkey);
                pjsonenvval = GETENV(pjsonenvkey);
                if (pjsonenvval != NULL) {
                    ret = _normalize_strdup(pjsonenvval,&copyenv);
                    if (ret < 0) {
                        goto out;
                    }
                    ret = format_cmd_prefix(pstate, i, &prefix, &prefixsize);
                    if (ret < 0) {
                        goto out;
                    }
                    ret = load_value_from_json(pcurcmdstate->m_optcmd, pstate, popt, copyenv, prefix);
                    if (ret < 0) {
                        goto out;
                    }
                    cnt += ret;
                }
            }
        }
    }
    ret = cnt;
out:
    _normalize_strdup(NULL,&copyenv);
    snprintf_safe(&pjsonenvkey, &jsonenvkeysize, NULL);
    format_cmd_prefix(NULL, 0, &prefix, &prefixsize);
    return ret;
}

int set_env_cmd_json_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    int cnt = 0;
    int ret;
    char* pjsonenvkey = NULL;
    int jsonenvkeysize = 0;
    char* pjsonenvval = NULL;
    char* dupenv= NULL;

    if (pstate->m_cmdstates != NULL && pstate->m_cmdnum > 0) {
        if (st_extargs_inner_state.m_options.m_jsonlong != NULL) {
            ret = snprintf_safe(&pjsonenvkey, &jsonenvkeysize, "EXTARGSPARSE_%s",st_extargs_inner_state.m_options.m_jsonlong);
        } else {
            ret = snprintf_safe(&pjsonenvkey, &jsonenvkeysize, "EXTARGSPARSE_%s",EXTARGS_DEFAULT_JSONLONG);
        }
        if (ret < 0) {
            goto out;
        }
        str_upper_case(pjsonenvkey);
        pjsonenvval = GETENV(pjsonenvkey);
        if (pjsonenvval != NULL) {
            ret = _normalize_strdup(pjsonenvval,&dupenv);
            if (ret < 0) {
                goto out;
            }
            ret = load_value_from_json(pmaincmd, pstate, popt, dupenv, "");
            if (ret < 0) {
                goto out;
            }
            cnt += ret;
        }
    }
    ret = cnt;
out:
    _normalize_strdup(NULL,&dupenv);
    snprintf_safe(&pjsonenvkey, &jsonenvkeysize, NULL);
    return ret;
}

int set_env_args_prefix(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt, const char* prefix)
{
    char* penvkey = NULL;
    int envkeysize = 0;
    char* pkey = NULL;
    int keysize = 0;
    char* jsonstr = NULL;
    int jsonsize = 0;
    unsigned int jsonlen = 0;
    int ret;
    char* phiphenchar = NULL;
    popt_cmd_t pcurcmd;
    popt_help_t pcuropt;
    char* pvalue = NULL;
    jvalue* jsonval = NULL;
    int i;
    int cnt = 0;
    jentry** entries = NULL;
    unsigned int entriesize = 0;
    char* pcurprefix = NULL;
    int curprefixsize = 0;
    unsigned long long llval;
    char* pendptr = NULL;

    if (pmaincmd->m_subcmds != NULL) {
        for (i = 0;; i++) {
            pcurcmd = pmaincmd->m_subcmds[i];
            if (pcurcmd == NULL) {
                break;
            }
            if (prefix != NULL && strlen(prefix) > 0) {
                ret = snprintf_safe(&pcurprefix, &curprefixsize, "%s_", prefix);
                if (ret < 0) {
                    goto out;
                }
            }
            ret = append_snprintf_safe(&pcurprefix, &curprefixsize, "%s", pcurcmd->m_cmd);
            if (ret < 0) {
                goto out;
            }
            ret = set_env_args_prefix(pcurcmd, pstate, popt, pcurprefix);
            if (ret < 0) {
                goto out;
            }
            cnt += ret;
        }
    }

    if (pmaincmd->m_cmdopts != NULL) {
        for (i = 0;; i++) {
            pcuropt = &(pmaincmd->m_cmdopts[i]);
            if (pcuropt->m_longopt == NULL) {
                break;
            }
            /*with underscore we will not append */
            phiphenchar = strchr(pcuropt->m_longopt, '-');
            if (phiphenchar != NULL) {
                ret = snprintf_safe(&penvkey, &envkeysize, "%s", pcuropt->m_longopt);
            } else {
                ret = snprintf_safe(&penvkey, &envkeysize, "EXTARGS_%s", pcuropt->m_longopt);
            }
            if (ret < 0) {
                goto out;
            }
            str_underscore_case(penvkey);
            str_upper_case(penvkey);
            pvalue = GETENV(penvkey);
            if (pvalue == NULL) {
                EXTARGS_DEBUG("[%s]=NULL", penvkey);
            }
            if (pvalue != NULL) {
                EXTARGS_DEBUG("[%s]=%s", penvkey, pvalue);
                if (jsonval != NULL) {
                    jvalue_destroy(jsonval);
                }
                jsonval = NULL;
                ret = snprintf_safe(&pkey, &keysize, "%s", pcuropt->m_longopt);
                if (ret < 0) {
                    goto out;
                }
                str_underscore_case(pkey);

                switch (pcuropt->m_opttype) {
                case OPT_INC_TYPE:
                case OPT_INT_TYPE:
                case OPT_LL_TYPE:
                case OPT_ULL_TYPE:
                    /*now we should give the value of it will start of 0x or x*/
                    ret = inner_parse_number(pvalue, &llval, &pendptr);
                    if (ret < 0) {
                        EXTARGS_ERROR("(%s) not valid value [%s]", penvkey, pvalue);
                        goto out;
                    }
                    ret = snprintf_safe(&jsonstr, &jsonsize, "{\"%s\": %lld}", pkey, llval);
                    if (ret < 0) {
                        goto out;
                    }
                    jsonlen = (int)strlen(jsonstr) + 1;
                    jsonval = jvalue_read(jsonstr, &jsonlen);
                    if (jsonval != NULL) {
                        jentries_destroy(&entries);
                        entriesize = 0;
                        entries = jobject_entries(jsonval, &entriesize);
                        if (entries != NULL) {
                            //ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, pkey, prefix, entries[0]->value);
                            ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, "", pkey, entries[0]->value);
                            if (ret < 0) {
                                goto out;
                            }
                            cnt += ret;
                        } else {
                            EXTARGS_WARN("get not get json value for (%s)", jsonstr);
                        }
                    } else {
                        EXTARGS_WARN("can not parse %s=%s", penvkey, pvalue);
                    }
                    break;
                case OPT_TRUE_TYPE:
                case OPT_FALSE_TYPE:
                case OPT_DOUBLE_TYPE:
                    ret = snprintf_safe(&jsonstr, &jsonsize, "{\"%s\" : %s}", pkey, pvalue);
                    if (ret < 0) {
                        goto out;
                    }
                    jsonlen = (int)strlen(jsonstr) + 1;
                    jsonval = jvalue_read(jsonstr, &jsonlen);
                    if (jsonval != NULL) {
                        jentries_destroy(&entries);
                        entriesize = 0;
                        entries = jobject_entries(jsonval, &entriesize);
                        if (entries != NULL) {
                            //ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, pkey, prefix, entries[0]->value);
                            ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, "", pkey, entries[0]->value);
                            if (ret < 0) {
                                goto out;
                            }
                            cnt += ret;
                        } else {
                            EXTARGS_WARN("get not get json value for (%s)", jsonstr);
                        }
                    } else {
                        EXTARGS_WARN("can not parse %s=%s", penvkey, pvalue);
                    }
                    break;
                case OPT_STRING_TYPE:
                case OPT_JSONFILE_TYPE:
                    if (pvalue && strlen(pvalue) > 0) {
                        ret = snprintf_safe(&jsonstr, &jsonsize, "{\"%s\" : \"%s\"}", pkey, pvalue);
                    }   else {
                        ret = snprintf_safe(&jsonstr, &jsonsize, "{\"%s\" : null}", pkey);
                    }
                    if (ret < 0) {
                        goto out;
                    }
                    jsonlen = (int)strlen(jsonstr) + 1;
                    jsonval = jvalue_read(jsonstr, &jsonlen);
                    if (jsonval != NULL) {
                        jentries_destroy(&entries);
                        entriesize = 0;
                        entries = jobject_entries(jsonval, &entriesize);
                        if (entries != NULL) {
                            //ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, prefix, pkey, entries[0]->value);
                            ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, "", pkey, entries[0]->value);
                            if (ret < 0) {
                                goto out;
                            }
                            cnt += ret;
                        } else {
                            EXTARGS_WARN("get not get json value for (%s)", jsonstr);
                        }

                    } else {
                        EXTARGS_WARN("can not parse %s=%s", penvkey, pvalue);
                    }
                    break;
                case OPT_LIST_TYPE:
                    ret = snprintf_safe(&jsonstr, &jsonsize, "{\"%s\" : %s}", pkey, pvalue);
                    if (ret < 0) {
                        goto out;
                    }
                    jsonlen = (int)strlen(jsonstr) + 1;
                    jsonval = jvalue_read(jsonstr, &jsonlen);
                    if (jsonval != NULL) {
                        jentries_destroy(&entries);
                        entriesize = 0;
                        entries = jobject_entries(jsonval, &entriesize);
                        if (entries != NULL) {
                            //ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, prefix, pkey, entries[0]->value);
                            ret = set_jsonvalue_not_defined(pmaincmd, pstate, popt, "", pkey, entries[0]->value);
                            if (ret < 0) {
                                goto out;
                            }
                            cnt += ret;
                        } else {
                            EXTARGS_WARN("get not get json value for (%s)", jsonstr);
                        }

                    } else {
                        EXTARGS_WARN("can not parse %s=%s", penvkey, pvalue);
                    }
                    break;
                case OPT_NONE_TYPE:
                case OPT_CMD_TYPE:
                case OPT_ARG_TYPE:
                case OPT_DICT_TYPE:
                    break;
                default:
                    EXTARGS_WARN("(%s)unknown type(%d)", pcuropt->m_longopt, pcuropt->m_opttype);
                    break;
                }
            }

        }
    }

    ret = cnt;
out:
    if (jsonval != NULL) {
        jvalue_destroy(jsonval);
    }
    jsonval = NULL;
    jentries_destroy(&entries);
    entriesize = 0;
    snprintf_safe(&pcurprefix, &curprefixsize, NULL);
    snprintf_safe(&jsonstr, &jsonsize, NULL);
    snprintf_safe(&pkey, &keysize, NULL);
    snprintf_safe(&penvkey, &envkeysize, NULL);
    return ret;
}

int set_env_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    return set_env_args_prefix(pmaincmd, pstate, popt, pmaincmd->m_cmd);
}

int set_default_args_inner(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    popt_cmd_t pcursubcmd = NULL;
    popt_help_t pcurhelp = NULL;
    int i;
    int ret;
    int cnt = 0;
    char* pvalue = NULL;
    int valuesize = 0;
    char** pptr;
    int multi = 0;
    float *pfltptr = NULL;
    char* pintervalue=NULL;

    /*first to test the subcommand*/
    if (pmaincmd && pmaincmd->m_subcmds != NULL) {
        for (i = 0;; i++) {
            pcursubcmd = pmaincmd->m_subcmds[i];
            if (pcursubcmd == NULL) {
                break;
            }

            ret = set_default_args_inner(pcursubcmd, pstate, popt);
            if (ret < 0) {
                goto out;
            }
            cnt += ret;
        }
    }

    if (pmaincmd != NULL) {
        for (i = 0;; i++) {
            multi = 0;
            pcurhelp = &(pmaincmd->m_cmdopts[i]);
            if (pcurhelp->m_longopt == NULL) {
                break;
            }

            if (is_opt_setted(pstate, pcurhelp) != 0) {
                continue;
            }
            ret = 0;
            switch (pcurhelp->m_opttype) {
            case OPT_TRUE_TYPE:
                /*this is set default , true for false*/
                ret = snprintf_safe(&pvalue,&valuesize,"false");
                break;
            case OPT_FALSE_TYPE:
                /*this is set default ,so we should change it ok*/
                ret= snprintf_safe(&pvalue,&valuesize,"true");
                break;
            case OPT_STRING_TYPE:
                pintervalue = (char*)((uintptr_t)pcurhelp->m_defvalue);
                if (pintervalue) {
                    ret = snprintf_safe(&pvalue,&valuesize,"%s",(char*)((uintptr_t)pcurhelp->m_defvalue));
                } else {
                    /*we should set to the null*/
                    snprintf_safe(&pvalue,&valuesize,NULL);
                    ret = 0;
                }

                break;
            case OPT_LIST_TYPE:
                pptr = (char**)((uintptr_t)pcurhelp->m_defvalue);
                ret = call_jsonfunc_function(pcurhelp,pptr,popt);
                if (ret < 0) {
                    goto out;
                }
                ret = insert_opt_setted(pstate,pcurhelp);
                if (ret < 0) {
                    goto out;
                }
                multi = -1;
                cnt ++;
                break;
            case OPT_CMD_TYPE:
            case OPT_DICT_TYPE:
                ret = -EXTARGS_INVAL_PARAM;
                goto out;
            case OPT_ARG_TYPE:
            case OPT_HELP_TYPE:
            case OPT_JSONFILE_TYPE:
                multi = -1;
                break;
            case OPT_INC_TYPE:
                ret = snprintf_safe(&pvalue,&valuesize,"0");
                break;
            case OPT_INT_TYPE:
                ret = snprintf_safe(&pvalue, &valuesize, "%d", (int)pcurhelp->m_defvalue);
                break;
            case OPT_DOUBLE_TYPE:
                pfltptr = (float*)((uintptr_t)pcurhelp->m_defvalue);
                if (pfltptr == NULL) {
                    ret = snprintf_safe(&pvalue, &valuesize, "0.0");
                } else {
                    ret = snprintf_safe(&pvalue, &valuesize, "%f", *pfltptr);
                }
                break;
            case OPT_LL_TYPE:
                ret = snprintf_safe(&pvalue, &valuesize, "%lld", (long long)pcurhelp->m_defvalue);
                break;
            case OPT_ULL_TYPE:
                ret = snprintf_safe(&pvalue, &valuesize, "%lld", (unsigned long long)pcurhelp->m_defvalue);
                break;
            default:
                EXTARGS_ERROR("not ok type %d", pcurhelp->m_opttype);
                ret = -EXTARGS_INVAL_PARAM;
                goto out;
            }
            if (ret < 0) {
                goto out;
            }
            if (multi == 0) {
                EXTARGS_DEBUG("%s %s", pcurhelp->m_longopt, pvalue ? pvalue : "NULL");
                ret = call_jsonfunc_function(pcurhelp,pvalue, popt);
                if (ret < 0) {
                    goto out;
                }
                ret = insert_opt_setted(pstate, pcurhelp);
                if (ret < 0) {
                    goto out;
                }
                cnt ++;
            }
        }
    }
    ret = cnt;
out:
    snprintf_safe(&pvalue, &valuesize, NULL);
    return ret;
}

int set_default_args(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt)
{
    return set_default_args_inner(pmaincmd, pstate, popt);
}

typedef int (*env_func_t)(popt_cmd_t pmaincmd, pparse_state_t pstate, void* popt);

typedef struct env_funcs {
    int m_priority;
    env_func_t m_func;
} env_funcs_t, *penv_funcs_t;

static env_funcs_t st_environ_funcs [] = {
    {EXTARGS_PRIO_SUBCMD_JSON             , set_subcmd_json_args        },
    {EXTARGS_PRIO_CMD_JSON                , set_cmd_json_args           },
    {EXTARGS_PRIO_ENV_SUBCMD_JSON         , set_env_subcmd_json_args    },
    {EXTARGS_PRIO_ENV_CMD_JSON            , set_env_cmd_json_args       },
    {EXTARGS_PRIO_ENV_CMD                 , set_env_args                },
    {EXTARGS_PRIO_NONE                    , NULL                          }
};

env_func_t find_env_func(penv_funcs_t funcs, int prior)
{
    env_func_t pfindfunc = NULL;
    int i;
    for (i = 0;; i++) {
        if (funcs[i].m_priority == EXTARGS_PRIO_NONE) {
            break;
        }
        if (funcs[i].m_priority == prior) {
            pfindfunc = funcs[i].m_func;
            break;
        }
    }
    return pfindfunc;
}

static int st_default_environ_prio[] = {
    EXTARGS_PRIO_SUBCMD_JSON,
    EXTARGS_PRIO_CMD_JSON,
    EXTARGS_PRIO_ENV_CMD,
    EXTARGS_PRIO_ENV_SUBCMD_JSON,
    EXTARGS_PRIO_ENV_CMD_JSON,
    EXTARGS_PRIO_NONE
};

popt_help_t find_args_help(popt_cmd_t pcmd)
{
    popt_help_t pfindhelp = NULL, pcurhelp;
    int i;
    if (pcmd != NULL && pcmd->m_cmdopts != NULL) {
        for (i = 0;; i++) {
            pcurhelp = &(pcmd->m_cmdopts[i]);
            if (pcurhelp->m_longopt == NULL) {
                break;
            }
            if (pcurhelp->m_opttype == OPT_ARG_TYPE) {
                pfindhelp = pcurhelp;
                break;
            }
        }
    }
    return pfindhelp;
}

pextargs_state_t alloc_extargs_state(void)
{
    pextargs_state_t pstate = NULL;

    pstate = malloc(sizeof(*pstate));
    if (pstate == NULL) {
        goto fail;
    }
    memset(pstate, 0, sizeof(*pstate));
    pstate->subcommand = NULL;
    pstate->leftargs = NULL;

    return pstate;
fail:
    return NULL;
}

void free_extargs_state(pextargs_state_t* ppextstate)
{
    pextargs_state_t pextstate;
    int i;
    if (ppextstate &&  *ppextstate) {
        pextstate = *ppextstate;
        if (pextstate->subcommand) {
            free(pextstate->subcommand);
        }
        pextstate->subcommand = NULL;
        if (pextstate->leftargs != NULL) {
            for (i=0;;i++) {
                if (pextstate->leftargs[i] == NULL) {
                    break;
                }
                free(pextstate->leftargs[i]);
                pextstate->leftargs[i] = NULL;
            }
            free(pextstate->leftargs);
            pextstate->leftargs = NULL;
        }

        free(pextstate);
        *ppextstate = NULL;
    }
}

int check_cmd_resursive(popt_cmd_t pcmd)
{
    popt_help_t pcurhelp = NULL;
    unsigned int cmdchecksize = sizeof(opt_cmd_t);
    unsigned int cmdminsize = OPTION_OFFSET(opt_cmd_t, m_subcmds) + sizeof(pcmd->m_subcmds);
    unsigned int optchecksize = sizeof(opt_help_t);
    unsigned int optminsize = OPTION_OFFSET(opt_help_t, m_optfunc) + sizeof(pcurhelp->m_optfunc);
    int ret;
    int chkcnt = 0;
    popt_cmd_t *ppsubcmds;
    popt_cmd_t pcurcmd;
    int i;

    if (pcmd->m_cmdsize > cmdchecksize) {
        ret = -EXTARGS_INVAL_PARAM;
        goto fail;
    }
    if (pcmd->m_cmdsize < cmdminsize) {
        ret = -EXTARGS_NOT_SUPPORTED;
        goto fail;
    }

    if (pcmd->m_subcmds != NULL) {
        ppsubcmds = pcmd->m_subcmds;
        for (i = 0;; i++) {
            pcurcmd = ppsubcmds[i];
            if (pcurcmd == NULL) {
                break;
            }
            ret = check_cmd_resursive(pcurcmd);
            if (ret < 0) {
                goto fail;
            }
            chkcnt += ret;
        }
    }

    for (i = 0;; i++) {
        pcurhelp = &(pcmd->m_cmdopts[i]);
        if (pcurhelp->m_longopt == NULL) {
            break;
        }
        if (pcurhelp->m_optsize  < optminsize) {
            ret = -EXTARGS_INVAL_PARAM;
            goto fail;
        }
        if (pcurhelp->m_optsize > optchecksize) {
            ret = -EXTARGS_NOT_SUPPORTED;
            goto fail;
        }
        chkcnt ++;
    }

    /*ok we checked*/
    ret = chkcnt;
    return ret;
fail:
    return ret;
}

int check_main_cmd(popt_cmd_t pmaincmd)
{
    return check_cmd_resursive(pmaincmd);
}

int __dup_left_args(pextargs_state_t pextstate,pparse_state_t pparsestate)
{
    char** pptmpargs=NULL;
    int i;
    int ncopied = 0;
    int ret;

    if (pparsestate->m_leftargs != NULL) {
        for (i=0;;i++) {
            if (pparsestate->m_leftargs[i] == NULL) {
                break;
            }
            ncopied ++;
        }
        pptmpargs = malloc((ncopied + 1)* sizeof(*pptmpargs));
        if (pptmpargs == NULL) {
            ret = -EXTARGS_NO_MEM;
            goto fail;
        }
        memset(pptmpargs,0,(ncopied+1)*sizeof(*pptmpargs));
        for (i=0;i<ncopied;i++) {
            assert(pparsestate->m_leftargs[i]);
            pptmpargs[i] = safe_strdup(pparsestate->m_leftargs[i]);
            if (pptmpargs[i] == NULL) {
                ret = -EXTARGS_NO_MEM;
                goto fail;
            }
        }
    }

    if (pextstate->leftargs != pptmpargs && 
        pextstate->leftargs != NULL) {
        for (i=0;;i++) {
            if (pextstate->leftargs[i] == NULL) {
                break;
            }
            free(pextstate->leftargs[i]);
            pextstate->leftargs[i] = NULL;
        }
        free(pextstate->leftargs);
        pextstate->leftargs = NULL;
    }
    pextstate->leftargs = pptmpargs;
    pptmpargs = NULL;
    return ncopied;
fail:
    if (pptmpargs != NULL) {
        for (i=0;;i++) {
            if (pptmpargs[i] == NULL) {
                break;
            }
            free(pptmpargs[i]);
            pptmpargs[i] = NULL;
        }
        free(pptmpargs);        
    }
    pptmpargs = NULL;
    return ret;
}

int get_leftargs(pextargs_state_t pextstate)
{
    int ret = 0;
    if (pextstate->leftargs) {
        for (ret = 0;; ret++) {
            if (pextstate->leftargs[ret] == 0) {
                break;
            }
        }
    }
    return ret;
}

int copy_to_leftargs(pparse_state_t pstate,char* arg)
{
    int ret=0;
    char* pdupstr=NULL;
    char** ptmpleftargs=NULL;
    int exnum =0;
    int i;
    pdupstr = safe_strdup(arg);
    if (pdupstr == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }
    EXTARGS_DEBUG("strdup (%s) [%p]",pdupstr,pdupstr);
    if (pstate->m_leftargs != NULL) {
        for (i=0;;i++) {
            if (pstate->m_leftargs[i] == NULL) {
                break;
            }
            exnum ++;
        }
    }

    ptmpleftargs = malloc(sizeof(*ptmpleftargs) * (exnum + 2));
    if (ptmpleftargs == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    memset(ptmpleftargs,0,sizeof(*ptmpleftargs)*(exnum + 2));
    if (exnum > 0) {
        memcpy(ptmpleftargs,pstate->m_leftargs,sizeof(*ptmpleftargs) * exnum);
    }        

    if (pstate->m_leftargs) {
        free(pstate->m_leftargs);
    }
    pstate->m_leftargs = ptmpleftargs;
    ptmpleftargs = NULL;

    EXTARGS_DEBUG("[%d] = [%p]",exnum,pdupstr);
    pstate->m_leftargs[exnum] = pdupstr;
    return (exnum+1);
fail:
    if (pdupstr) {
        free(pdupstr);
    }
    pdupstr = NULL;
    return ret;
}

int __update_parse_state_step(pparse_state_t pstate,int step)
{
    if (pstate->m_curcharidx >= 0) {
        if (pstate->m_shortcharhasidx < 0) {
            pstate->m_shortcharhasidx = 0;
        }
        if (pstate->m_shortcharhasidx > 0) {
            return -EXTARGS_MULTI_NEEDARGS;
        }
        EXTARGS_DEBUG("m_shortcharhasidx [%d] => [%d]",pstate->m_shortcharhasidx,(pstate->m_shortcharhasidx + step));
        pstate->m_shortcharhasidx += step;
    } else {
        if (pstate->m_longopthasidx < 0) {
            pstate->m_longopthasidx = 0;
        }
        if (pstate->m_longopthasidx > 0) {
            return -EXTARGS_MULTI_NEEDARGS;
        }
        EXTARGS_DEBUG("m_longopthasidx [%d] => [%d]",pstate->m_longopthasidx,(pstate->m_longopthasidx + step));
        pstate->m_longopthasidx += step;
    }
    return 0;
}


int parse_param_smart_ex(int argc, char* argv[], popt_cmd_t pmaincmd, void* popt, pextargs_state_t* ppextstate, int* pprio, pextargs_options_t pargoptions)
{
    int ret;
    int i;
    parse_state_t state;
    char* opt;
    popt_cmd_t pcurcmd = pmaincmd;
    int error = 0;
    popt_help_t pgetopt = NULL;
    int* getprior = pprio;
    env_func_t penvfunc = NULL;
    int nargs;
    pextargs_state_t pextstate = NULL;
    char* psubcmdname = NULL;
    char* pcurkey;
    char* pcurval;
    int realnargs = 0;
    int validx;
    int step;

    if (ppextstate == NULL || *ppextstate != NULL) {
        ret = -EXTARGS_INVAL_PARAM;
        goto fail;
    }
    init_parse_state(&state);
    extargs_log_init();

    ret = init_extargs_inner_state(argc, argv, pmaincmd, pargoptions);
    if (ret < 0) {
        goto fail;
    }

    ret = check_main_cmd(pmaincmd);
    if (ret < 0) {
        goto fail;
    }
    EXTARGS_DEBUG("popt %p", popt);
    if (pmaincmd == NULL) {
        ret = -EXTARGS_INVAL_PARAM;
        goto fail;
    }

    ret = expand_opts_array(&state, pcurcmd);
    if (ret < 0) {
        goto fail;
    }
    if (getprior == NULL) {
        getprior = st_default_environ_prio;
    }
    ret = init_parse_prio(&state, getprior);
    if (ret < 0) {
        goto fail;
    }


    while (1) {
next_cycle:
        error = 0;
        pgetopt = find_opt_idx(argc, argv, &state, &error);
        EXTARGS_DEBUG("get opt %s curidx %d error %d", pgetopt ? pgetopt->m_longopt : "NULL", state.m_curidx, error);
        if (pgetopt == NULL) {
            if (state.m_curidx >= argc) {
                /*that is over ,so we should handle out this*/
                break;
            }
            if (error == 0) {
                /*this may be the command ,so we should find it whether it is subcommands*/
                for (i = 0;; i++) {
                    if (pcurcmd->m_subcmds == NULL) {
                        break;
                    }
                    opt = NULL;
                    if (state.m_curidx < argc && state.m_curidx >= 0) {
                        opt = argv[state.m_curidx];
                    }
                    if (opt == NULL) {
                        break;
                    }
                    EXTARGS_DEBUG("[%d] %p opt %s", i, pcurcmd->m_subcmds[i], opt);
                    if (pcurcmd->m_subcmds[i] == NULL || pcurcmd->m_subcmds[i]->m_cmd == NULL) {
                        /*we can not find ,so we just return current parse command*/
                        break;
                    }
                    if (strcmp(opt, pcurcmd->m_subcmds[i]->m_cmd) == 0) {
                        EXTARGS_DEBUG("step cmd[%s]",opt);
                        ret = expand_opts_array(&state, pcurcmd->m_subcmds[i]);
                        if (ret < 0) {
                            goto fail;
                        }
                        EXTARGS_DEBUG(" ");
                        pcurcmd = (pcurcmd->m_subcmds[i]);
                        step_one_cmd(argc, argv, &state);
                        goto next_cycle;
                    }
                }
                if ((st_extargs_inner_state.m_options.m_flags & EXTARGS_FLAG_NO_PASSALL)){
                    break;
                } else {
                    ret = copy_to_leftargs(&state,argv[state.m_curidx]);
                    if (ret < 0) {
                        goto fail;
                    }
                    EXTARGS_DEBUG(" ");
                    step_one_cmd(argc,argv,&state);
                    goto next_cycle;
                }
            }
            opt = "NULL";
            EXTARGS_DEBUG("[%d]",state.m_curidx);
            if (state.m_curidx < argc && state.m_curidx >= 0) {
                opt = argv[state.m_curidx];
            }
            default_help_function(argv[0], "", error, pcurcmd, "unknown %s options", opt);
        }
        assert(pgetopt->m_longopt != NULL);
        EXTARGS_DEBUG("%s optfunc %p offset %d", pgetopt->m_longopt, pgetopt->m_optfunc , pgetopt->m_offset);

        /*now first to check for jsonfile opt*/
        if (pgetopt->m_opttype == OPT_JSONFILE_TYPE) {
            if (pgetopt->m_needargs == 0) {
                ret = -EXTARGS_INVAL_PARAM;
                EXTARGS_ERROR("can not accept (%s) for JSONFILE TYPE", pgetopt->m_longopt);
                goto fail;
            }
            ret = add_jsonfile_value(&state, pgetopt, argv[state.m_validx]);
            if (ret < 0) {
                goto fail;
            }
            /*we search for the next one*/
            step_one_cmd(argc,argv,&state);
            continue;
        }   

        /*now we should call opt*/
        if (pgetopt->m_opttype != OPT_HELP_TYPE) {
            assert(state.m_keyidx > 0 && state.m_keyidx < argc);
            validx = state.m_validx;
        } else {
            if (psubcmdname) {
                free(psubcmdname);
            }
            psubcmdname = NULL;
            psubcmdname = get_command_subcommand_name(&state);
            if (psubcmdname == NULL) {
                ret = -EXTARGS_NO_MEM;
                goto fail;
            }
            pcurkey = argv[state.m_keyidx];
            pcurval = psubcmdname;
            ret = help_opt_func_base(pcurkey,pcurval,NULL);
            exit(0);
        }

        step = call_optparse_function(argc,argv,validx,pgetopt,popt);
        if (step < 0) {
            ret = -EXTARGS_INVAL_RETURN;
            goto fail;
        }
        ret = insert_opt_setted(&state, pgetopt);
        if (ret < 0) {
            goto fail;
        }

        EXTARGS_DEBUG("[%d][%s] %s%s step [%d]",(validx),argv[(validx-1)],st_extargs_inner_state.m_options.m_longprefix,pgetopt->m_longopt,step);
        ret = __update_parse_state_step(&state,step);
        if (ret < 0) {
            goto fail;
        }
    }

    for (i = 0;; i++) {
        EXTARGS_DEBUG("[%d] priority [%d]",i,state.m_priorities[i]);
        penvfunc = find_env_func(st_environ_funcs, state.m_priorities[i]);
        if (penvfunc == NULL) {
            break;
        }
        EXTARGS_DEBUG("[%d] %d func 0x%p", i, state.m_priorities[i], penvfunc);
        ret = penvfunc(pmaincmd, &state, popt);
        if (ret < 0) {
            goto fail;
        }
    }

    ret = set_default_args(pmaincmd, &state, popt);
    if (ret < 0) {
        goto fail;
    }

    if (pextstate == NULL) {
        pextstate = alloc_extargs_state();
        if (pextstate == NULL) {
            ret = -EXTARGS_NO_MEM;
            goto fail;
        }
    }

    EXTARGS_DEBUG("idx=%d(%s)", state.m_curidx, argc > state.m_curidx ? argv[state.m_curidx] : "NULL");
    while(state.m_curidx < argc) {
        ret = copy_to_leftargs(&state,argv[state.m_curidx]);
        if (ret < 0) {
            goto fail;
        }
        ret = step_one_cmd(argc,argv,&state);
        if (ret < 0) {
            goto fail;
        }
    }
    if (pextstate->subcommand) {
        free(pextstate->subcommand);
        pextstate->subcommand = NULL;
    }

    if (psubcmdname != NULL) {
        free(psubcmdname);
    }
    psubcmdname = NULL;

    psubcmdname = get_command_subcommand_name(&state);
    if (psubcmdname == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }
    pextstate->subcommand = safe_strdup(psubcmdname);
    if (pextstate->subcommand == NULL) {
        ret = -EXTARGS_NO_MEM;
        goto fail;
    }

    /*now to check for the number of args */
    realnargs = __dup_left_args(pextstate,&state);
    if (realnargs < 0) {
        ret = realnargs;
        goto fail;
    }
    pgetopt = find_args_help(pcurcmd);
    if (pgetopt != NULL) {
        /*we should check */
        switch ((pgetopt->m_defvalue & EXTARGS_NARGS_SPECIAL_MASK)) {
        case 0:
            /*this means we should detect for it*/
            nargs = (int)pgetopt->m_defvalue;
            if (nargs != realnargs) {
                EXTARGS_ERROR("need %d args but %d", nargs, realnargs);
                ret = -EXTARGS_INVAL_PARAM;
                goto fail;
            }
            break;
        case EXTARGS_NARGS_QUESTION:
            if ( realnargs > 1) {
                EXTARGS_ERROR("more args than expected");
                ret = -EXTARGS_INVAL_PARAM;
                goto fail;
            }
            break;
        case EXTARGS_NARGS_PLUS:
            if (realnargs < 1) {
                EXTARGS_ERROR("need more args");
                ret = -EXTARGS_INVAL_PARAM;
                goto fail;
            }
            break;
        case EXTARGS_NARGS_STAR:
            /*all is ok*/
            break;
        default:
            EXTARGS_ERROR("unknown type for args %lld", pgetopt->m_defvalue);
            ret = -EXTARGS_INVAL_PARAM;
            goto fail;
        }
    }


    if (psubcmdname != NULL) {
        free(psubcmdname);
    }
    psubcmdname = NULL;
    EXTARGS_DEBUG(" ");
    deinitialize_state(&state);
    if (pcurcmd && pcurcmd->m_cmdfunc) {
        ret = pcurcmd->m_cmdfunc(argc, argv, pextstate, popt);
        if (ret < 0) {
            ret = -EXTARGS_INVAL_RETURN;
            goto fail;
        }
    }
    *ppextstate = pextstate;
    EXTARGS_DEBUG(" ");
    return realnargs;
fail:
    if (psubcmdname != NULL) {
        free(psubcmdname);
    }
    psubcmdname = NULL;
    deinitialize_state(&state);
    if (ppextstate && *ppextstate != pextstate && pextstate != NULL) {
        free_extargs_state(&pextstate);
    }
    pextstate = NULL;
    return ret;
}

void extargs_deinit(void)
{
    free_extargs_inner_state(&st_extargs_inner_state);
    return;
}