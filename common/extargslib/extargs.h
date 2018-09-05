#ifndef __EXTARGS_H__
#define __EXTARGS_H__

#include <stdarg.h>
#include <stdint.h>
/*this for the WINLIB_API define*/
#include <cmn_err.h>

/**************************************************
*
*  to parse handle
**************************************************/

#define OPTION_OFFSET(typestruct,mem)  ((int)((uintptr_t)(&(((typestruct*)0)->mem))))

typedef struct __extargs_state {
    unsigned int statesize;
    char* subcommand;
    char** leftargs;
} extargs_state_t,*pextargs_state_t;

struct __opt_help;

typedef int (*cmd_func_t)(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
typedef int (*opt_func_t)(int argc,char* argv[],int validx,struct __opt_help* popthelp,void** ppdestopt);
typedef char* (*opt_help_func_t)(struct __opt_help* popthelp);
typedef int (*opt_jsonfunc_t)(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);

#define OPT_NONE_TYPE            0
#define OPT_TRUE_TYPE            1
#define OPT_FALSE_TYPE           2
#define OPT_STRING_TYPE          3
#define OPT_LIST_TYPE            4
#define OPT_INC_TYPE             5
#define OPT_CMD_TYPE             6
#define OPT_ARG_TYPE             7
#define OPT_DICT_TYPE            8
#define OPT_INT_TYPE             9
#define OPT_DOUBLE_TYPE          10
#define OPT_LL_TYPE              11
#define OPT_ULL_TYPE             12
#define OPT_HELP_TYPE            13
#define OPT_JSONFILE_TYPE        14

#define EXTARGSLIB_MAIN_VERSION  1
#define EXTARGSLIB_MINOR_VERSION 0
#define EXTARGSLIB_PATCH_VERSION 2


#define EXTARGS_NARGS_BITS_SHIFT 32
#define EXTARGS_NARGS_MASK       ((1ULL << EXTARGS_NARGS_BITS_SHIFT) -1)


/* this is for the "$" : "?" */
#define EXTARGS_NARGS_QUESTION   ( 1ULL << EXTARGS_NARGS_BITS_SHIFT)
/* this is for the "$" : "+" */
#define EXTARGS_NARGS_PLUS       ( 1ULL << (EXTARGS_NARGS_BITS_SHIFT+1))
/* this is for the "$" : "*" */
#define EXTARGS_NARGS_STAR       ( 1ULL << (EXTARGS_NARGS_BITS_SHIFT+2))

#define EXTARGS_NARGS_SPECIAL_MASK ( EXTARGS_NARGS_QUESTION | EXTARGS_NARGS_PLUS | EXTARGS_NARGS_STAR )


#define EXTARGSLIB_VERSION       ((EXTARGSLIB_MAIN_VERSION & 0xff )<< 16 | (EXTARGSLIB_MAIN_VERSION  & 0xff )<< 8  | (EXTARGSLIB_PATCH_VERSION & 0xff))



#define EXTARGS_FLAG_NO_JSON     (1UL << 0)
#define EXTARGS_FLAG_NO_PASSALL  (1UL << 1)
#define EXTARGS_FLAG_NO_BUNDLE   (1UL << 2)

#define EXTARGS_FLAG_DEFAULT     (0)

#define EXTARGS_DEFAULT_SCREENWIDTH 80
#define EXTARGS_MIN_SCREENWIDTH     50

#define EXTARGS_DEFAULT_LONGPREFIX  "--"
#define EXTARGS_DEFAULT_SHORTPREFIX "-"
#define EXTARGS_DEFAULT_JSONLONG    "json"

typedef struct __extargs_options {
    unsigned int m_optionsize;
    int m_nohelp;
    char* m_argv0;
    unsigned int m_flags;
    int m_screenwidth;
    char* m_longprefix;
    char* m_shortprefix;
    char* m_jsonlong;
} extargs_options_t,*pextargs_options_t;

typedef struct __opt_help {
    unsigned int m_optsize;
    const char* m_longopt;
    const char m_shortopt;
    const char* m_argname;
    const char* m_helpinfo;
    int m_needargs;
    int m_offset;
    unsigned long long m_defvalue;
    int m_opttype;
    opt_func_t m_optfunc;
    opt_help_func_t m_helpfunc;
    opt_jsonfunc_t m_jsonfunc;
} opt_help_t, *popt_help_t;

typedef struct __opt_cmd {
    unsigned int m_cmdsize;
    const char* m_cmd;
    const char* m_cmdepxr;
    const char* m_cmdhelp;
    cmd_func_t m_cmdfunc;
    opt_help_t *m_cmdopts;
    struct __opt_cmd** m_subcmds;
} opt_cmd_t, *popt_cmd_t;

typedef int extargs_priority_t;

#define  EXTARGS_NEED_ARGS          1
#define  EXTARGS_NO_OPTS            2
#define  EXTARGS_NO_MEM             3
#define  EXTARGS_INVAL_PARAM        4
#define  EXTARGS_INVAL_SUBCMD       5
#define  EXTARGS_INVAL_RETURN       6
#define  EXTARGS_NOT_SUPPORTED      7
#define  EXTARGS_IO_ERROR           8
#define  EXTARGS_MULTI_NEEDARGS     9
#define  EXTARGS_INVALID_JSON       10

#define  EXTARGS_PRIO_NONE               0
#define  EXTARGS_PRIO_SUBCMD_JSON        1
#define  EXTARGS_PRIO_CMD_JSON           2
#define  EXTARGS_PRIO_ENV_SUBCMD_JSON    3
#define  EXTARGS_PRIO_ENV_CMD_JSON       4
#define  EXTARGS_PRIO_ENV_CMD            5

#if defined(_WIN32) || defined(_WIN64)
#define __EXTARGS_WIN__
#else
#undef __EXTARGS_WIN__
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define  INIT_EXTARGS_OPTIONS(option)                        \
static extargs_options_t option = {                          \
    sizeof(option)                     /* to make size */  , \
    0                                  /* nohelp to make*/ , \
    NULL                               /* argv0  */        , \
    EXTARGS_FLAG_DEFAULT               /* have json */     , \
    EXTARGS_DEFAULT_SCREENWIDTH        /* default 80*/     , \
    EXTARGS_DEFAULT_LONGPREFIX         /* long prefix --*/ , \
    EXTARGS_DEFAULT_SHORTPREFIX        /* short prefix -*/ , \
    EXTARGS_DEFAULT_JSONLONG           /* json long */       \
}

WINLIB_API int true_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int false_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int string_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int list_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int inc_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int cmd_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int arg_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int dict_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int int_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int double_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int ll_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int ull_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);
WINLIB_API int jsonfile_opt_func(int argc,char* argv[],int validx,popt_help_t popthelp,void** ppdestopt);


WINLIB_API int true_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int false_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int string_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int list_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int inc_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int cmd_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int arg_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int dict_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int int_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int double_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int ll_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int ull_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);
WINLIB_API int jsonfile_opt_jsonfunc(struct __opt_help* popthelp,void* pvalue,void** ppdestopt);

WINLIB_API void default_help_functionv(const char* arg0,const char* subcmd, int ec, popt_cmd_t pmaincmd,  const char* fmt, va_list ap);
WINLIB_API void default_help_function(const char* arg0,const char* subcmd, int ec, popt_cmd_t pmaincmd,  const char* fmt, ...);
WINLIB_API char* help_usage(const char* arg0,const char* subcmd, popt_cmd_t pmaincmd, const char* fmt, ...);
WINLIB_API char* help_usagev(const char* arg0,const char* subcmd, popt_cmd_t pmaincmd,  const char* fmt, va_list ap);

WINLIB_API pextargs_state_t alloc_extargs_state(void);
WINLIB_API void free_extargs_state(pextargs_state_t* ppextstate);

WINLIB_API int parse_param_smart_ex(int argc, char* argv[], popt_cmd_t pmaincmd, void* popt, pextargs_state_t* ppoutstate, int* pprio,pextargs_options_t pargoptions);
WINLIB_API void extargs_deinit(void);


#define parse_param_smart(argc,argv,st_main_cmds,popt,ppoutstate,prio,pargoptions)  parse_param_smart_ex(argc,argv,st_main_cmds,popt,ppoutstate,prio,pargoptions)
#define EXTARGS_PARSE(argc,argv,popt,pextstate) parse_param_smart(argc,argv,st_main_cmds,popt,&(pextstate),NULL,NULL)

#ifdef __cplusplus
};
#endif


#endif /*__EXTARGS_H__*/