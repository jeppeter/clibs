#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_output_debug.h>
#include <ux_fileop.h>


#include <authenticode.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef struct __args_options {
    char* m_input;
    char* m_output;
    int m_verbose;
} args_options_t, *pargs_options_t;

#ifdef __cplusplus
extern "C" {
#endif

int peauth_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pkcs7octstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pkcs7dump_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1intenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1octstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1objenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1enumerateenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1strenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1seqenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1seq2enc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

#ifdef __cplusplus
};
#endif


#define  GET_OPT_TYPE(num, desc, typeof)                                          \
do{                                                                               \
    char* __pendptr;                                                              \
    uint64_t __num;                                                               \
    if (parsestate->leftargs &&                                                   \
        parsestate->leftargs[idx] != NULL) {                                      \
        ret = parse_number(parsestate->leftargs[idx],&__num,&__pendptr);          \
        if (ret < 0) {                                                            \
            GETERRNO(ret);                                                        \
            fprintf(stderr,"%s error[%d]\n", desc, ret);                          \
            goto out;                                                             \
        }                                                                         \
        num = (typeof)__num;                                                      \
        idx ++;                                                                   \
    }                                                                             \
} while(0)

#define  GET_OPT_NUM64(num,desc)          GET_OPT_TYPE(num,desc, uint64_t)
#define  GET_OPT_INT(num, desc)           GET_OPT_TYPE(num,desc,int)


#include "args_options.cpp"

int init_log_verbose(pargs_options_t pargs)
{
    int loglvl = BASE_LOG_ERROR;
    int ret;
    if (pargs->m_verbose <= 0) {
        loglvl = BASE_LOG_ERROR;
    } else if (pargs->m_verbose == 1) {
        loglvl = BASE_LOG_WARN;
    } else if (pargs->m_verbose == 2) {
        loglvl = BASE_LOG_INFO;
    } else if (pargs->m_verbose == 3) {
        loglvl = BASE_LOG_DEBUG;
    } else {
        loglvl = BASE_LOG_TRACE;
    }
    ret = INIT_LOG(loglvl);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("init [%d] verbose error[%d]", pargs->m_verbose, ret);
        SETERRNO(ret);
        return ret;
    }
    return 0;
}

#include "peauth.cpp"
#include "pkcs7.cpp"

int main(int argc, char* argv[])
{
    char** args = NULL;
    int ret = 0;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;

    memset(&argsoption, 0, sizeof(argsoption));

    args = copy_args(argc, argv);
    if (args == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not copy args error[%d]\n", ret);
        goto out;
    }

    ret = EXTARGS_PARSE(argc, args, &argsoption, pextstate);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "could not parse error(%d)", ret);
        goto out;
    }

    ret = 0;
out:
    free_extargs_state(&pextstate);
    release_extargs_output(&argsoption);
    free_args(&args);
    extargs_deinit();
    return ret;
}