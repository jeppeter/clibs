#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_output_debug.h>
#include <ux_fileop.h>
#include <ux_strop.h>
#include <jvalue.h>


#include <authenticode.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>


typedef struct __args_options {
    char* m_input;
    char* m_output;
    char* m_ecpriv;
    char* m_ecparam;
    char* m_ecpub;
    char* m_convform;
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
int asn1objdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1enumerateenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1strenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1seqenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1seqdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1timeenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int asn1bignumenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int aes256cfbenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int aes256cfbdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcstrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcserialobjenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcserialobjdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spclinkenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spclinkdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcopusinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcopusinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcattrvalenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcattrvaldec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int algoidentenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int algoidentdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int diginfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int diginfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcinddatacontentenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcinddatacontentdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int cataauthattrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int cataauthattrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int catainfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int catainfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int msctlconenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int msctlcondec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcpeimgenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcpeimgdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcsipinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcsipinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int msgimpprnenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int msgimpprndec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int timestampreqblobenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int timestampreqblobdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int timestamprqstenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int timestamprqstdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pkistatusinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pkistatusinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ia5strset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int generalnameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int generalnamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int othernameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int othernamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int edipartynameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int edipartynamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int x509nameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int x509namedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int timestamprespdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcasn1codeenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int spcasn1codedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int x509algrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int x509algrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ndefcloseenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ndefclosedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pkcs7vfy_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecprivkeyenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecprivkeydec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecpkparamsenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecpkparamsdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecx9pentenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecx9pentdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecchartwoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecchartwodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecfieldidenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecfieldiddec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int eccurveenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int eccurvedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecparamsenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecparamsdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecgen_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecsignbase_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecvfybase_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bnbinmul_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int binadd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int binmulmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int binmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bininv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int randprivate_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int randmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bnmodfixup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ecpubload_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bndivmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bnsqrtmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bnmodsqrquad_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int montto_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int montfrom_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int montmul_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int modlshift_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int modexpmont_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bnlshift_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);


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

void dump_buffer_out(FILE* fp, uint8_t* pbuf, int len, const char* fmt, ...)
{
    int i, lasti;
    if (fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, " ");
    }

    fprintf(fp, "buffer [%p] len[0x%x:%d]", pbuf, len, len);
    for (i = 0, lasti = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                fprintf(fp, "    ");
                while (lasti < i) {
                    if (pbuf[lasti] >= 0x20 && pbuf[lasti] <= 0x7e) {
                        fprintf(fp, "%c", pbuf[lasti]);
                    } else {
                        fprintf(fp, ".");
                    }
                    lasti ++;
                }
            }
            fprintf(fp, "\n0x%08x:", i);
        }
        fprintf(fp, " 0x%02x", pbuf[i]);
    }

    if (lasti != i) {
        while ((i % 16) != 0) {
            fprintf(fp, "     ");
            i ++;
        }
        fprintf(fp, "    ");
        while (lasti < len) {
            if (pbuf[lasti] >= 0x20 && pbuf[lasti] <= 0x7e) {
                fprintf(fp, "%c", pbuf[lasti]);
            } else {
                fprintf(fp, ".");
            }
            lasti ++;
        }
    }
    fprintf(fp,"\n");
    return;
}

int hex_value(char v,int* perr)
{
    int retval = 0;
    if (v >= '0' && v <= '9') {
        retval = v - '0';
    } else if (v >= 'a' && v <= 'f') {
        retval = v - 'a' + 10;
    } else if (v >= 'A' && v <= 'F') {
        retval = v - 'A' + 10;
    } else {
        if (perr) {
            *perr = 1;
        }
    }
    return retval;
}


int parse_hex_string(const char* hexstr,uint8_t** ppv8,int* psize)
{
    int ret;
    int slen = 0;
    int idx;
    int didx;
    uint8_t* pretv8=NULL;
    int retsize=0;
    int retlen=0;
    int errnum = 0;
    if (hexstr == NULL) {
        if (ppv8 && *ppv8) {
            free(*ppv8);
            *ppv8 = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppv8 == NULL || psize == NULL) {
        ret=  -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    if (*ppv8 == NULL && *psize != 0) {
        ret=  -EINVAL;
        SETERRNO(ret);
        return ret;     
    }

    pretv8 = *ppv8;
    retsize = *psize;

    slen = (int)strlen(hexstr);
    if (slen > 0) {
        idx = 0;
        didx = 0;
        retlen = slen / 2;
        if ((slen % 2) != 0){
            retlen ++;
            idx = 1;
        }
        if (retlen > retsize) {
            retsize = retlen;
            pretv8 = (uint8_t*)malloc(retlen);
            if (pretv8 ==NULL) {
                GETERRNO(ret);
                goto fail;
            }
        }
        memset(pretv8,0,retsize);

        if (idx > 0) {
            pretv8[didx] = hex_value(hexstr[0],&errnum);
            didx = 1;
        }

        while (idx < slen) {
            pretv8[didx] |= (hex_value(hexstr[idx],&errnum) << 4);
            pretv8[didx] |= hex_value(hexstr[idx+1],&errnum);
            idx += 2;
            didx += 1;
        }
    }

    if (errnum != 0) {
        ret = -EINVAL;
        goto fail;
    }

    if (*ppv8 && *ppv8 != pretv8) {
        free(*ppv8);
    }
    *ppv8 = pretv8;
    *psize = retsize;
    return retlen;
fail:
    if (pretv8 && pretv8 != *ppv8) {
        free(pretv8);
    }
    pretv8 = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

#include "bntest.cpp"
#include "peauth.cpp"
#include "asn1comp.cpp"
#include "pkcs7.cpp"
#include "aes.cpp"
#include "randtest.cpp"
#include "ossldump.cpp"
#include "ecdump.cpp"

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