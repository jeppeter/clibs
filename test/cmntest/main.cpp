#include <extargs.h>
#include <cmn_args.h>
#include <cmn_fileop.h>
#include <cmn_output_debug.h>
#include <cmn_strop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jvalue.h>

typedef struct __args_options {
    int m_verbose;
    char* m_input;
    char* m_output;
} args_options_t, *pargs_options_t;

#ifdef __cplusplus
extern "C" {
#endif

int addstring_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int addobject_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

#ifdef __cplusplus
};
#endif

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

int read_input(pargs_options_t pargs, char** ppoutbuf, int *pbufsize)
{
    if (pargs == NULL) {
        SETERRNO(-1);
        return -1;
    }
    if (pargs->m_input == NULL) {
        return read_stdin_whole(0, ppoutbuf, pbufsize);
    }

    return read_file_whole(pargs->m_input, ppoutbuf, pbufsize);
}

int write_output(pargs_options_t pargs, char* poutbuf, int outsize)
{
    int ret;
    if (pargs == NULL) {
        ret = -CMN_EINVAL;
        SETERRNO(ret);
        return ret;
    }

    if (pargs->m_output != NULL) {
        return write_file_whole(pargs->m_output, poutbuf, outsize);
    }

    return write_out_whole(STDOUT_FILE_FLAG, poutbuf, outsize);
}

void free_input(pargs_options_t pargs, char** ppoutbuf, int *pbufsize)
{
    if (pargs == NULL) {
        return;
    }
    if (pargs->m_input == NULL) {
        read_stdin_whole(1, ppoutbuf, pbufsize);
        return;
    }
    read_file_whole(NULL, ppoutbuf, pbufsize);
    return;
}

int pretty_write_output(jvalue* pj, pargs_options_t pargs)
{
    char* poutstr = NULL;
    char* poutbuf = NULL ;
    int outsize = 0;
    int outlen = 0;
    int strsize = 0;
    int ret;

    poutstr = jvalue_write_pretty(pj, (unsigned int*)&strsize);
    if (poutstr == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not pretty out error[%d]\n", ret);
        goto fail;
    }

    ret = snprintf_safe(&poutbuf, &outsize, "%s\n", poutstr);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not add line error[%d]\n", ret);
        goto fail;
    }
    outlen = ret;

    ret = write_output(pargs, poutbuf, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not write output error[%d]\n", ret);
        goto fail;
    }

    snprintf_safe(&poutbuf, &outsize, NULL);
    if (poutstr != NULL) {
        free(poutstr);
    }
    poutstr = NULL;
    strsize = 0;
    outlen = 0;
    return ret;

fail:
    snprintf_safe(&poutbuf, &outsize, NULL);
    if (poutstr != NULL) {
        free(poutstr);
    }
    poutstr = NULL;
    strsize = 0;
    outlen = 0;
    SETERRNO(ret);
    return ret;
}


int addstring_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    args_options_t * pargs = (args_options_t*) popt;
    int ret;
    char* preadbuf = NULL;
    int readsize = 0;
    int retlen = 0;
    int argcnt = 0;
    jvalue* pj = NULL;
    char* pkey = NULL;
    char* pstr = NULL;
    int i;

    argc = argc;
    argv = argv;

    ret = init_log_verbose(pargs);
    if (ret < 0) {
        goto out;
    }


    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2 || (argcnt % 2) != 0) {
        ret = -CMN_EINVAL;
        fprintf(stderr, "must at least 2 args for addstring[%d]\n", argcnt);
        goto out;
    }
    ret = read_input(pargs, &preadbuf, &readsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
        goto out;
    }

    fprintf(stdout, "read json\n-----------------\n%s\n+++++++++++++++++\n", preadbuf);

    pj = jvalue_read(preadbuf, (unsigned int*)&retlen);
    if (pj == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "parse error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < argcnt ; i += 2) {
        pkey = parsestate->leftargs[i];
        pstr = parsestate->leftargs[i + 1];

        ret = jobject_put_string(pj, pkey, pstr);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not insert key[%s]=[%s] error[%d]\n", pkey, pstr, ret);
            goto out;
        }
    }

    ret = pretty_write_output(pj, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ret = 0;
out:
    if (pj != NULL) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    free_input(pargs, &preadbuf, &readsize);
    SETERRNO(ret);
    return ret;
}

int __add_object(jvalue* pj, char* pkey, char* value)
{
    jvalue* pinsertval = NULL;
    char* parsestr
    int ret = 0;
    jvalue* pjret = NULL;
    char* pretstr = NULL;
    uint64_t num = 0;
    int inum = 0;
    if (str_nocase_cmp(value, "null") == 0) {
        pinsertval = jnull_create();
    } else if (str_case_cmp(value, "false") == 0) {
        pinsertval = jbool_create(0);
    } else if (str_case_cmp(value, "true") == 0) {
        pinsertval = jbool_create(1);
    } else {
        ret = parse_int(value, &inum, &pretstr);
        if (ret >= 0) {
            if (pretstr != 0 && pretstr[0] == '\0') {
                pinsertval = jint_create(inum);
            }
        } else {
            ret = parse_number(value, &num, &pretstr);
            if (ret >= 0) {
                if (pretstr != NULL && pretstr[0] == '\0') {
                    pinsertval = jint64_create(num);
                }
            }
        }
    }
    if (pinsertval != NULL) {
        pjret = jobject_put(pj, pkey, pinsertval, &ret);
        if (pjret == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "insert value [%s] error[%d]\n", value, ret);
            jvalue_destroy(pinsertval);
            return ret;
        }
        jvalue_destroy(pinsertval);
        return 1;
    }

    /*now we do not detect whether the value is ,so we should use */


}

int addobject_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    args_options_t * pargs = (args_options_t*) popt;
    int ret;
    char* preadbuf = NULL;
    int readsize = 0;
    int retlen = 0;
    int argcnt = 0;
    jvalue* pj = NULL;
    char* pkey = NULL;
    char* pstr = NULL;
    int i;

    argc = argc;
    argv = argv;

    ret = init_log_verbose(pargs);
    if (ret < 0) {
        goto out;
    }


    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2 || (argcnt % 2) != 0) {
        ret = -CMN_EINVAL;
        fprintf(stderr, "must at least 2 args for addstring[%d]\n", argcnt);
        goto out;
    }
    ret = read_input(pargs, &preadbuf, &readsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
        goto out;
    }

    fprintf(stdout, "read json\n-----------------\n%s\n+++++++++++++++++\n", preadbuf);

    pj = jvalue_read(preadbuf, (unsigned int*)&retlen);
    if (pj == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "parse error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < argcnt ; i += 2) {
        pkey = parsestate->leftargs[i];
        pstr = parsestate->leftargs[i + 1];

        ret = jobject_put_string(pj, pkey, pstr);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not insert key[%s]=[%s] error[%d]\n", pkey, pstr, ret);
            goto out;
        }
    }

    ret = pretty_write_output(pj, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ret = 0;
out:
    if (pj != NULL) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    free_input(pargs, &preadbuf, &readsize);
    SETERRNO(ret);
    return ret;
}

#include "args_options.cpp"

int main(int argc, char* argv[])
{
    char** args = NULL;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;
    int ret;

    memset(&argsoption, 0, sizeof(argsoption));
    args = copy_args(argc, argv);
    if (args == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not copy args ret[%d]\n", ret);
        goto out;
    }

    ret = EXTARGS_PARSE(argc, args, &argsoption, pextstate);
    //ret = parse_param_smart(argc, args, st_main_cmds, &argsoption, &pextstate, NULL, NULL);
    if (ret < 0) {
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