#include <extargs.h>
#include <cmn_args.h>
#include <cmn_fileop.h>
#include <cmn_output_debug.h>
#include <cmn_strop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jvalue_ex.h>

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
int queryobject_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

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
        ERROR_INFO( "can not pretty out error[%d]\n", ret);
        goto fail;
    }

    ret = snprintf_safe(&poutbuf, &outsize, "%s\n", poutstr);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO( "can not add line error[%d]\n", ret);
        goto fail;
    }
    outlen = ret;

    ret = write_output(pargs, poutbuf, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO( "can not write output error[%d]\n", ret);
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
        ERROR_INFO( "must at least 2 args for addstring[%d]\n", argcnt);
        goto out;
    }
    ret = read_input(pargs, &preadbuf, &readsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO( "can not read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
        goto out;
    }

    fprintf(stdout, "read json\n-----------------\n%s\n+++++++++++++++++\n", preadbuf);

    pj = jvalue_read(preadbuf, (unsigned int*)&retlen);
    if (pj == NULL) {
        GETERRNO(ret);
        ERROR_INFO( "parse error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < argcnt ; i += 2) {
        pkey = parsestate->leftargs[i];
        pstr = parsestate->leftargs[i + 1];

        ret = jobject_put_string(pj, pkey, pstr);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO( "can not insert key[%s]=[%s] error[%d]\n", pkey, pstr, ret);
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
    free_jvalue(&pj);
    free_input(pargs, &preadbuf, &readsize);
    SETERRNO(ret);
    return ret;
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
        ERROR_INFO( "must at least 2 args for addstring[%d]\n", argcnt);
        goto out;
    }
    ret = read_input(pargs, &preadbuf, &readsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO( "can not read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
        goto out;
    }

    fprintf(stdout, "read json\n-----------------\n%s\n+++++++++++++++++\n", preadbuf);

    pj = jvalue_read(preadbuf, (unsigned int*)&retlen);
    if (pj == NULL) {
        GETERRNO(ret);
        ERROR_INFO( "parse error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < argcnt ; i += 2) {
        pkey = parsestate->leftargs[i];
        pstr = parsestate->leftargs[i + 1];

        ret = add_jobject(pj, pkey, pstr);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO( "can not insert key[%s]=[%s] error[%d]\n", pkey, pstr, ret);
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
    free_jvalue(&pj);
    free_input(pargs, &preadbuf, &readsize);
    SETERRNO(ret);
    return ret;
}

jvalue* __make_new_value(char* pkey, jvalue* getpj)
{
    jvalue* basepj = NULL, *clonepj = NULL, *oldpj = NULL;
    int ret;
    basepj = jobject_create();
    if (basepj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create object for [%s] error[%d]", pkey,ret);
        goto fail;
    }

    clonepj = jvalue_clone(getpj);
    if (clonepj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("clone value for [%s] error[%d]", pkey,ret);
        goto fail;
    }

    ret = 0;
    oldpj = jobject_put(basepj, pkey, clonepj, &ret);
    ASSERT_IF(oldpj == NULL);
    if (ret != 0) {
        if (ret > 0) {
            ret = -ret;
        }
        ERROR_INFO("put [%s] error[%d]",pkey,ret);
        goto fail;
    }
    clonepj = NULL;

    return basepj;
fail:
    if (clonepj != NULL) {
        jvalue_destroy(clonepj);
    }
    clonepj = NULL;
    if (basepj != NULL) {
        jvalue_destroy(basepj);
    }
    basepj = NULL;
    SETERRNO(ret);
    return NULL;
}

int __output_value(FILE* fp,char* pkey,jvalue* getpj)
{
    jvalue* basepj = NULL;
    char* pstr = NULL;
    int ret;
    unsigned int outsize;

    basepj = __make_new_value(pkey,getpj);
    if (basepj == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pstr = jvalue_write_pretty(basepj,&outsize);
    if (pstr == NULL) {
        GETERRNO(ret);
        ERROR_INFO("out [%s] error[%d]",pkey, ret);
        goto fail;
    }

    fprintf(fp, "%s\n",pstr);

    if (pstr != NULL) {
        free(pstr);
    }
    pstr = NULL;    

    free_jvalue(&basepj);
    return 0;
fail:
    if (pstr != NULL) {
        free(pstr);
    }
    pstr = NULL;
    free_jvalue(&basepj);
    SETERRNO(ret);
    return ret;
}

int queryobject_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    args_options_t * pargs = (args_options_t*) popt;
    char* preadbuf = NULL;
    int readsize = 0;
    unsigned int retlen = 0;
    int argcnt = 0;
    jvalue* pj = NULL;
    char* pkey = NULL;
    jvalue* getpj = NULL;
    int i;

    argc = argc;
    argv = argv;

    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 1) {
        ret = -CMN_EINVAL;
        ERROR_INFO("need at least one key");
        goto out;
    }

    ret = read_input(pargs, &preadbuf, &readsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    fprintf(stdout, "read %s\n------------\n%s\n+++++++++++\n", pargs->m_input ? pargs->m_input : "stdin", preadbuf);

    pj = jvalue_read(preadbuf, &retlen);
    if (pj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("parse error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < argcnt; i++) {
        pkey = parsestate->leftargs[i];
        getpj = jobject_get(pj, pkey);
        if (getpj == NULL) {
            fprintf(stdout, "can not find [%s]\n", pkey);
            continue;
        }

        ret = __output_value(stdout,pkey,getpj);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
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
        ERROR_INFO( "can not copy args ret[%d]\n", ret);
        goto out;
    }

    ret = EXTARGS_PARSE(argc, args, &argsoption, pextstate);
    //ret = parse_param_smart(argc, args, st_main_cmds, &argsoption, &pextstate, NULL, NULL);
    if (ret < 0) {
        ERROR_INFO( "could not parse error(%d)", ret);
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