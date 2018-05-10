#include <extargs.h>
#include <cmn_args.h>
#include <cmn_fileop.h>
#include <cmn_output_debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct __args_options {
    int m_verbose;
    char* m_input;
    char* m_output;
} args_options_t, *pargs_options_t;

#ifdef __cplusplus
extern "C" {
#endif

int addstring_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

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

int read_input(pargs_options_t pargs, char** ppoutbuf,int *pbufsize)
{
	if (pargs == NULL) {
        SETERRNO(-1);
		return -1;
	}
	if (pargs->m_input == NULL) {
		return read_stdin_whole(0,ppoutbuf,pbufsize);
	}

	return read_file_whole(pargs->m_input,ppoutbuf,pbufsize);
}

void free_input(pargs_options_t pargs, char** ppoutbuf, int *pbufsize)
{
    if (pargs == NULL) {
        return;
    }
    if (pargs->m_input == NULL) {
        read_stdin_whole(1,ppoutbuf,pbufsize);
        return;
    }
    read_file_whole(NULL,ppoutbuf,pbufsize);
    return;
}


int addstring_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	args_options_t * pargs= (args_options_t*) popt;
	int ret;
	char* preadbuf=NULL;
	int readsize=0;
	int readlen=0;
    int argcnt=0;

    argc = argc;
    argv = argv;

	ret = init_log_verbose(pargs);
	if (ret < 0){
		goto out;
	}


    if (parsestate->leftargs == NULL) {
        while(parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -CMN_EINVAL;
        fprintf(stderr,"must at least 2 args for addstring\n");
        goto out;
    }

	ret = read_input(pargs,&preadbuf,&readsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr,"can not read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}

    readlen = ret;
	

out:
	free_input(pargs,&preadbuf,&readsize);
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