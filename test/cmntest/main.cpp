#include <extargs.h>
#include <cmn_args.h>
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

int read_stdin_buffer(FILE* fp,char** ppoutbuf,int *pbufsize)
{
	int retlen=0;
	char* pretbuf=NULL;
	int retsize=0;
	char* ptmpbuf=NULL;
	int ret;

	if (fp == NULL) {
		if (ppoutbuf != NULL) {
			if (*ppoutbuf != NULL) {
				free(*ppoutbuf);
			}
			*ppoutbuf = NULL;
		}
		if (pbufsize != NULL) {
			*pbufsize = 0;
		}
		return 0;
	}

	if (ppoutbuf == NULL || pbufsize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	while(1) {
		
	}

fail:
	if (ptmpbuf != NULL) {
		free(ptmpbuf);
	}
	ptmpbuf = NULL;
	if (pretbuf != NULL && pretbuf != *ppoutbuf) {
		free(pretbuf);
	}
	pretbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int addstring_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	return 0;
}

#include "args_options.cpp"

int main(int argc,char* argv[])
{
	char** args=NULL;
	args_options_t argsoption;
    pextargs_state_t pextstate = NULL;
	int ret;

	memset(&argsoption, 0, sizeof(argsoption));
	args = copy_args(argc,argv);
	if (args == NULL) {
		GETERRNO(ret);
		fprintf(stderr,"can not copy args ret[%d]\n",ret);
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