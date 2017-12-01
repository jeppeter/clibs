#include <ux_output_debug.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>

#include <string.h>

typedef struct __args_options {
	int m_verbose;
}args_options_t,*pargs_options_t;

int debug_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);

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
		ERROR_INFO("init [%d] verbose error[%d]",pargs->m_verbose, ret);
		SETERRNO(ret);
		return ret;
	}
	return 0;
}

int debug_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}
	DEBUG_INFO("hello world");
	ERROR_INFO("hello world");
	return 0;
}


int main(int argc,char* argv[])
{
	char** args=NULL;
	int ret = 0;
	args_options_t argsoption;
	pextargs_state_t pextstate = NULL;

	memset(&argsoption, 0, sizeof(argsoption));

	args = copy_args(argc,argv);
	if (args == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not copy args error[%d]\n",ret);
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