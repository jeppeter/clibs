#include <ux_output_debug.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>

typedef struct __args_options {
	int m_verbose;
	char* m_fmtstr;
	char** m_args;
}args_options_t,*pargs_options_t;

#include "args_options.cpp"

int debug_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int ret;
	int cnt=0;
	int i;
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