#include <win_fileop.h>
#include <win_output_debug.h>
#include <win_args.h>
#include <extargs.h>
#include <win_err.h>

typedef struct __args_options {
	int m_verbose;
}args_options_t,*pargs_options_t;

int mktemp_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);
int readencode_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);

#include "args_options.cpp"

int mktemp_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int i;
	char* templstr=NULL;
	int templsize=0;
	int ret = 0;
	argv = argv;
	argc = argc;
	popt = popt;
	if (parsestate->leftargs != NULL) {
		for (i=0;parsestate->leftargs[i] != NULL ; i++) {
			ret = mktempfile_safe(parsestate->leftargs[i],&templstr,&templsize);
			//ret = 0;
			if (ret < 0) {
				fprintf(stderr, "can not parse [%s] error(%d)\n",parsestate->leftargs[i],ret);
				goto out;
			}
			fprintf(stdout,"[%d]%s => %s\n",i,parsestate->leftargs[i],templstr);
		}
	}
out:	
	mktempfile_safe(NULL,&templstr,&templsize);
	return ret;
}

int readencode_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int i;
	char* templstr=NULL;
	int templsize = 0;
	int ret=0;
	argv = argv;
	argc = argc;
	popt = popt;
	if (parsestate->leftargs != NULL) {
		for (i=0;parsestate->leftargs[i] != NULL;i++) {
			ret = read_file_encoded(parsestate->leftargs[i],&templstr,&templsize);
			if (ret < 0) {
				fprintf(stderr,"can not read [%s] error[%d]\n",parsestate->leftargs[i],ret);
				goto out;
			}
			fprintf(stdout, "%s\n----------------------\n%s\n+++++++++++++++++++++++++\n",parsestate->leftargs[i],templstr);
		}
	}
out:
	read_file_encoded(NULL,&templstr,&templsize);
	return ret;
}

int main(int argc, char* argv[])
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