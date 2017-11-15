#include <win_fileop.h>
#include <win_output_debug.h>
#include <win_args.h>
#include <extargs.h>
#include <win_err.h>
#include <win_proc.h>
#include <win_window.h>

typedef struct __args_options {
	int m_verbose;
	char* m_classname;
}args_options_t,*pargs_options_t;

int mktemp_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);
int readencode_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);
int pidargv_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);
int findwindow_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);
int fullpath_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt);

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

int pidargv_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	char** ppargv=NULL;
	int argvsize=0;
	int pid=-1;
	int ret = 0;
	int totalret = 0;
	int i,j;
	argv = argv;
	argc = argc;
	popt = popt;
	if (parsestate->leftargs != NULL) {
		for (i=0;parsestate->leftargs[i]!= NULL;i++) {
			pid = atoi(parsestate->leftargs[i]);
			ret = get_pid_argv(pid,&ppargv,&argvsize);
			if (ret < 0) {
				fprintf(stderr, "can not get [%d] error[%d]\n",pid,ret);
				totalret = ret;
				continue;
			}
			for (j=0;j<ret;j++) {
				fprintf(stdout, "[%d][%d]=[%s]\n",pid,j,ppargv[j]);
			}
		}
	}
	get_pid_argv(-1,&ppargv,&argvsize);
	return totalret;
}

int findwindow_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int i,j;
	int pid=-1;
	int ret=0;
	int totalret = 0;
	HWND* pwnd=NULL;
	pargs_options_t poption = (pargs_options_t) popt;
	argv = argv;
	argc = argc;
	int wndsize=0;
	if (parsestate->leftargs != NULL) {
		for (i=0;parsestate->leftargs[i] != NULL;i++) {
			pid = atoi(parsestate->leftargs[i]);
			ret = get_win_handle_by_classname(poption->m_classname,pid,&pwnd,&wndsize);
			if (ret < 0) {
				GETERRNO(ret);
				totalret = ret;
				fprintf(stderr,"can not get [%d] class[%s] error[%d]\n",pid,poption->m_classname,ret);
				continue;
			}
			fprintf(stdout,"get [%d] class [%s]:",pid,poption->m_classname);
			for (j=0;j<ret;j++) {
				if ((j%5) == 0) {
					fprintf(stdout,"\n    ");
				}
				fprintf(stdout," 0x%p",pwnd[j]);				
			}
			fprintf(stdout, "\n");
		}

	} else {
		ret = get_win_handle_by_classname(poption->m_classname,-1,&pwnd,&wndsize);
		if (ret < 0) {
			GETERRNO(ret);
			totalret = ret;
			fprintf(stderr, "can not get [%s] on pid[%d] error[%d]\n",poption->m_classname,pid,ret);
			goto out;
		}
		fprintf(stdout,"get class [%s]:",poption->m_classname);
		for (j=0;j<ret;j++) {
			if ((j%5) == 0) {
				fprintf(stdout,"\n    ");
			}
			fprintf(stdout," 0x%p",pwnd[j]);
		}
		fprintf(stdout, "\n");

	}

	ret = totalret;
out:
	get_win_handle_by_classname(NULL,-1,&pwnd,&wndsize);
	SETERRNO(-ret);
	return ret;
}

int fullpath_handler(int argc,char* argv[],pextargs_state_t parsestate, void* popt)
{
	int ret;
	char* pfullpath=NULL;
	int fullsize=0;
	int i;
	argv = argv;
	argc = argc;
	popt = popt;
	if (parsestate->leftargs != NULL) {
		for (i=0;parsestate->leftargs[i] != NULL; i ++) {
			ret = get_full_path(parsestate->leftargs[i],&pfullpath,&fullsize);
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			}
			fprintf(stdout,"[%d][%s] => [%s]\n",i,parsestate->leftargs[i],pfullpath);
		}
	}

	ret = 0;
out:
	get_full_path(NULL,&pfullpath,&fullsize);	
	SETERRNO(-ret);
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