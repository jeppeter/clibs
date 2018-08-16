#include <ux_proc.h>


#define  CHLD_IDX       0
#define  PARENT_IDX     1

#define  STDIN_PIPE     0x1
#define  STDOUT_PIPE    0x2
#define  STDERR_PIPE    0x4

#define  STDIN_NULL     0x10
#define  STDOUT_NULL    0x20
#define  STDERR_NULL    0x40

#define  NULL_FILE      "/dev/null"

typedef struct __proc_comm
{
	pid_t m_pid;
	int m_stdin[2];
	int m_stdout[2];
	int m_stderr[2];
} proc_comm_t,*pproc_comm_t;

void __close_pipefd(int fd[])
{
	int ret;
	if (fd[CHLD_IDX] >= 0) {
		ret = close(fd[CHLD_IDX]);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("close [%d] error[%d]",fd[CHLD_IDX], ret);
		}
	}
	fd[CHLD_IDX] = -1;

	if (fd[PARENT_IDX] >= 0) {
		ret = close(fd[PARENT_IDX]);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("close [%d] error[%d]", fd[PARENT_IDX], ret);
		}
	}
	fd[PARENT_IDX] = -1;
	return;

}

int __set_nonblock(int fd)
{
	int flags;
	SETERRNO(0);
	flags = fcntl(fd,F_GETFL,0);
	if (flags < 0)  {
		GETERRNO_DIRECT(ret);
		if (ret < 0) {
			ERROR_INFO("can not get fd[%d] flag error[%d]", fd, ret);
			goto fail;
		}
	}
	ret = fcntl(fd,F_SETFL, flags | O_NONBLOCK);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set read fd [%d] nonblock error[%d]", fd,  ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __pipefd(int *rfd,int* wfd)
{
	int ret;
	int fd[2] = {-1,-1};
	int flags;
	if (rfd == NULL || wfd == NULL) {
		ret = -EINVAL;
		goto fail;
	}
	ret = pipe(fd);
	if (ret <0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __set_nonblock(fd[0]);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __set_nonblock(fd[1]);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	*rfd = fd[0];
	*wfd = fd[1];
	return 0;
fail:
	if (fd[0] >= 0) {
		close(fd[0]);
	}
	fd[0] = -1;
	if (fd[1] >= 0) {
		close(fd[1]);
	}
	fd[1] = -1;
	SETERRNO(ret);
	return ret;
}

void __close_proc_comm(pproc_comm_t pproc)
{
	int i;
	int sig = SIGINT;
	int ret;
	int status;
	if (pproc->m_pid >= 0) {
		for (i=0;;i++) {
			if (i>= 5) {
				sig = SIGTERM; 
			}
			if (i >= 10) {
				sig = SIGKILL;
			}

			ret = waitpid(pproc->m_pid, &status,WNOHANG);
			if (ret < 0) {
				GETERRNO(ret);
				if (ret == -ECHLD) {
					DEBUG_INFO("child not [%d]", pproc->m_pid);
					break;
				}
				ERROR_INFO("can not wait [%d] error[%d]", pproc->m_pid,ret);
			} else {
				if (WIFEXITED(status) || WIFSIGNALED(status)) {
					break;
				}
			}

			ret= kill(pproc->m_pid , sig);
			if (ret < 0){
				GETERRNO(ret);
				ERROR_INFO("can not kill [%d] [%d] error[%d]", pproc->m_pid, sig,ret);
			}
			/*sleep 50 mill second*/
			if ((i % 20) == 0 && i > 0) {
				DEBUG_INFO("wait [%d] at time [%d]", pproc->m_pid, i);
			}
			usleep(50000);
		}
	}
	pproc->m_pid = -1;
	__close_pipefd(pproc->m_stdin);
	__close_pipefd(pproc->m_stdout);
	__close_pipefd(pproc->m_stderr);
	return;
}

void __free_proc_comm(pproc_comm_t *ppproc)
{
	if (ppproc && *ppproc) {
		__close_proc_comm(*ppproc);
		free(*ppproc);
		*ppproc = NULL;
	}
	return ;
}

void __init_pipefd(int fd[])
{
	fd[CHLD_IDX] = -1;
	fd[PARENT_IDX] = -1;
	return;
}

pproc_comm_t __alloc_proc(void)
{
	pproc_comm_t pproc=NULL;
	int ret;

	pproc = malloc(sizeof(*pproc));
	if (pproc == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc [%d] error[%d]", sizeof(*pproc),ret);
		goto fail;
	}
	memset(pproc,0, sizeof(*pproc));
	pproc->m_pid = -1;
	__init_pipefd(pproc->m_stdin);
	__init_pipefd(pproc->m_stdout);
	__init_pipefd(pproc->m_stderr);
	return pproc;
fail:
	SETERRNO(ret);
	return NULL;
}

int __open_nullfd(int flags)
{
	int fd=-1;
	int ret;

	fd = open(NULL_FILE,flags);
	if (fd <0) {
		GETERRNO(ret);
		return ret;
	}

	return fd;
}

int __dup2_close(int *oldfd, int newfd)
{
	int ret;
	ret = dup2(*oldfd,newfd);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}
	close(*oldfd);
	*oldfd = -1;
	return 0;
}

pproc_comm_t __start_proc(int flags,char* prog[])
{
	int ret,res;
	pproc_comm_t pproc=NULL;
	int stdinnull=-1,stdoutnull=-1,stderrnull=-1;

	if (prog == NULL || prog[0] == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (((flags & STDIN_PIPE) && (flags & STDIN_NULL)) || 
		((flags & STDOUT_PIPE) && (flags & STDOUT_NULL)) ||
		((flags & STDERR_PIPE) && (flags & STDERR_NULL))) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pproc = __alloc_proc();
	if (pproc == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	if (flags  & STDIN_PIPE) {
		ret = __pipefd(&(pproc->m_stdin[CHLD_IDX]),&(pproc->m_stdin[PARENT_IDX]));
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (flags & STDOUT_PIPE) {
		ret = __pipefd(&(pproc->m_stdout[PARENT_IDX]), &(pproc->m_stdout[CHLD_IDX]));
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (flags & STDERR_PIPE) {
		ret = __pipefd(&(pproc->m_stderr[PARENT_IDX]), &(pproc->m_stderr[CHLD_IDX]));
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	pproc->m_pid = fork();
	if (pproc->m_pid == 0) {
		char* pcmdlines=NULL;
		int cmdsize=0;
		int i;
		/*this is child*/
		if (flags & STDIN_NULL) {
			stdinnull = __open_nullfd(O_RDONLY);
			if (stdinnull < 0) {
				ERROR_INFO("can not open [%s] for READ ONLY", NULL_FILE);
				exit(3);
			}
		}

		if (flags & STDOUT_NULL) {
			stdoutnull = __open_nullfd(O_WRONLY);
			if (stdinnull < 0) {
				ERROR_INFO("can not open [%s] for WRITE ONLY", NULL_FILE);
				exit(3);
			}
		}

		if (flags & STDERR_NULL) {
			stderrnull = 	__open_nullfd(O_WRONLY);
			if (stdinnull < 0) {
				ERROR_INFO("can not open [%s] for WRITE ONLY", NULL_FILE);
				exit(3);
			}			
		}

		for (i=0;i<1024;i++) {
			if (i == pproc->m_stdin[CHLD_IDX] ||
				i == pproc->m_stdout[CHLD_IDX] || 
				i == pproc->m_stderr[CHLD_IDX] ||
				i == stdinnull ||
				i == stdoutnull ||
				i == stderrnull ||
				i == STDIN_FILENO ||
				i == STDOUT_FILENO ||
				i == STDERR_FILENO) {
				/*these fileno not close*/
				continue;
			}
			/*close all others*/
			close(i);
		}

		if (flags & STDIN_PIPE) {
			ret = __dup2_close(&(pproc->m_stdin[CHLD_IDX]),STDIN_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 STDIN [%d] error[%d]", pproc->m_stdin[CHLD_IDX],ret);
				exit(4);
			}
		}

		if (flags & STDOUT_PIPE) {
			ret = __dup2_close(&(pproc->m_stdout[CHLD_IDX]), STDOUT_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 STDOUT [%d] error[%d]", pproc->m_stdout[CHLD_IDX],ret);
				exit(4);				
			}
		}

		if (flags & STDERR_PIPE) {
			ret = __dup2_close(&(pproc->m_stderr[CHLD_IDX]), STDERR_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 STDERR [%d] error[%d]", pproc->m_stderr[CHLD_IDX], ret);
				exit(4);
			}
		}

		if (flags & STDIN_NULL) {
			ret = __dup2_close(&stdinnull,STDIN_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 stdin null [%d] error[%d]", stdinnull, ret);
				exit(4);				
			}
		}

		if (flags & STDOUT_NULL) {
			ret = __dup2_close(&stdoutnull,STDOUT_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 stdout null [%d] error[%d]", stdoutnull, ret);
				exit(4);				
			}
		}

		if (flags & STDERR_NULL) {
			ret = __dup2_close(&stderrnull,STDERR_FILENO);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("can not dup2 stderr null [%d] error[%d]", stderrnull, ret);
				exit(4);
			}
		}

		/*now exec call*/
		execvp(prog[0], prog);
		GETERRNO(res);
		for (i=0;prog[i] != NULL;i++) {
			if (i>0) {
				ret = append_snprintf_safe(&pcmdlines,&cmdsize," %s",prog[i]);
			} else {
				ret = snprintf_safe(&pcmdlines,&cmdsize,"%s", prog[i]);
			}
			if (ret < 0) {
				exit(5);
			}
		}
		ERROR_INFO("can not run [%s] error[%d]", pcmdlines,res);
		snprintf_safe(&pcmdlines,&cmdsize,NULL);
		exit(6);
	} else if (pproc->m_pid < 0) {
		GETERRNO(ret);
		ERROR_INFO("fork error[%d]",ret);
		goto fail;
	}

	return pproc;
fail:
	__free_proc_comm(&pproc);
	SETERRNO(ret);
	return NULL;
}

int __write_nonblock(int fd,char* pbuf,int bufsize, int* pispending)
{
	int ret;
	ret = write(fd,pbuf,bufsize);
	if (ret < 0) {
		GETERRNO(ret);
	}
}

int __read_nonbloc(int fd, char* pbuf,int bufsize, int* pispending)
{

}

#define   MINI_BUFSIZE         1024

int __inner_run(int evtfd,pproc_comm_t pproc,char* pin ,int insize, char** ppout, int *poutsize , char** pperr, int *perrsize,int *pexitcode,int timeout)
{
	int fd[4];
	int fdnum =0;
	struct timeval tm;
	uint64_t sticks,cticks;
	char* pretout=NULL;
	int outsize=0, outlen=0;
	char* preterr=NULL;
	int errsize=0, errlen=0;
	int ret;
	int status;
	int inlen = 0;
	int exitcode=0;

	if (ppout != NULL && poutsize == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (pperr != NULL && perrsize == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ppout != NULL) {
		pretout = *ppout;
		outsize = *poutsize;
		if (pretout == NULL || outsize < MINI_BUFSIZE)	 {
			if (outsize < MINI_BUFSIZE) {
				outsize = MINI_BUFSIZE;
			}
			pretout = malloc(outsize);
			if (pretout == NULL) {
				GETERRNO(ret);
				ERROR_INFO("alloc %d error[%d]", outsize, ret);
				goto fail;
			}
		}
		memset(pretout, 0 ,outsize);
	}
	
	if (pperr != NULL) {
		preterr = *pperr;
		errsize = *perrsize;
		if (preterr == NULL || errsize < MINI_BUFSIZE) {
			if (errsize < MINI_BUFSIZE) {
				errsize = MINI_BUFSIZE;
			}
			preterr = malloc(errsize);
			if (preterr == NULL) {
				GETERRNO(ret);
				ERROR_INFO("alloc %d error[%d]", errsize, ret);
				goto fail;
			}
		}
		memset(preterr, 0 ,errsize);
	}

	sticks = get_cur_ticks();
	while(1) {
		/*first to wait for the status*/
		ret= waitpid(pproc->m_pid, &status,WNOHANG);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("wait [%d] error[%d]", pproc->m_pid, ret);
			goto fail;
		}
		if (WIFSIGNALED(status) ) {
			/**/
			exitcode = WEXITSTATUS(status);
			break;
		} else if (WIFEXITED(status)) {
			exitcode = WTERMSIG(status);
			break;
		}

		if (pin && inlen < insize) {

		}
	}
}

int run_cmd_event_output(int exitfd, char* pin,  int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{

}