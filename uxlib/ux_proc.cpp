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

typedef struct __proc_comm {
    pid_t m_pid;
    int m_stdin[2];
    int m_stdout[2];
    int m_stderr[2];
} proc_comm_t, *pproc_comm_t;

void __close_pipefd(int fd[])
{
    int ret;
    if (fd[CHLD_IDX] >= 0) {
        ret = close(fd[CHLD_IDX]);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("close [%d] error[%d]", fd[CHLD_IDX], ret);
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
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)  {
        GETERRNO_DIRECT(ret);
        if (ret < 0) {
            ERROR_INFO("can not get fd[%d] flag error[%d]", fd, ret);
            goto fail;
        }
    }
    ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

int __pipefd(int *rfd, int* wfd)
{
    int ret;
    int fd[2] = { -1, -1};
    int flags;
    if (rfd == NULL || wfd == NULL) {
        ret = -EINVAL;
        goto fail;
    }
    ret = pipe(fd);
    if (ret < 0) {
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
        for (i = 0;; i++) {
            if (i >= 5) {
                sig = SIGTERM;
            }
            if (i >= 10) {
                sig = SIGKILL;
            }

            ret = waitpid(pproc->m_pid, &status, WNOHANG);
            if (ret < 0) {
                GETERRNO(ret);
                if (ret == -ECHLD) {
                    DEBUG_INFO("child not [%d]", pproc->m_pid);
                    break;
                }
                ERROR_INFO("can not wait [%d] error[%d]", pproc->m_pid, ret);
            } else {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    break;
                }
            }

            ret = kill(pproc->m_pid , sig);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not kill [%d] [%d] error[%d]", pproc->m_pid, sig, ret);
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
    pproc_comm_t pproc = NULL;
    int ret;

    pproc = malloc(sizeof(*pproc));
    if (pproc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pproc), ret);
        goto fail;
    }
    memset(pproc, 0, sizeof(*pproc));
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
    int fd = -1;
    int ret;

    fd = open(NULL_FILE, flags);
    if (fd < 0) {
        GETERRNO(ret);
        return ret;
    }

    return fd;
}

int __dup2_close(int *oldfd, int newfd)
{
    int ret;
    ret = dup2(*oldfd, newfd);
    if (ret < 0) {
        GETERRNO(ret);
        return ret;
    }
    close(*oldfd);
    *oldfd = -1;
    return 0;
}

pproc_comm_t __start_proc(int flags, char* prog[])
{
    int ret, res;
    pproc_comm_t pproc = NULL;
    int stdinnull = -1, stdoutnull = -1, stderrnull = -1;

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
        ret = __pipefd(&(pproc->m_stdin[CHLD_IDX]), &(pproc->m_stdin[PARENT_IDX]));
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
        char* pcmdlines = NULL;
        int cmdsize = 0;
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

        for (i = 0; i < 1024; i++) {
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
            ret = __dup2_close(&(pproc->m_stdin[CHLD_IDX]), STDIN_FILENO);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not dup2 STDIN [%d] error[%d]", pproc->m_stdin[CHLD_IDX], ret);
                exit(4);
            }
        }

        if (flags & STDOUT_PIPE) {
            ret = __dup2_close(&(pproc->m_stdout[CHLD_IDX]), STDOUT_FILENO);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not dup2 STDOUT [%d] error[%d]", pproc->m_stdout[CHLD_IDX], ret);
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
            ret = __dup2_close(&stdinnull, STDIN_FILENO);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not dup2 stdin null [%d] error[%d]", stdinnull, ret);
                exit(4);
            }
        }

        if (flags & STDOUT_NULL) {
            ret = __dup2_close(&stdoutnull, STDOUT_FILENO);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not dup2 stdout null [%d] error[%d]", stdoutnull, ret);
                exit(4);
            }
        }

        if (flags & STDERR_NULL) {
            ret = __dup2_close(&stderrnull, STDERR_FILENO);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not dup2 stderr null [%d] error[%d]", stderrnull, ret);
                exit(4);
            }
        }

        /*now exec call*/
        execvp(prog[0], prog);
        GETERRNO(res);
        for (i = 0; prog[i] != NULL; i++) {
            if (i > 0) {
                ret = append_snprintf_safe(&pcmdlines, &cmdsize, " %s", prog[i]);
            } else {
                ret = snprintf_safe(&pcmdlines, &cmdsize, "%s", prog[i]);
            }
            if (ret < 0) {
                exit(5);
            }
        }
        ERROR_INFO("can not run [%s] error[%d]", pcmdlines, res);
        snprintf_safe(&pcmdlines, &cmdsize, NULL);
        exit(6);
    } else if (pproc->m_pid < 0) {
        GETERRNO(ret);
        ERROR_INFO("fork error[%d]", ret);
        goto fail;
    }

    return pproc;
fail:
    __free_proc_comm(&pproc);
    SETERRNO(ret);
    return NULL;
}

int __write_nonblock(int fd, char* pbuf, int bufsize, int* pispending)
{
    int ret;
    int writelen = 0;
    while (writelen < bufsize) {
        ret = write(fd, &(pbuf[writelen]), (bufsize - writelen));
        if (ret < 0) {
            GETERRNO(ret);
            if (ret == -EINTR) {
                continue;
            } else if (ret == -EAGAIN) {
                if (pispending) {
                    *pispending = 1;
                }
                return writelen;
            }
            ERROR_INFO("write [%d] error[%d]", writelen, ret);
            goto fail;
        }
        writelen += ret;
    }
    if (pispending) {
        *pispending = 0;
    }
    return writelen;
fail:
    SETERRNO(ret);
    return ret;
}

int __read_nonbloc(int fd, char* pbuf, int bufsize, int* pispending)
{
    int ret;
    int readlen = 0;
    while (readlen < bufsize) {
        ret = read(fd, &(pbuf[readlen]), bufsize - readlen);
        if (ret < 0) {
            GETERRNO(ret);
            if (ret == -EINTR) {
                continue;
            } else if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                if (pispending) {
                    *pispending = 1;
                }
                return readlen;
            }
            ERROR_INFO("read [%d] error[%d]", readlen, ret);
            goto fail;
        } else if (ret == 0) {
            /*that is read all*/
            break;
        }
        readlen += ret;
    }
    if (pispending) {
        *pispending = 0;
    }
    return readlen;
fail:
    SETERRNO(ret);
    return ret;
}

#define   MINI_BUFSIZE         1024
#define   MAX_MILLS            15000
int get_min(int a, int b)
{
    if (a > b) {
        return b;
    }
    return a;
}

#define  WRITE_WAIT(fdmem,ptrmem,memlen,memsize)                                       \
	do {                                                                               \
		if (pproc->fdmem[PARENT_IDX] >= 0) {                                           \
			ret = __write_nonblock(pproc->fdmem[PARENT_IDX],&(ptrmem[memlen]),         \
				(memsize - memlen), &pending);                                         \
			if (ret < 0) {                                                             \
				GETERRNO(ret);                                                         \
				ERROR_INFO("write %s error[%d]", #fdmem, ret);                         \
				goto fail;                                                             \
			}                                                                          \
			memlen += ret;                                                             \
			if (pending) {                                                             \
				fd[fdnum] = pproc->fdmem[PARENT_IDX];                                  \
				fdnum ++;                                                              \
				FD_SET(pproc->fdmem[PARENT_IDX],&wset);                                \
			} else {                                                                   \
				ASSERT_IF(memlen == memsize);                                          \
				__close_pipefd(pproc->fdmem);                                          \
			}                                                                          \
		}                                                                              \
	} while(0)

#define STDIN_WRITE_WAIT()  WRITE_WAIT(m_stdin,pin,inlen,insize)

#define  READ_EXPAND(fdmem,ptrmem,pptrmem, memlen,memsize,gotolabel)                   \
	do {                                                                               \
		if (pproc->fdmem[PARENT_IDX] >= 0) {                                           \
		gotolabel:                                                                     \
			ret = __read_nonbloc(pproc->fdmem[PARENT_IDX],&(ptrmem[memlen]),           \
					(memsize - memlen), &pending);                                     \
			if (ret < 0) {                                                             \
				GETERRNO(ret);                                                         \
				ERROR_INFO("read %s error[%d]", #fdmem, ret);                          \
				goto fail;                                                             \
			}                                                                          \
			memlen += ret;                                                             \
			if (pending) {                                                             \
				fd[fdnum] = pproc->fdmem[PARENT_IDX];                                  \
				fdnum ++;                                                              \
				FD_SET(pproc->fdmem[PARENT_IDX],&rset);                                \
			} else {                                                                   \
				if (ret == 0) {                                                        \
					__close_pipefd(pproc->fdmem);                                      \
				} else {                                                               \
					ASSERT_IF(memlen == memsize);                                      \
					memsize <<= 1;                                                     \
					ptmpbuf = malloc(memsize);                                         \
					if (ptmpbuf == NULL) {                                             \
						GETERRNO(ret);                                                 \
						ERROR_INFO("alloc %d error[%d]", memsize, ret);                \
						goto fail;                                                     \
					}                                                                  \
					memset(ptmpbuf, 0 ,memsize);                                       \
					if (memlen >0) {                                                   \
						memcpy(ptmpbuf, ptrmem, memlen);                               \
					}                                                                  \
					if (ptrmem != NULL && ptrmem != *pptrmem) {                        \
						free(ptrmem);                                                  \
					}                                                                  \
					ptrmem = ptmpbuf;                                                  \
					ptmpbuf = NULL;                                                    \
					goto gotolabel;                                                    \
				}                                                                      \
			}                                                                          \
		}                                                                              \
	} while(0)

#define  STDOUT_READ_EXPAND(gotolabel)                                                 \
	READ_EXPAND(m_stdout, pretout,ppout, outlen, outsize, gotolabel)

#define  STDERR_READ_EXPAND(gotolabel)                                                 \
	READ_EXPAND(m_stderr, preterr,pperr, errlen, errsize, gotolabel)


int __inner_run(int evtfd, pproc_comm_t pproc, char* pin , int insize, char** ppout, int *poutsize , char** pperr, int *perrsize, int *pexitcode, int timeout)
{
    int fd[4];
    int fdnum = 0;
    struct timeval tm, *ptm;
    uint64_t sticks, cticks;
    char* pretout = NULL;
    int outsize = 0, outlen = 0;
    char* preterr = NULL;
    int errsize = 0, errlen = 0;
    int ret;
    int status;
    int inlen = 0;
    int exitcode = 0;
    char* ptmpbuf = NULL;
    int maxfd = 0;
    int timemills = 0;
    int pending=0;
    int maxmills = 0;
    fd_set rset;
    fd_set wset;


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
        memset(pretout, 0 , outsize);
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
        memset(preterr, 0 , errsize);
    }

    sticks = get_cur_ticks();
    while (1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        fdnum = 0;
        memset(fd, 0, sizeof(fd));
        maxmills = MAX_MILLS;
        /*first to wait for the status*/
        ret = waitpid(pproc->m_pid, &status, WNOHANG);
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

        STDIN_WRITE_WAIT();
        STDOUT_READ_EXPAND(read_out);
        STDERR_READ_EXPAND(read_err);

        if (evtfd >= 0) {
            fd[fdnum] = evtfd;
            fdnum ++;
            FD_SET(evtfd, &rset);
        }

        ptm = NULL;
        if (timeout > 0) {
            cticks = get_cur_ticks();
            timemills = time_left(sticks, cticks, timeout);
            if (timemills < 0) {
                ret = -ETIMEDOUT;
                ERROR_INFO("timed out [%d]", timeout);
                goto fail;
            }
            maxmills = get_min(maxmills, timemills);
        }

        memset(&tm, 0, sizeof(tm));
        ptm = &tm;
        ptm->tv_sec = (maxmills / 1000);
        ptm->tv_usec = (maxmills % 1000) * 1000;

        if (fdnum > 0) {
            maxfd = 0;
            for (i = 0; i < fdnum; i++) {
                if (maxfd <= fd[i]) {
                    maxfd = fd[i] + 1;
                }
            }

            ret = select(maxfd, &rset, &wset, NULL, ptm);
            if (ret < 0) {
                GETERRNO(ret);
                if (ret == -EINTR) {
                    continue;
                }
                ERROR_INFO("select error[%d]", ret);
                goto fail;
            }
            /*we have something to read ,so do read again*/
            if (evtfd >= 0 && FD_ISSET(evtfd, &rset)) {
                ret = -ERFKILL;
                ERROR_INFO("manually stopped");
                goto fail;
            }
            /*to read again*/
            continue;
        } else {
            ret = select(0, NULL, NULL, NULL, ptm);
            if (ret < 0) {
                GETERRNO(ret);
                if (ret == -EINTR) {
                    continue;
                }
                ERROR_INFO("select NULL error[%d]", ret);
                goto fail;
            }
            continue;
        }
    }

    /*now child exited ,so we should read all is ok*/
    while (1) {
        /*all closed ,so we ok*/
        fdnum = 0;
        memset(fd, 0, sizeof(fd));
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        if (pproc->m_stdin[PARENT_IDX] < 0 &&
                pproc->m_stdout[PARENT_IDX] < 0 &&
                pproc->m_stderr[PARENT_IDX] < 0)  {
            break;
        }
        /*we get the time later*/
        maxmills = 50;

        STDIN_WRITE_WAIT();
        STDOUT_READ_EXPAND(read_out_later);
        STDERR_READ_EXPAND(read_err_later);

        if (evtfd >= 0) {
        	fd[fdnum] = evtfd;
        	fdnum ++;
        	FD_SET(evtfd,&rset);
        }

        if (timeout > 0) {
        	cticks = get_cur_ticks();
        	timemills = time_left(sticks, cticks,timeout);
        	if (timemills < 0) {
        		GETERRNO(ret);
        		ERROR_INFO("wait timed out");
        		goto fail;
        	}
        	maxmills = get_min(maxmills, timemills);
        }



        if (fdnum > 0) {
        	maxfd = 0;
        	for (i=0;i<fdnum;i++) {
        		if (maxfd <= fd[i]) {
        			maxfd = fd[i] + 1;
        		}
        	}
        	ret = select(maxfd,&rset,&wset,NULL,ptm);
        	if (ret < 0) {
        		GETERRNO(ret);
        		if (ret == -EINTR) {
        			continue;
        		}
        		ERROR_INFO("select error[%d]", ret);
        		goto fail;
        	}

        	if (evtfd >= 0 && FD_ISSET(evtfd,&rset)) {
        		ret = -ERFKILL;
        		ERROR_INFO("user stopped");
        		goto fail;
        	}
        }
    }

    if (pperr != NULL && *pperr != preterr) {
        free(*pperr);
    }
    if (pperr) {
        *pperr = preterr;
    }

    if (poutsize) {
        *poutsize = outlen;
    }

    if (ppout != NULL && *ppout != pretout) {
        free(*ppout);
    }
    if (ppout != NULL) {
        *ppout = pretout;
    }

    if (perrsize) {
        *perrsize = errlen;
    }

    if (pexitcode) {
        *pexitcode = exitcode;
    }

    return 0;
fail:
    if (preterr && preterr != *pperr) {
        free(preterr);
    }
    preterr = NULL;
    if (pretout && pretout != *ppout) {
        free(pretout);
    }
    pretout = NULL;
    if (ptmpbuf) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    SETERRNO(ret);
    return ret;
}

int run_cmd_event_outputv(int exitfd, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
{
	pproc_comm_t pproc=NULL;
	int ret;
	int flags = 0;

	if (pin) {
		flags |= STDIN_PIPE;
	}
	if (ppout) {
		flags |= STDOUT_PIPE;
	} else {
		flags |= STDOUT_NULL;
	}

	if (pperr) {
		flags |= STDERR_PIPE;
	} else {
		flags |= STDERR_NULL;
	}

	pproc = __start_proc(flags, prog);
	if (pproc == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __inner_run(evtfd, pproc,pin, insize, ppout, poutsize, pperr, perrsize,exitcode, timeout);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	__free_proc_comm(&pproc);
	return 0;
fail:
	__free_proc_comm(&pproc);
	SETERRNO(ret);
	return ret;
}

int __get_progs(char* prog,va_list ap, char** ppprogs[], int *psize)
{
	int i;
	int ret;
	int size = 0;
	int cnt = 0;
	char** pptmpprogs=NULL;
	char** ppretprogs=NULL;
	if (prog == NULL) {
		if (ppprogs && *ppprogs) {
			ppretprogs = *ppprogs;
			for (i=0;ppretprogs[i];i++) {
				free(ppretprogs[i]);
				ppretprogs[i] = NULL;
			}
			free(ppretprogs);
			*ppprogs = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppprogs == NULL || psize == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	ppretprogs = *ppprogs;
	size = *psize;
	if (ppretprogs) {
		/*free memory*/
		for (i=0;i<size;i++) {
			if (ppretprogs[i]) {
				free(ppretprogs[i]);
				ppretprogs[i] = NULL;
			}
		}
	}

	if (size < 4 || ppretprogs == NULL) {
		if (size < 4) {
			size = 4;
		}
		ppretprogs = malloc(sizeof(*ppretprogs) * size);
		if (ppretprogs == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc %d error[%d]", sizeof(*ppretprogs)* size, ret);
			goto fail;
		}
		memset(ppretprogs, 0 ,sizeof(*ppretprogs) * size);
	}

	ppretprogs[cnt] = strdup(prog);
	if (ppretprogs[cnt] == NULL) {
		GETERRNO(ret);
		ERROR_INFO("strdup [%s] error[%d]", prog,ret);
		goto fail;
	}
	cnt ++;

	if (ap != NULL) {
		
	}


	return cnt;
fail:
	if (pptmpprogs) {
		free(pptmpprogs);
	}
	pptmpprogs = NULL;

	if (ppretprogs) {
		for (i=0;ppretprogs[i];i++) {
			free(ppretprogs[i]);
			ppretprogs[i] = NULL;
		}
		if (ppretprogs != *ppprogs) {
			free(ppretprogs);
		}
	}
	ppretprogs = NULL;
	SETERRNO(ret);
	return ret;
}


int run_cmd_event_output(int exitfd, char* pin,  int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
	char* progs[]=NULL;

fail:

}
