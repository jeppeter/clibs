
#include <sys/signalfd.h>

int sigfd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	sigset_t sigmaskv;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int sigfd = -1;
    int efd = -1;
    struct epoll_event evt;
    struct signalfd_siginfo siginfo;
    int i;

    init_log_verbose(pargs);
    sigemptyset(&sigmaskv);
    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        int signum = atoi(parsestate->leftargs[i]);
    	sigaddset(&sigmaskv,signum);
    }

    ret = sigprocmask(SIG_BLOCK,&sigmaskv,NULL);
    if (ret <0){
        GETERRNO(ret);
        fprintf(stderr,"sigprocmask error %d\n", ret);
        goto out;
    }

    sigfd = signalfd(-1,&sigmaskv,SFD_NONBLOCK);
    if (sigfd < 0) {
        GETERRNO(ret);
        fprintf(stderr,"signalfd error %d\n",ret);
        goto out;
    }

    efd = epoll_create1(0);
    if (efd < 0) {
        GETERRNO(ret);
        fprintf(stderr,"can not epoll_create1 error %d\n", ret);
        goto out;
    }

    memset(&evt,0,sizeof(evt));
    evt.data.fd = sigfd;
    evt.events = EPOLLIN;

    ret = epoll_ctl(efd,EPOLL_CTL_ADD, sigfd, &evt);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"EPOLL_CTL_ADD error %d\n", ret);
        goto out;
    }


    ret = epoll_wait(efd,&evt,1,100000);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"epoll_wait error %d\n", ret);
        goto out;
    } else if (ret > 0) {
        ret = read(sigfd,&siginfo,sizeof(siginfo));
        if (ret < (int)sizeof(siginfo) ) {
            GETERRNO(ret);
            fprintf(stderr,"read error %d\n" , ret);
            goto out;
        }

        fprintf(stdout,"signo %d\n",siginfo.ssi_signo);
    }


    ret = sigprocmask(SIG_UNBLOCK,&sigmaskv,NULL);
    if (ret <0){
        GETERRNO(ret);
        fprintf(stderr,"sigprocmask error %d\n", ret);
        goto out;
    }


    ret = epoll_wait(efd,&evt,1,100000);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"epoll_wait error %d\n", ret);
        goto out;
    } else if (ret > 0) {
        ret = read(sigfd,&siginfo,sizeof(siginfo));
        if (ret < (int)sizeof(siginfo) ) {
            GETERRNO(ret);
            fprintf(stderr,"read error %d\n" , ret);
            goto out;
        }

        fprintf(stdout,"signo %d\n",siginfo.ssi_signo);
    }


    ret = 0;
out:
    if (efd >= 0) {
        close(efd);
    }
    efd = -1;

    if (sigfd >= 0) {
        close(sigfd);
    }
    sigfd = -1;

	SETERRNO(ret);
	return ret;
}


int getaddrinfoa_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int signum=-1;   
}