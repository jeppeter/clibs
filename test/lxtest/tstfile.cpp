
int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* dir = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL; i++) {
        dir = parsestate->leftargs[i];
        ret = mkdir_p(dir, pargs->m_mask);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not mkdir [%s] error[%d]\n", dir, ret);
            goto out;
        }

        fprintf(stdout, "[%d][%s] [%s]\n", i, dir, ret > 0 ? "created" : "exists");
    }

    ret  = 0;
out:
    SETERRNO(ret);
    return ret;
}

int cpfile_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* srcfile = NULL;
    char* dstfile = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;


    srcfile = parsestate->leftargs[0];
    dstfile = parsestate->leftargs[1];
    ret = cp_file(srcfile, dstfile);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cp [%s] => [%s] error[%d]\n", srcfile, dstfile, ret);
        goto out;
    }

    fprintf(stdout, "cp [%s] => [%s] size[%d]\n", srcfile, dstfile, ret);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int readoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");
    GET_OPT_INT(bufsize, "buffer size");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;

    pbuf = (char*)malloc(bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error[%d]\n", bufsize, ret);
        goto out;
    }

    ret = read_offset_file(infile, offset, pbuf, bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto  out;
    }
    buflen = ret;
    fprintf(stdout, "read [%s] ret[%d]\n", infile, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;
    SETERRNO(ret);
    return ret;
}


int writeoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* outfile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;
    if (pargs->m_output == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the output by --output|-o\n");
        goto out;
    }
    outfile = pargs->m_output;

    ret = read_file_whole(infile, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto out;
    }
    buflen = ret;

    ret = write_offset_file(outfile, offset, pbuf, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", outfile, ret);
        goto out;
    }

    fprintf(stdout, "read [%s] => [%s] offset[%ld:0x%lx] len[%d]\n", infile, outfile, offset, offset, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    read_file_whole(NULL, &pbuf, &bufsize);
    SETERRNO(ret);
    return ret;
}

int readlines_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i, j;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* infile = NULL;
    int ret;
    int maxlen = 0;
    int maxi;

    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL ; i++) {
        infile = parsestate->leftargs[i];
        ret = read_file_lines(infile, &pplines, &lsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", infile, ret);
            goto out;
        }
        llen = ret;

        maxi = 1;
        maxlen = 1;
        while (maxi < llen) {
            maxi *= 10;
            maxlen ++;
        }

        fprintf(stdout, "[%d] [%s] lines[%d]\n", i, infile, llen);
        for (j = 0; j < llen; j++) {
            fprintf(stdout, "    [%*d][%s]\n", maxlen, j, pplines[j]);
        }
    }

    ret = 0;
out:
    read_file_lines(NULL, &pplines, &lsize);
    SETERRNO(ret);
    return ret;
}

int exists_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    const char* fname;
    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        fname = parsestate->leftargs[i];
        ret = is_path_exist(fname);
        fprintf(stdout, "[%d][%s] %s\n", i, fname, ret > 0 ? "exist" : "not exist");
    }
    ret = 0;

    SETERRNO(ret);
    return ret;
}

int format_md5_digest(pmd5_state_t p, char* fmt, int size)
{
    char* pcur = fmt;
    int leftlen = size;
    int ret;
    int i;
    unsigned char* pc;

    for (i = 0; i < 4; i++) {
        pc = (unsigned char*) & (p->state[i]);
        ret = snprintf(pcur, (size_t)leftlen, "%02x%02x%02x%02x", pc[0], pc[1], pc[2], pc[3]);
        if (ret < 0 || ret >= (leftlen - 1)) {
            return -1;
        }
        pcur += ret;
        leftlen -= ret;
    }
    return 0;
}

int md5sum_file(char* fname, uint64_t size, char* digest, int digsize)
{
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    int overed = 0;
    uint64_t cursize;
    md5_state_t s;
    unsigned char bufdig[70];
    int ret;

    bufsize = 1024 * 1024;
    pbuf = (char*)malloc((size_t)bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    cursize = 0;
    init_md5_state(&s);
    while (1) {
        buflen = bufsize;
        ret = read_offset_file(fname, cursize, pbuf, buflen);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        DEBUG_BUFFER_FMT(pbuf, (buflen > 0x20 ? 0x20 : buflen), "[%s] at [0x%llx]", fname, cursize);
        buflen = ret;
        if (buflen > 0) {
            md5sum((unsigned char*)pbuf, (unsigned int) buflen, bufdig, &s);
        }
        cursize += buflen;
        if (buflen < bufsize) {
            overed = 1;
            break;
        }
    }

    if ((buflen & 0x3f) == 0) {
        md5sum((unsigned char*)pbuf, (unsigned int)0, bufdig, &s);
    }

    format_md5_digest(&s, digest, digsize);

    if (pbuf) {
        free(pbuf);
    }

    return overed;
fail:
    if (pbuf) {
        free(pbuf);
    }
    SETERRNO(ret);
    return ret;
}

int md5_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* fname;
    char digest[64];
    int i;
    int ret;

    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        fname = parsestate->leftargs[i];
        ret = md5sum_file(fname, 0, digest, sizeof(digest));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("calc [%s] error[%d]", fname, ret);
            goto out;
        }
        fprintf(stdout, "[%s] => [%s]\n", fname, digest);
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int ttyread_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* ptty = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* ttyname = NULL;
    int readsize = 100;
    int timemills = 1000;
    char* pbuf = NULL;
    uint64_t sticks;
    int evfd = -1;
    int pollfd = -1;
    struct epoll_event evt;
    struct epoll_event getevt;
    int leftmills;
    char* output=NULL;

    init_log_verbose(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        ttyname = parsestate->leftargs[0];
        if (parsestate->leftargs[1]) {
            readsize = atoi(parsestate->leftargs[1]);
            if (parsestate->leftargs[2]) {
                timemills = atoi(parsestate->leftargs[2]);
            }
        }
    }

    if (ttyname == NULL) {
        ret = -EINVAL;
        ERROR_INFO("can not get ttyname");
        goto out;
    }

    ptty = open_tty(ttyname, -1);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", ttyname, ret);
        goto out;
    }
    DEBUG_INFO("open [%s] succ", ttyname);

    pbuf = (char*)malloc(readsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(pbuf, 0, readsize);

    ret = read_tty_nonblock(ptty, (uint8_t*)pbuf, readsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("read error[%d]", ret);
        goto out;
    } else if (ret == 0) {
        sticks = get_cur_ticks();
        evfd = epoll_create(1);
        if (evfd < 0) {
            GETERRNO(ret);
            fprintf(stderr, "epoll_create [%d]\n", ret);
            goto out;
        }

        pollfd = get_tty_read_handle(ptty);
        if (pollfd < 0) {
            GETERRNO(ret);
            ERROR_INFO("get read handle error[%d]", ret);
            goto out;
        }

        memset(&evt, 0, sizeof(evt));
        evt.events = (EPOLLIN | EPOLLET);
        evt.data.fd = pollfd;

        DEBUG_INFO("EPOLLET [0x%x] EPOLLIN [%d]" , EPOLLET, EPOLLIN);


        ret = epoll_ctl(evfd, EPOLL_CTL_ADD, pollfd, &evt);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not add pollfd [%d] error[%d]", pollfd, ret);
            goto out;
        }

        while (1) {
            ret = time_left(sticks, (uint32_t)timemills);
            if (ret <= 0) {
                ret = -ETIMEDOUT;
                ERROR_INFO("read [%s] timedout", ttyname);
                goto out;
            }
            leftmills = ret;

            DEBUG_INFO("leftmills [%d]", leftmills);
            ret = epoll_wait(evfd, &getevt, 1, leftmills);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("epoll_wait error[%d]", ret);
                goto out;
            } else if (ret > 0) {
                DEBUG_INFO("get fd [%d] events [%d:0x%x]", getevt.data.fd, getevt.events, getevt.events);
                if (getevt.data.fd == pollfd && getevt.events == EPOLLIN) {
                    ret = complete_tty_read(ptty);
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("complete read error[%d]", ret);
                        goto out;
                    } else if (ret > 0) {
                        break;
                    }
                }
            }
        }
    }

    output = pargs->m_output;
    if (output != NULL) {
        ret = write_file_whole(output,pbuf,readsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("write [%s] error[%d]", output,ret);
            goto out;
        }
    } else {
        print_buffer(stdout, (unsigned char*)pbuf, readsize, "read [%s] buffer", ttyname);
    }

    
    ret = 0;
out:
    free_tty(&ptty);
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;

    if (evfd >= 0) {
        close(evfd);
    }
    evfd = -1;
    SETERRNO(ret);
    return ret;
}

int ttywrite_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* ptty = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* ttyname = NULL;
    char* infile = NULL;
    int timemills = 1000;
    char* pbuf = NULL;
    char* pptr = NULL;
    int bufsize = 0, buflen = 0;
    uint64_t sticks;
    int evfd = -1;
    int pollfd = -1;
    struct epoll_event evt;
    struct epoll_event getevt;
    int leftmills;

    init_log_verbose(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        ttyname = parsestate->leftargs[0];
        if (parsestate->leftargs[1]) {
            infile = parsestate->leftargs[1];
            if (parsestate->leftargs[2]) {
                timemills = atoi(parsestate->leftargs[2]);
            }
        }
    }

    if (ttyname == NULL || infile == NULL) {
        ret = -EINVAL;
        ERROR_INFO("can not get ttyname and infile");
        goto out;
    }

    ptty = open_tty(ttyname, -1);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", ttyname, ret);
        goto out;
    }


    ret = read_file_whole(infile, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    buflen = ret;


    ret = write_tty_nonblock(ptty, (uint8_t*)pbuf, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("read error[%d]", ret);
        goto out;
    } else if (ret == 0) {
        sticks = get_cur_ticks();
        evfd = epoll_create(1);
        if (evfd < 0) {
            GETERRNO(ret);
            fprintf(stderr, "epoll_create [%d]\n", ret);
            goto out;
        }

        pollfd = get_tty_write_handle(ptty);
        if (pollfd < 0) {
            GETERRNO(ret);
            ERROR_INFO("get write handle error[%d]", ret);
            goto out;
        }

        memset(&evt, 0, sizeof(evt));
        evt.events = (EPOLLOUT | EPOLLET);
        evt.data.fd = pollfd;


        ret = epoll_ctl(evfd, EPOLL_CTL_ADD, pollfd, &evt);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not add pollfd [%d] error[%d]", pollfd, ret);
            goto out;
        }

        while (1) {
            ret = time_left(sticks, (uint32_t)timemills);
            if (ret <= 0) {
                ret = -ETIMEDOUT;
                ERROR_INFO("write [%s] timedout", ttyname);
                goto out;
            }
            leftmills = ret;

            ret = epoll_wait(evfd, &getevt, 1, leftmills);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("epoll_wait error[%d]", ret);
                goto out;
            } else if (ret > 0) {
                DEBUG_INFO("get fd [%d] events [%d:0x%x] EPOLLOUT [%d]", getevt.data.fd, getevt.events, getevt.events, EPOLLOUT);
                if (getevt.data.fd == pollfd && getevt.events == EPOLLOUT) {
                    ret = complete_tty_write(ptty);
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("complete write error[%d]", ret);
                        goto out;
                    } else if (ret > 0) {
                        break;
                    }
                }
            }
        }
    }

    if (buflen > 0x200) {
        print_buffer(stdout, (unsigned char*)pbuf, 0x200, "write [%s] buffer start", ttyname);
        pptr = pbuf + buflen;
        pptr -= 0x200;
        print_buffer(stdout, (unsigned char*)pptr, 0x200, "write [%s] buffer end", ttyname);
    } else {
        print_buffer(stdout, (unsigned char*)pbuf, buflen, "write [%s] buffer", ttyname);
    }

    ret = 0;
out:
    free_tty(&ptty);
    read_file_whole(NULL, &pbuf, &bufsize);
    buflen = 0;
    if (evfd >= 0) {
        close(evfd);
    }
    evfd = -1;
    SETERRNO(ret);
    return ret;
}

#define TTY_CFG_BIT(member,bits, bitdesc)                                                         \
do{                                                                                               \
    if ( ((pcfg->member) & bits ) != 0 ) {                                                        \
        fprintf(stdout,"%s",bitdesc);                                                             \
    } else {                                                                                      \
        fprintf(stdout, "-%s",bitdesc);                                                           \
    }                                                                                             \
    fprintf(stdout," ");                                                                          \
}while(0)

#define  TTY_CC_VAL(ccnum,desc)                                                                   \
do{                                                                                               \
    if (pcfg->c_cc[(ccnum)] == 0) {                                                               \
        fprintf(stdout,"%s off[%d] undef",desc,ccnum);                                            \
    } else {                                                                                      \
        fprintf(stdout,"%s off[%d] [0x%x]", desc,ccnum,pcfg->c_cc[(ccnum)]);                      \
    }                                                                                             \
    fprintf(stdout," ");                                                                          \
}while(0)

#define TTY_IFLAG_BIT(bits, bitdesc) TTY_CFG_BIT(c_iflag,bits,bitdesc)
#define TTY_OFLAG_BIT(bits, bitdesc) TTY_CFG_BIT(c_oflag,bits,bitdesc)
#define TTY_CFLAG_BIT(bits, bitdesc) TTY_CFG_BIT(c_cflag,bits,bitdesc)
#define TTY_LFLAG_BIT(bits, bitdesc) TTY_CFG_BIT(c_lflag,bits,bitdesc)

#define TTY_SPEED_NOTE(member,desc)                                                               \
do{                                                                                               \
    val = pcfg->member;                                                                           \
    sval = val;                                                                                   \
    if (val == B0) {                                                                              \
        sval = 0;                                                                                 \
    } else if (val == B50) {                                                                      \
        sval = 50;                                                                                \
    } else if (val == B75) {                                                                      \
        sval = 75;                                                                                \
    } else if (val == B110) {                                                                     \
        sval = 110;                                                                               \
    } else if (val == B134) {                                                                     \
        sval = 134;                                                                               \
    } else if (val == B150) {                                                                     \
        sval = 150;                                                                               \
    } else if (val == B200) {                                                                     \
        sval = 200;                                                                               \
    } else if (val == B300) {                                                                     \
        sval = 300;                                                                               \
    } else if (val == B600) {                                                                     \
        sval = 600;                                                                               \
    } else if (val == B1200) {                                                                    \
        sval = 1200;                                                                              \
    } else if (val == B2400) {                                                                    \
        sval = 2400;                                                                              \
    } else if (val == B4800) {                                                                    \
        sval = 4800;                                                                              \
    } else if (val == B9600) {                                                                    \
        sval = 9600;                                                                              \
    } else if (val == B19200) {                                                                   \
        sval = 19200;                                                                             \
    } else if (val == B38400) {                                                                   \
        sval = 38400;                                                                             \
    } else if (val == B57600) {                                                                   \
        sval = 57600;                                                                             \
    } else if (val == B115200) {                                                                  \
        sval = 115200;                                                                            \
    } else if (val == B230400) {                                                                  \
        sval = 230400;                                                                            \
    } else if (val == B460800) {                                                                  \
        sval = 460800;                                                                            \
    } else if (val == B500000) {                                                                  \
        sval = 500000;                                                                            \
    } else if (val == B576000) {                                                                  \
        sval = 576000;                                                                            \
    } else if (val == B921600) {                                                                  \
        sval = 921600;                                                                            \
    } else if (val == B1000000) {                                                                 \
        sval = 1000000;                                                                           \
    } else if (val == B1152000) {                                                                 \
        sval = 1152000;                                                                           \
    } else if (val == B1500000) {                                                                 \
        sval = 1500000;                                                                           \
    } else if (val == B2000000) {                                                                 \
        sval = 2000000;                                                                           \
    } else if (val == B2500000) {                                                                 \
        sval = 2500000;                                                                           \
    } else if (val == B3000000) {                                                                 \
        sval = 3000000;                                                                           \
    } else if (val == B3500000) {                                                                 \
        sval = 3500000;                                                                           \
    } else if (val == B4000000) {                                                                 \
        sval = 4000000;                                                                           \
    }                                                                                             \
    fprintf(stdout,"%s [0x%x] [%d]\n", desc,val,sval);                                            \
}while(0)

int ttycfgget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* ptty = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* ttyname = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    struct termios* pcfg;
    int val;
    int sval;

    init_log_verbose(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        ttyname = parsestate->leftargs[0];
    }

    if (ttyname == NULL) {
        ret = -EINVAL;
        ERROR_INFO("can not get ttyname");
        goto out;
    }

    ptty = open_tty(ttyname, -1);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open [%s] error[%d]", ttyname, ret);
        goto out;
    }

    ret = get_tty_config_direct(ptty, (void**)&pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get [%s] config error [%d]", ttyname, ret);
        goto out;
    }
    buflen = ret;

    DEBUG_BUFFER_FMT(pbuf, buflen, "[%s] config", ttyname);
    pcfg = (struct termios*) pbuf;
    fprintf(stdout, "[%s]\n", ttyname);
    TTY_SPEED_NOTE(c_ispeed, "ispeed");
    TTY_SPEED_NOTE(c_ospeed, "ospeed");


    fprintf(stdout, "c_cc    ");
    TTY_CC_VAL(VINTR, "intr");
    TTY_CC_VAL(VQUIT, "quit");
    TTY_CC_VAL(VERASE, "erase");
    TTY_CC_VAL(VKILL, "kill");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_CC_VAL(VEOF, "eof");
    TTY_CC_VAL(VEOL, "eol");
    TTY_CC_VAL(VEOL2, "eol2");
    TTY_CC_VAL(VSWTC, "swtch");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_CC_VAL(VSTART, "start");
    TTY_CC_VAL(VSTOP, "stop");
    TTY_CC_VAL(VSUSP, "susp");
    TTY_CC_VAL(VREPRINT, "rprnt");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_CC_VAL(VWERASE, "werase");
    TTY_CC_VAL(VLNEXT, "lnext");
    TTY_CC_VAL(VDISCARD, "flush");
    TTY_CC_VAL(VMIN, "min");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_CC_VAL(VTIME, "time");
    fprintf(stdout, "\n");


    fprintf(stdout, "iflags  ");
    TTY_IFLAG_BIT(IGNBRK, "ignbrk");
    TTY_IFLAG_BIT(BRKINT, "brkint");
    TTY_IFLAG_BIT(IGNPAR, "ignpar");
    TTY_IFLAG_BIT(PARMRK, "parmrk");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_IFLAG_BIT(INPCK, "inpck");
    TTY_IFLAG_BIT(ISTRIP, "istrip");
    TTY_IFLAG_BIT(INLCR, "inlcr");
    TTY_IFLAG_BIT(IGNCR, "igncr");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_IFLAG_BIT(ICRNL, "icrnl");
    TTY_IFLAG_BIT(IUCLC, "iuclc");
    TTY_IFLAG_BIT(IXON, "ixon");
    TTY_IFLAG_BIT(IXANY, "ixany");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_IFLAG_BIT(IXOFF, "ixoff");
    TTY_IFLAG_BIT(IMAXBEL, "imaxbel");
    TTY_IFLAG_BIT(IUTF8, "iutf8");
    fprintf(stdout, "\n");


    fprintf(stdout, "c_cflag ");
    TTY_CFLAG_BIT(PARENB, "parenb");
    TTY_CFLAG_BIT(PARODD, "parodd");
    val = pcfg->c_cflag & CSIZE;
    if (val == CS5) {
        fprintf(stdout, "cs5 ");
    } else if (val == CS6) {
        fprintf(stdout, "cs6 ");
    } else if (val == CS7) {
        fprintf(stdout, "cs7 ");
    } else if (val == CS8) {
        fprintf(stdout, "cs8 ");
    } else {
        fprintf(stdout, "cs[0x%x] ", val);
    }
    TTY_CFLAG_BIT(HUPCL, "hupcl");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_CFLAG_BIT(CSTOPB, "cstopb");
    TTY_CFLAG_BIT(CREAD, "cread");
    TTY_CFLAG_BIT(CLOCAL, "clocal");
    TTY_CFLAG_BIT(CRTSCTS, "crtscts");
    fprintf(stdout, "\n");

    fprintf(stdout, "c_oflag ");
    TTY_OFLAG_BIT(OPOST, "opost");
    TTY_OFLAG_BIT(OLCUC, "olcuc");
    TTY_OFLAG_BIT(OCRNL, "ocrnl");
    TTY_OFLAG_BIT(ONLCR, "onlcr");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_OFLAG_BIT(ONOCR, "onocr");
    TTY_OFLAG_BIT(ONLRET, "onlret");
    TTY_OFLAG_BIT(OFILL, "ofill");
    TTY_OFLAG_BIT(OFDEL, "ofdel");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    val = pcfg->c_oflag & NLDLY;
    if (val == NL0) {
        fprintf(stdout, "nl0 ");
    } else if (val == NL1) {
        fprintf(stdout, "nl1 ");
    } else {
        fprintf(stdout, "nl[0x%x] ", val);
    }

    val = pcfg->c_oflag & CRDLY;
    if (val == CR0) {
        fprintf(stdout, "cr0 ");
    } else if (val == CR1) {
        fprintf(stdout, "cr1 ");
    } else if (val == CR2) {
        fprintf(stdout, "cr2 ");
    } else if (val == CR3) {
        fprintf(stdout, "cr3 ");
    } else {
        fprintf(stdout, "cr[0x%x] ", val);
    }


    val = pcfg->c_oflag & TABDLY;
    if (val == TAB0) {
        fprintf(stdout, "tab0 ");
    } else if (val == TAB1) {
        fprintf(stdout, "tab1 ");
    } else if (val == TAB2) {
        fprintf(stdout, "tab2 ");
    } else if (val == TAB3) {
        fprintf(stdout, "tab3 ");
    } else {
        fprintf(stdout, "tab[0x%x] ", val);
    }


    val = pcfg->c_oflag & BSDLY;
    if (val == BS0) {
        fprintf(stdout, "bs0 ");
    } else if (val == BS1) {
        fprintf(stdout, "bs1 ");
    } else {
        fprintf(stdout, "bs[0x%x] ", val);
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "        ");

    val = pcfg->c_oflag & VTDLY;
    if (val == VT0) {
        fprintf(stdout, "vt0 ");
    } else if (val == VT1) {
        fprintf(stdout, "vt1 ");
    } else {
        fprintf(stdout, "vt[0x%x] ", val);
    }


    val = pcfg->c_oflag & FFDLY;
    if (val == FF0) {
        fprintf(stdout, "ff0 ");
    } else if (val == FF1) {
        fprintf(stdout, "ff1 ");
    } else {
        fprintf(stdout, "ff[0x%x] ", val);
    }

    fprintf(stdout, "\n");

    fprintf(stdout, "c_lflag ");
    TTY_LFLAG_BIT(ISIG, "isig");
    TTY_LFLAG_BIT(ICANON, "icanon");
    TTY_LFLAG_BIT(IEXTEN, "iexten");
    TTY_LFLAG_BIT(ECHO, "echo");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_LFLAG_BIT(ECHOE, "echoe");
    TTY_LFLAG_BIT(ECHOK, "echok");
    TTY_LFLAG_BIT(ECHONL, "echonl");
    TTY_LFLAG_BIT(NOFLSH, "noflsh");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_LFLAG_BIT(XCASE, "xcase");
    TTY_LFLAG_BIT(TOSTOP, "tostop");
    TTY_LFLAG_BIT(ECHOPRT, "echoprt");
    TTY_LFLAG_BIT(ECHOCTL, "echoctl");
    fprintf(stdout, "\n");
    fprintf(stdout, "        ");
    TTY_LFLAG_BIT(ECHOKE, "echoke");

    fprintf(stdout, "\n");

    ret = 0;
out:
    get_tty_config_direct(NULL, (void**)&pbuf, &bufsize);
    buflen = 0;
    free_tty(&ptty);
    SETERRNO(ret);
    return ret;
}

int ttycfgset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* ptty = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* ttyname = NULL;
    int vflag = 0;
    char cfgbuf[10];
    unsigned int* uptr;
    unsigned char* ucptr;
    int *iptr;
    int ival;
    uint64_t val64;
    char* keyname = NULL;
    int idx;
    char* valname = NULL;

    init_log_verbose(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        ttyname = parsestate->leftargs[0];
    }

    if (ttyname == NULL) {
        ret = -EINVAL;
        ERROR_INFO("can not get ttyname");
        goto out;
    }

    ptty = open_tty(ttyname, -1);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open [%s] error[%d]", ttyname, ret);
        goto out;
    }

    for (idx = 1; parsestate->leftargs && parsestate->leftargs[idx] != NULL;) {
        keyname = parsestate->leftargs[idx];
        idx += 1;
        ival = -1;
        val64 = 0;
        if (strcmp(keyname, "iflagset") == 0) {
            vflag = TTY_SET_IFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "ignbrk") == 0) {
                val64 = IGNBRK;
            } else if (strcmp(valname, "brkint") == 0) {
                val64 = BRKINT;
            } else if (strcmp(valname, "ignpar") == 0) {
                val64 = IGNPAR;
            } else if (strcmp(valname, "parmrk") == 0) {
                val64 = PARMRK;
            } else if (strcmp(valname, "inpck") == 0) {
                val64 = INPCK;
            } else if (strcmp(valname, "istrip") == 0) {
                val64 = ISTRIP;
            } else if (strcmp(valname, "inlcr") == 0) {
                val64 = INLCR;
            } else if (strcmp(valname, "igncr") == 0) {
                val64 = IGNCR;
            } else if (strcmp(valname, "icrnl") == 0) {
                val64 = ICRNL;
            } else if (strcmp(valname, "iuclc") == 0) {
                val64 = IUCLC;
            } else if (strcmp(valname, "ixon") == 0) {
                val64 = IXON;
            } else if (strcmp(valname, "ixoff") == 0) {
                val64 = IXOFF;
            } else if (strcmp(valname, "imaxbel") == 0) {
                val64 = IMAXBEL;
            } else if (strcmp(valname, "iutf8") == 0) {
                val64 = IUTF8;
            } else {
                GET_OPT_NUM64(val64, "set iflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no set iflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "iflagclear") == 0) {
            vflag = TTY_CLEAR_IFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "ignbrk") == 0) {
                val64 = IGNBRK;
            } else if (strcmp(valname, "brkint") == 0) {
                val64 = BRKINT;
            } else if (strcmp(valname, "ignpar") == 0) {
                val64 = IGNPAR;
            } else if (strcmp(valname, "parmrk") == 0) {
                val64 = PARMRK;
            } else if (strcmp(valname, "inpck") == 0) {
                val64 = INPCK;
            } else if (strcmp(valname, "istrip") == 0) {
                val64 = ISTRIP;
            } else if (strcmp(valname, "inlcr") == 0) {
                val64 = INLCR;
            } else if (strcmp(valname, "igncr") == 0) {
                val64 = IGNCR;
            } else if (strcmp(valname, "icrnl") == 0) {
                val64 = ICRNL;
            } else if (strcmp(valname, "iuclc") == 0) {
                val64 = IUCLC;
            } else if (strcmp(valname, "ixon") == 0) {
                val64 = IXON;
            } else if (strcmp(valname, "ixoff") == 0) {
                val64 = IXOFF;
            } else if (strcmp(valname, "imaxbel") == 0) {
                val64 = IMAXBEL;
            } else if (strcmp(valname, "iutf8") == 0) {
                val64 = IUTF8;
            } else {
                GET_OPT_NUM64(val64, "clear iflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no clear iflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "oflagset") == 0) {
            vflag = TTY_SET_OFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "opost") == 0) {
                val64 = OPOST;
            } else if (strcmp(valname, "olcuc") == 0) {
                val64 = OLCUC;
            } else if (strcmp(valname, "ocrnl") == 0) {
                val64 = OCRNL;
            } else if (strcmp(valname, "onlcr") == 0) {
                val64 = ONLCR;
            } else if (strcmp(valname, "onocr") == 0) {
                val64 = ONOCR;
            } else if (strcmp(valname, "onlret") == 0) {
                val64 = ONLRET;
            } else if (strcmp(valname, "ofill") == 0) {
                val64 = OFILL;
            } else if (strcmp(valname, "ofdel") == 0) {
                val64 = OFDEL;
            } else {
                GET_OPT_NUM64(val64, "set oflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no set oflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "oflagclear") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "opost") == 0) {
                val64 = OPOST;
            } else if (strcmp(valname, "olcuc") == 0) {
                val64 = OLCUC;
            } else if (strcmp(valname, "ocrnl") == 0) {
                val64 = OCRNL;
            } else if (strcmp(valname, "onlcr") == 0) {
                val64 = ONLCR;
            } else if (strcmp(valname, "onocr") == 0) {
                val64 = ONOCR;
            } else if (strcmp(valname, "onlret") == 0) {
                val64 = ONLRET;
            } else if (strcmp(valname, "ofill") == 0) {
                val64 = OFILL;
            } else if (strcmp(valname, "ofdel") == 0) {
                val64 = OFDEL;
            } else {
                GET_OPT_NUM64(val64, "clear oflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no clear oflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "cflagset") == 0) {
            vflag = TTY_SET_CFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "parenb") == 0) {
                val64 = PARENB;
            } else if (strcmp(valname, "parodd") == 0) {
                val64 = PARODD;
            } else if (strcmp(valname, "hupcl") == 0) {
                val64 = HUPCL;
            } else if (strcmp(valname, "cstopb") == 0) {
                val64 = CSTOPB;
            } else if (strcmp(valname, "cread") == 0) {
                val64 = CREAD;
            } else if (strcmp(valname, "clocal") == 0) {
                val64 = CLOCAL;
            } else if (strcmp(valname, "crtscts") == 0) {
                val64 = CRTSCTS;
            } else {
                GET_OPT_NUM64(val64, "set cflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no set cflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "cflagclear") == 0) {
            vflag = TTY_CLEAR_CFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "parenb") == 0) {
                val64 = PARENB;
            } else if (strcmp(valname, "parodd") == 0) {
                val64 = PARODD;
            } else if (strcmp(valname, "hupcl") == 0) {
                val64 = HUPCL;
            } else if (strcmp(valname, "cstopb") == 0) {
                val64 = CSTOPB;
            } else if (strcmp(valname, "cread") == 0) {
                val64 = CREAD;
            } else if (strcmp(valname, "clocal") == 0) {
                val64 = CLOCAL;
            } else if (strcmp(valname, "crtscts") == 0) {
                val64 = CRTSCTS;
            } else {
                GET_OPT_NUM64(val64, "clear cflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no clear cflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "lflagset") == 0) {
            vflag = TTY_SET_LFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "isig") == 0) {
                val64 = ISIG;
            } else if (strcmp(valname, "icanon") == 0) {
                val64 = ICANON;
            } else if (strcmp(valname, "icanon") == 0) {
                val64 = ICANON;
            } else if (strcmp(valname, "iexten") == 0) {
                val64 = IEXTEN;
            } else if (strcmp(valname, "echo") == 0) {
                val64 = ECHO;
            } else if (strcmp(valname, "echoe") == 0) {
                val64 = ECHOE;
            } else if (strcmp(valname, "echok") == 0) {
                val64 = ECHOK;
            } else if (strcmp(valname, "echonl") == 0) {
                val64 = ECHONL;
            } else if (strcmp(valname, "noflsh") == 0) {
                val64 = NOFLSH;
            } else if (strcmp(valname, "xcase") == 0) {
                val64 = XCASE;
            } else if (strcmp(valname, "tostop") == 0) {
                val64 = TOSTOP;
            } else if (strcmp(valname, "echoprt") == 0) {
                val64 = ECHOPRT;
            } else if (strcmp(valname, "echoctl") == 0) {
                val64 = ECHOCTL;
            } else if (strcmp(valname, "echoke") == 0) {
                val64 = ECHOKE;
            } else {
                GET_OPT_NUM64(val64, "set lflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no set lflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "lflagclear") == 0) {
            vflag = TTY_CLEAR_LFLAGS;
            if (parsestate->leftargs[idx] == NULL) {
                ret = -EINVAL;
                ERROR_INFO("[%s] need arg", keyname);
                goto out;
            }
            valname = parsestate->leftargs[idx];
            if (strcmp(valname, "isig") == 0) {
                val64 = ISIG;
            } else if (strcmp(valname, "icanon") == 0) {
                val64 = ICANON;
            } else if (strcmp(valname, "icanon") == 0) {
                val64 = ICANON;
            } else if (strcmp(valname, "iexten") == 0) {
                val64 = IEXTEN;
            } else if (strcmp(valname, "echo") == 0) {
                val64 = ECHO;
            } else if (strcmp(valname, "echoe") == 0) {
                val64 = ECHOE;
            } else if (strcmp(valname, "echok") == 0) {
                val64 = ECHOK;
            } else if (strcmp(valname, "echonl") == 0) {
                val64 = ECHONL;
            } else if (strcmp(valname, "noflsh") == 0) {
                val64 = NOFLSH;
            } else if (strcmp(valname, "xcase") == 0) {
                val64 = XCASE;
            } else if (strcmp(valname, "tostop") == 0) {
                val64 = TOSTOP;
            } else if (strcmp(valname, "echoprt") == 0) {
                val64 = ECHOPRT;
            } else if (strcmp(valname, "echoctl") == 0) {
                val64 = ECHOCTL;
            } else if (strcmp(valname, "echoke") == 0) {
                val64 = ECHOKE;
            } else {
                GET_OPT_NUM64(val64, "clear lflag");
                if (val64 == 0) {
                    ret = -EINVAL;
                    fprintf(stderr, "no clear lflag\n");
                    goto out;
                }
                idx -= 1;
            }
            idx += 1;
            uptr = (unsigned int*)cfgbuf;
            *uptr = (unsigned int) val64;
        } else if (strcmp(keyname, "clineset") == 0) {
            vflag = TTY_SET_CLINE;
            GET_OPT_INT(ival, "line set");
            if (ival < 0) {
                ret = -EINVAL;
                fprintf(stderr, "no line set\n");
                goto out;
            }
            ucptr = (unsigned char*)cfgbuf;
            *ucptr = (unsigned char)ival;
        } else if (strcmp(keyname, "speedset") == 0) {
            vflag = TTY_SET_SPEED;
            GET_OPT_INT(ival, "speed");
            if (ival < 0) {
                ret = -EINVAL;
                fprintf(stderr, "no speed\n");
                goto out;
            }
            iptr = (int*)cfgbuf;
            *iptr = ival;
        } else if (strcmp(keyname, "ccset") == 0) {
            vflag = TTY_SET_CC;
            ucptr = (unsigned char*)cfgbuf;
            GET_OPT_INT(ival, "set cc offset");
            if (ival < 0) {
                ret = -EINVAL;
                fprintf(stderr, "no set cc offset\n");
                goto out;
            }
            ucptr[0] = (unsigned char)ival;
            ival = -1;
            GET_OPT_INT(ival, "set cc value");
            if (ival < 0) {
                ret = -EINVAL;
                fprintf(stderr, "no set cc value\n");
                goto out;
            }
            ucptr[1] = (unsigned char)ival;
        } else if (strcmp(keyname, "raw") == 0) {
            vflag = TTY_SET_RAW;
            memset(cfgbuf, 0, sizeof(cfgbuf));
        } else if (strcmp(keyname, "cs8") == 0) {
            vflag = TTY_CLEAR_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CSIZE;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CS8;
        } else if (strcmp(keyname, "cs7") == 0) {
            vflag = TTY_CLEAR_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CSIZE;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CS7;
        } else if (strcmp(keyname, "cs6") == 0) {
            vflag = TTY_CLEAR_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CSIZE;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CS6;
        } else if (strcmp(keyname, "cs5") == 0) {
            vflag = TTY_CLEAR_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CSIZE;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_CFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CS5;
        } else if (strcmp(keyname, "nl0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = NLDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = NL0;
        } else if (strcmp(keyname, "nl1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = NLDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = NL0;
        } else if (strcmp(keyname, "cr0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CRDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CR0;
        } else if (strcmp(keyname, "cr1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CRDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CR1;
        } else if (strcmp(keyname, "cr2") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CRDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CR2;
        } else if (strcmp(keyname, "cr3") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CRDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = CR3;
        } else if (strcmp(keyname, "tab0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TABDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TAB0;
        } else if (strcmp(keyname, "tab1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TABDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TAB1;
        } else if (strcmp(keyname, "tab2") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TABDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TAB2;
        } else if (strcmp(keyname, "tab3") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TABDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = TAB3;
        } else if (strcmp(keyname, "bs0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = BSDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = BS0;
        } else if (strcmp(keyname, "bs1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = BSDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = BS1;
        } else if (strcmp(keyname, "vt0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = VTDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = VT0;
        } else if (strcmp(keyname, "vt1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = VTDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = VT1;
        } else if (strcmp(keyname, "ff0") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = FFDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = FF0;
        } else if (strcmp(keyname, "ff1") == 0) {
            vflag = TTY_CLEAR_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = FFDLY;
            ret = prepare_tty_config(ptty, vflag, cfgbuf);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not set [%s] ", keyname);
                goto out;
            }
            vflag = TTY_SET_OFLAGS;
            iptr = (int*)cfgbuf;
            *iptr = FF1;
        } else {
            ret = -EINVAL;
            fprintf(stderr, "not support keyname [%s]\n", keyname);
            goto out;
        }

        ret = prepare_tty_config(ptty, vflag, cfgbuf);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not set [%s] ", keyname);
            goto out;
        }
    }

    ret = commit_tty_config(ptty);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not commit [%s] config", ttyname);
        goto out;
    }
    fprintf(stdout, "config [%s] succ\n", ttyname);

    ret = 0;
out:
    free_tty(&ptty);
    SETERRNO(ret);
    return ret;
}