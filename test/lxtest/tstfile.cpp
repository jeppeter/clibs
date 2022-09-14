
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
    int ival;
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

    ptty = open_tty(ttyname);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", ttyname, ret);
        goto out;
    }
    DEBUG_INFO("open [%s] succ", ttyname);

    ival = pargs->m_bauderate;
    ret = set_tty_config(ptty, TTY_SET_SPEED, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set SPEED [%d] error[%d]", ival, ret);
        goto out;
    }
    DEBUG_INFO("set [%s] speed [%d]", ttyname, ival);

    ival = pargs->m_xonxoff;
    ret = set_tty_config(ptty, TTY_SET_XONXOFF, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set XONXOFF [%d]  error[%d]", ival, ret);
        goto out;
    }

    DEBUG_INFO("set [%s] XONXOFF %s",ttyname, ival != 0 ? "TRUE" : "FALSE");

    ival = pargs->m_csbits;
    ret = set_tty_config(ptty, TTY_SET_SIZE, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set CSISE [%d]  error[%d]", ival, ret);
        goto out;
    }
    DEBUG_INFO("set [%s] m_csbits [%d]", ttyname, ival);

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

        memset(&evt,0,sizeof(evt));
        evt.events = (EPOLLIN | EPOLLET);
        evt.data.fd = pollfd;

        DEBUG_INFO("EPOLLET [0x%x] EPOLLIN [%d]" ,EPOLLET,EPOLLIN);


        ret = epoll_ctl(evfd,EPOLL_CTL_ADD,pollfd,&evt);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not add pollfd [%d] error[%d]",pollfd, ret);
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
            ret = epoll_wait(evfd,&getevt,1,leftmills);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("epoll_wait error[%d]", ret);
                goto out;
            } else if (ret > 0) {
                DEBUG_INFO("get fd [%d] events [%d:0x%x]", getevt.data.fd,getevt.events, getevt.events);
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

    DEBUG_BUFFER_FMT(pbuf, readsize, "read [%s] buffer", ttyname);
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
    int bufsize=0,buflen=0;
    int ival;
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

    ptty = open_tty(ttyname);
    if (ptty == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", ttyname, ret);
        goto out;
    }

    ival = pargs->m_bauderate;
    ret = set_tty_config(ptty, TTY_SET_SPEED, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set SPEED [%d] error[%d]", ival, ret);
        goto out;
    }

    ival = pargs->m_xonxoff;
    ret = set_tty_config(ptty, TTY_SET_XONXOFF, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set XONXOFF [%d]  error[%d]", ival, ret);
        goto out;
    }

    ival = pargs->m_csbits;
    ret = set_tty_config(ptty, TTY_SET_SIZE, &ival);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("set CSISE [%d]  error[%d]", ival, ret);
        goto out;
    }

    ret = read_file_whole(infile,&pbuf,&bufsize);
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

        memset(&evt,0,sizeof(evt));
        evt.events = (EPOLLOUT | EPOLLET);
        evt.data.fd = pollfd;


        ret = epoll_ctl(evfd,EPOLL_CTL_ADD,pollfd,&evt);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not add pollfd [%d] error[%d]",pollfd, ret);
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

            ret = epoll_wait(evfd,&getevt,1,leftmills);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("epoll_wait error[%d]", ret);
                goto out;
            } else if (ret > 0) {
                DEBUG_INFO("get fd [%d] events [%d:0x%x]", getevt.data.fd,getevt.events, getevt.events);
                if (getevt.data.fd == pollfd && getevt.events != EPOLLOUT) {
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

    DEBUG_BUFFER_FMT(pbuf, buflen, "write [%s] buffer", ttyname);
    ret = 0;
out:
    free_tty(&ptty);
    read_file_whole(NULL,&pbuf,&bufsize);
    buflen = 0;
    if (evfd >= 0) {
        close(evfd);
    }
    evfd = -1;
    SETERRNO(ret);
    return ret;
}
