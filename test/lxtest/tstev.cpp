
int exit_fd_notify(void* pev, uint64_t fd, int event, void* arg)
{
    DEBUG_INFO("exit_fd_notify");
    break_uxev(pev);
    return 0;
}

typedef struct __chatsvr_cli {
    void* m_sock;
    int m_event;

    void* m_parent;

    int m_sockfd;
    void* m_pev;


    int m_inrd;
    int m_inwr;
    int m_insertsock;


    uint8_t* m_pwbuf;
    int m_wleft;

    uint8_t* m_ppwbufs;
    int* m_ppwlens;
    int m_wbufsize;

} chatsvr_cli_t, *pchatsvr_cli_t;

typedef struct __chat_svr {
    int m_bindsock;
    void* m_pev;

    int m_inacc;
    int m_insertsock;

    pchatsvr_cli_t* m_clis;
    int m_clinum;
} chat_svr_t, *pchat_svr_t;

void __free_chatsvr_cli(pchatsvr_cli_t* ppcli)
{
    if (ppcli && *ppcli) {
        pchatsvr_cli_t pcli = *ppcli;

        if (pcli->m_parent != NULL) {
            if (pcli->m_sockfd >= 0) {
                remove_server_client_sock((pchat_svr_t)pcli->m_parent,pcli->m_sockfd,0);
            }
            pcli->m_parent = NULL;            
        }

        if (pcli->m_insertsock > 0) {
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);
            pcli->m_insertsock = 0;
        }

        free_sock(&pcli->m_sock);
        pcli->m_sockfd = -1;

        if (pcli->m_pwbuf) {
            free(pcli->m_pwbuf);
        }
        pcli->m_pwbuf = NULL;
        pcli->m_wleft = 0;

        if (pcli->m_ppwbufs && pcli->m_ppwlens) {
            for(i=0;i<pcli->m_wbufsize;i++) {
                if (pcli->m_ppwbufs[i] != NULL) {
                    free(pcli->m_ppwbufs[i]);
                    pcli->m_ppwbufs[i] = NULL;
                }
            }
        }

        if (pcli->m_ppwbufs) {
            free(pcli->m_ppwbufs);
        }
        pcli->m_ppwbufs = NULL;

        if (pcli->m_ppwlens) {
            free(pcli->m_ppwlens);
        }
        pcli->m_ppwlens = NULL;

        pcli->m_wbufsize = 0;

        free(pcli);
        *ppcli = NULL;
    }
}

int __write_socket_chatsvr_cli(pchatsvr_cli_t pcli)
{
    int ret;
    int i;
    if (pcli->m_inwr == 0) {
        while(1) {
            if (pcli->m_pwbuf != NULL) {
                ret = write_tcp_socket(pcli->m_sock,pcli->m_pwbuf,pcli->m_wleft);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                } else if (ret == 0) {
                    pcli->m_inwr = 1;
                    break;
                }
                free(pcli->m_pwbuf);
                pcli->m_pwbuf = NULL;
                pcli->m_wleft = 0;
            }

            if (pcli->m_ppwbufs && pcli->m_ppwlens) {
                if (pcli->m_ppwbufs[0] != NULL) {
                    pcli->m_pwbuf = pcli->m_ppwbufs[0];
                    pcli->m_wleft = pcli->m_ppwlens[0];
                    for(i=1;i<pcli->m_wbufsize;i++) {
                        pcli->m_ppwlens[(i-1)] = pcli->m_ppwlens[i];
                        pcli->m_ppwbufs[(i-1)] = pcli->m_ppwbufs[i];
                    }
                    pcli->m_ppwbufs[(pcli->m_wbufsize - 1)] = NULL;
                    pcli->m_ppwlens[(pcli->m_wbufsize-1)] = 0;
                }
            }

            if (pcli->m_pwbuf == NULL) {
                pcli->m_inwr = 0;
                break;
            }
        }
    }
    return 0;

fail:
    SETERRNO(ret);
    return ret; 
}

int __echo_socket_chatsvr_cli(pchatsvr_cli_t pcli)
{
    int wlen = 0;
    uint8_t* pwbuf = NULL;

    if (pcli->m_rdlen == 0) {
        return 0;
    }

    wlen = pcli->m_rdlen;
    pwbuf = (uint8_t*) malloc(wlen + 1);
    if (pwbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pwbuf,0,wlen + 1);

    for(i=0;i<pcli->m_rdlen;i++) {
        cidx = pcli->m_rdsidx + idx;
        cidx %= pcli->m_rdsize;
        pwbuf[i] = pcli->M_rdbuf[cidx];
    }
    pcli->m_rdlen = 0;
    pcli->m_rdsidx = pcli->m_rdeidx;

    if (pcli->m_pwbuf == NULL) {
        pcli->m_pwbuf = pwbuf;
        pcli->m_wleft = wlen;
        pwbuf = NULL;
    } else {
        for(i=0;i<pcli->m_wbufsize;i++) {
            if (pcli->m_ppwbufs[i] == NULL) {
                fidx = i;
                break;
            }
        }

        if (fidx >= 0) {
            pcli->m_ppwbufs[fidx] = pwbuf;
            pcli->m_ppwlens[fidx] = wlen;
            pwbuf = NULL;
            wlen = 0;
        } else {
            if (pcli->m_wbufsize == 0) {
                wbufsize = 4;
            } else {
                wbufsize = pcli->m_wbufsize << 1;
            }

            ppwbufs = (uint8_t**) malloc(sizeof(*ppwbufs) * wbufsize);
            ppwlens = (int*) malloc(sizeof(*ppwlens) * wbufsize);
            if (ppwbufs == NULL || ppwlens == NULL) {
                GETERRNO(ret);
                goto fail;
            }
            memset(ppwbufs,0, sizeof(*ppwbufs) * wbufsize);
            memset(ppwlens,0, sizeof(*ppwlens) * wbufsize);
            if (pcli->m_wbufsize > 0) {
                memcpy(ppwbufs,pcli->m_ppwbufs,sizeof(*ppwbufs) * pcli->m_wbufsize);
                memcpy(ppwlens,pcli->m_ppwlens,sizeof(*ppwlens) * pcli->m_wbufsize);
            }

            ppwbufs[pcli->m_wbufsize] = pwbuf;
            ppwlens[pcli->m_wbufsize] = wlen;
            pwbuf = NULL;
            wlen = 0;
            if (pcli->m_ppwbufs) {
                free(pcli->m_ppwbufs);
            }
            pcli->m_ppwbufs = ppwbufs;
            if (pcli->m_ppwlens) {
                free(pcli->m_ppwlens);
            }
            pcli->m_ppwlens = ppwlens;
            ppwbufs = NULL;
            ppwlens = NULL;
            pcli->m_wbufsize = wbufsize;
        }       
    }

    ret = __write_socket_chatsvr_cli(pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    return 0;
fail:
    if (pwbuf) {
        free(pwbuf);
    }
    pwbuf = NULL;
    SETERRNO(ret);
    return ret;
}

int __read_socket_chatsvr_cli(pchatsvr_cli_t pcli)
{
    int ret;
    if (pcli->m_inrd == 0) {
        while(1) {
            if (pcli->m_rdlen == pcli->m_rdsize) {
                ret = __echo_socket_chatsvr_cli(pcli);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
            }

            ret = read_tcp_socket(pcli->m_sock,&(pcli->M_rdbuf[pcli->m_rdeidx]),1);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            } else if (ret == 0) {
                pcli->m_inrd = 1;
                ret = __echo_socket_chatsvr_cli(pcli);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                break;
            }

            pcli->m_rdeidx += 1;
            pcli->m_rdeidx %= pcli->m_rdsize;
            pcli->m_rdlen += 1;
        }
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __insert_socket_chatsvr_cli(pchatsvr_cli_t pcli)
{
    int insertsock = 0;
    int removesock = 0;

    if (pcli->m_inrd > 0 || pcli->m_inwr > 0) {
        if ((pcli->m_evttype & READ_EVENT) == 0 && pcli->m_inrd > 0) {
            insertsock = 1;
        }
        if ((pcli->m_evttype & WRITE_EVENT) == 0 && pcli->m_inwr > 0) {
            insertsock = 1;
        }

        if ((pcli->m_evttype & READ_EVENT) != 0 && pcli->m_inrd == 0) {
            insertsock = 1;
        }

        if ((pcli->m_evttype & WRITE_EVENT) != 0 && pcli->m_inwr == 0) {
            insertsock = 1;
        }
    }

    if (pcli->m_inrd == 0 && pcli->m_inwr == 0) {
        removesock = 0;
    }

    if (insertsock > 0) {
        if (pcli->m_insertsock > 0) {
            assert!(pcli->m_sockfd >= 0);
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);
            pcli->m_insertsock = 0;
        }

        pcli->m_evttype = 0;
        if (pcli->m_inrd > 0) {
            pcli->m_evttype |= READ_EVENT;
        }

        if (pcli->m_inwr > 0) {
            pcli->m_evttype |= WRITE_EVENT;
        }

        pcli->m_sockfd = (int)get_tcp_real_handle(pcli->m_sock);
        ret = add_uxev_callback(pcli->m_pev,pcli->m_sockfd,pcli->m_evttype,chat_svr_cli_proc,pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        pcli->m_insertsock = 1;
    }

    if (removesock > 0) {
        if (pcli->m_insertsock > 0) {
            assert(pcli->m_sockfd >= 0);
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);
            pcli->m_insertsock = 0;
        }
        pcli->m_evttype = 0;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}


pchatsvr_cli_t __alloc_chatsvr_cli(void* parent,void* psock,void* pev)
{
    pchatsvr_cli_t pcli = NULL;
    int ret;

    pcli = (pchatsvr_cli_t) malloc(sizeof(*pcli));
    if (pcli == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pcli, 0, sizeof(*pcli));
    pcli->m_sock = psock;
    pcli->m_parent = parent;
    pcli->m_pev = pev;
    pcli->m_event = 0;
    pcli->m_pwbuf = NULL;
    pcli->m_wleft = 0;
    pcli->m_insertsock = 0;

    pcli->m_inrd = 0;
    pcli->m_inwr = 0;

    pcli->m_ppwbufs = NULL;
    pcli->m_ppwlens = NULL;
    pcli->m_wbufsize = 0;

    ret = __read_socket_chatsvr_cli(pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __insert_socket_chatsvr_cli(pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return pcli;
fail:
    __free_chatsvr_cli(&pcli);
    SETERRNO(ret);
    return NULL;
}



int add_server_client_socket(pchat_svr_t psvr, void* psock)
{
    pchatsvr_cli_t*parr = NULL;
    int nsize = 0;
    int ret;
    pchatsvr_cli_t pnewcli = NULL;
    nsize = psvr->m_clinum + 1;

    parr = (pchatsvr_cli_t*) malloc(sizeof(*parr) * nsize);
    if (parr == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(parr, 0, sizeof(*parr) * nsize);
    if (psvr->m_clinum > 0) {
        memcpy(parr, psvr->m_clis, sizeof(*parr) * psvr->m_clinum);
    }
    pnewcli = __alloc_chatsvr_cli(psock,psvr->m_pev);
    if (pnewcli == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    parr[psvr->m_clinum] = pnewcli;
    pnewcli = NULL;
    if (psvr->m_clis) {
        free(psvr->m_clis);
    }
    psvr->m_clis = parr;
    parr = NULL;
    psvr->m_clinum = nsize;
    return nsize;
    fail:
    if (parr) {
        free(parr);
    }
    parr = NULL;
    __free_chatsvr_cli(&pnewcli);
    SETERRNO(ret);
    return ret;
}

pchatsvr_cli_t __find_server_client(pchat_svr_t psvr, int sock)
{
    int i;
    for (i = 0; i < psvr->m_clinum; i++) {
        if (psvr->m_clis[i]->m_sock->get_tcp_real_handle() == (uint64_t)sock) {
            return psvr->m_clis[i];
        }
    }
    return NULL;
}

int remove_server_client_sock(pchat_svr_t psvr, int sock,int freed)
{
    int i;
    int nsize;
    pchatsvr_cli_t* parr = NULL;
    pchatsvr_cli_t poldcli = NULL;
    int finded = 0;
    int ret;
    poldcli = __find_server_client(psvr, sock);
    if (poldcli == NULL) {
        return 0;
    }

    nsize = psvr->m_clinum - 1;
    if (nsize > 0) {
        parr = (pchatsvr_cli_t*) malloc(sizeof(*parr) * nsize);
        if (parr == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        memset(parr, 0, sizeof(*parr) * nsize);
        for (i = 0; i < psvr->m_clinum; i++) {
            if (finded == 0) {
                if (psvr->m_clis[i] != poldcli) {
                    parr[i] = psvr->m_clis[i];
                } else if (psvr->m_clis[i] == poldcli) {
                    finded = 1;
                }
            } else  {
                if (i < nsize) {
                    parr[i] = psvr->m_clis[i + 1];
                }
            }
        }
    }

    if (freed) {
        __free_chatsvr_cli(&poldcli);    
    }    
    if (psvr->m_clis) {
        free(psvr->m_clis);
    }
    psvr->m_clis = parr;
    parr = NULL;
    psvr->m_clinum = nsize;
    return nsize;
fail:
    __free_chatsvr_cli(&poldcli);
    if (parr) {
        free(parr);
    }
    parr = NULL;
    SETERRNO(ret);
    return ret;
}

int __add_server_client_write_buffer(pchatsvr_cli_t pcli, uint8_t* pbuf, int len)
{
    uint8_t* pnewbuf = NULL;
    int nsize = 0;
    int ret;

    nsize = pcli->m_wleft + len;
    pnewbuf = (uint8_t*)malloc(sizeof(*pnewbuf) * nsize);
    if (pnewbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pnewbuf, 0, nsize);
    if (pcli->m_wleft > 0) {
        memcpy(pnewbuf, pcli->m_pwbuf, pcli->m_wleft);
    }
    memcpy(&pnewbuf[pcli->m_wleft], pbuf, len);
    if (pcli->m_pwbuf) {
        free(pcli->m_pwbuf);
    }
    pcli->m_pwbuf = pnewbuf;
    pnewbuf = NULL;
    pcli->m_wleft = nsize;
    return nsize;

    fail:
    if (pnewbuf) {
        free(pnewbuf);
    }
    pnewbuf = NULL;
    SETERRNO(ret);
    return ret;
}

int __shrink_server_client_write_buffer(pchatsvr_cli_t pcli, int len)
{
    int nsize = pcli->m_wleft - len;
    uint8_t* pnewbuf = NULL;
    int ret ;
    if (nsize > 0) {
        pnewbuf = (uint8_t*) malloc(sizeof(*pnewbuf) * nsize);
        if (pnewbuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        memcpy(pnewbuf, &pcli->m_pwbuf[len], nsize);
    }
    if (pcli->m_pwbuf) {
        free(pcli->m_pwbuf);
    }
    pcli->m_pwbuf = pnewbuf;
    pnewbuf = NULL;
    if (nsize > 0) {
        pcli->m_wleft = nsize;
    } else {
        pcli->m_wleft = 0;
    }
    return pcli->m_wleft;
    fail:
    if (pnewbuf) {
        free(pnewbuf);
    }
    pnewbuf = NULL;
    SETERRNO(ret);
    return ret;
}

int add_chatsvr_cli_buffer(pchat_svr_t psvr, int sock, uint8_t* pbuf, int len)
{
    pchatsvr_cli_t poldcli = NULL;
    poldcli = __find_server_client(psvr, sock);
    if (poldcli == NULL) {
        return 0;
    }

    return __add_server_client_write_buffer(poldcli, pbuf, len);
}

int shrink_chatsvr_cli_buffer(pchat_svr_t psvr, int sock, int len)
{
    pchatsvr_cli_t poldcli = NULL;
    poldcli = __find_server_client(psvr, sock);
    if (poldcli == NULL) {
        return 0;
    }
    return __shrink_server_client_write_buffer(poldcli, len);
}

void __free_chatsvr(pchat_svr_t* ppsvr)
{
    if (ppsvr && *ppsvr) {
        pchat_svr_t psvr = *ppsvr;
        int i;
        for (i = 0; i < psvr->m_clinum; i++) {
            __free_chatsvr_cli(&psvr->m_clis[i]);
        }
        free(psvr->m_clis);
        psvr->m_clis = NULL;
        psvr->m_clinum = 0;
        if (psvr->m_bindsock >= 0) {
            close(psvr->m_bindsock);
        }
        psvr->m_bindsock = -1;
        free(psvr);
        *ppsvr = NULL;
    }
}

int bind_chat_server(int port)
{
    int sock = -1;
    int ret;
    int reuse = 1;
    struct sockaddr_in sinaddr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret =   setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set reuse error [%d]\n", ret);
        goto fail;
    }

    ret = ioctl(sock, FIONBIO, &reuse);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "set non-block error[%d]\n", ret);
        goto fail;
    }

    memset(&sinaddr, 0, sizeof(sinaddr));
    sinaddr.sin_family = AF_INET;
    sinaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    sinaddr.sin_port = htons(port);
    ret = bind(sock, (struct sockaddr*)&sinaddr, sizeof(sinaddr));
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "bind [%d] error[%d]\n", port, ret);
        goto fail;
    }

    ret = listen(sock, 5);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "listen on [%d] error[%d]\n", port, ret);
        goto fail;
    }

    return sock;
    fail:
    if (sock >= 0) {
        close(sock);
    }
    sock = -1;
    SETERRNO(ret);
    return ret;
}


pchat_svr_t __alloc_chatsvr(int port)
{
    pchat_svr_t psvr = NULL;
    int ret;

    psvr = (pchat_svr_t)malloc(sizeof(*psvr));
    if (psvr == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(psvr, 0, sizeof(*psvr));
    psvr->m_bindsock = -1;
    psvr->m_clis = NULL;
    psvr->m_clinum = 0;

    psvr->m_bindsock = bind_chat_server(port);
    if (psvr->m_bindsock < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return psvr;
    fail:
    __free_chatsvr(&psvr);
    SETERRNO(ret);
    return NULL;
}

int read_server_notify(void* pev, uint64_t sock, int event, void* arg);

int write_server_notify(void* pev, uint64_t sock, int event, void* arg)
{
    pchatsvr_cli_t poldcli = NULL;
    pchat_svr_t psvr = (pchat_svr_t)arg;
    int ret;
    int wlen;
    if ((event & WRITE_EVENT) != 0) {
        poldcli = __find_server_client(psvr, sock);
        if (poldcli != NULL) {
            if (poldcli->m_wleft > 0)
                ret = write(sock, poldcli->m_pwbuf, poldcli->m_wleft);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            wlen = ret;
            ret = __shrink_server_client_write_buffer(poldcli, wlen);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            if (ret == 0) {
                ret = delete_uxev_callback(pev, sock);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                ret = add_uxev_callback(pev, sock, READ_EVENT, read_server_notify, pev);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                poldcli->m_event = READ_EVENT;
            }
        }
    }

    ret = read_server_notify(pev, sock, event, arg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    return 0;
    fail:
    SETERRNO(ret);
    return ret;
}

int read_server_notify(void* pev, uint64_t sock, int event, void* arg)
{
    char rbuf[1024];
    int rlen = 0;
    int clen ;
    pchatsvr_cli_t poldcli = NULL;
    pchat_svr_t psvr = (pchat_svr_t) arg;
    int ret;
    if ((event & READ_EVENT) != 0) {
        SETERRNO(0);
        poldcli = __find_server_client(psvr, sock);
        if (poldcli != NULL) {
            ret = read(sock, rbuf, sizeof(rbuf)-1);
            if (ret < 0) {
                GETERRNO_DIRECT(ret);
                if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == 0) {
                    return 0;
                }
                fprintf(stderr, "read sock error[%d]\n", ret);
                goto close_socket;
            } else if (ret == 0) {
                close_socket:
                ret = delete_uxev_callback(pev, sock);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                ret = remove_server_client_sock(psvr, sock);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
            } else {
                rlen = ret;
                rbuf[rlen] = 0;
                DEBUG_INFO("read [%s]",rbuf);
                ret = __add_server_client_write_buffer(poldcli, (uint8_t*)rbuf, rlen);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                DEBUG_BUFFER_FMT(poldcli->m_pwbuf,poldcli->m_wleft,"write %d socket",sock);
                ret = write(sock, poldcli->m_pwbuf, poldcli->m_wleft);
                if (ret < 0) {
                    if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
                        if ((poldcli->m_event & WRITE_EVENT) == 0) {
                            ret = delete_uxev_callback(pev, sock);
                            if (ret < 0) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            ret = add_uxev_callback(pev, sock, READ_EVENT | WRITE_EVENT, write_server_notify, arg);
                            if (ret < 0) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            poldcli->m_event = READ_EVENT | WRITE_EVENT;
                        }
                    }
                } else if (ret >= 0) {
                    clen = __shrink_server_client_write_buffer(poldcli, ret);
                    if (clen < 0) {
                        GETERRNO(ret);
                        goto fail;
                    } else if (clen == 0) {
                        if (poldcli->m_event != READ_EVENT) {
                            ret = delete_uxev_callback(pev, sock);
                            if (ret < 0) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            ret = add_uxev_callback(pev, sock, READ_EVENT, read_server_notify, arg);
                            if ( ret < 0 ) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            poldcli->m_event = READ_EVENT;
                        }

                    } else if (clen > 0) {
                        if (poldcli->m_event != (READ_EVENT | WRITE_EVENT)) {
                            ret = delete_uxev_callback(pev, sock);
                            if (ret < 0) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            ret = add_uxev_callback(pev, sock, READ_EVENT, write_server_notify, arg);
                            if ( ret < 0 ) {
                                GETERRNO(ret);
                                goto fail;
                            }
                            poldcli->m_event = READ_EVENT | WRITE_EVENT;
                        }
                    }
                }
            }
        }
    }

    return 0;
    fail:
    SETERRNO(ret);
    return ret;
}


int accept_server_notify(void* pev, uint64_t fd, int event, void* arg)
{
    struct sockaddr_in addr;
    socklen_t socklen;
    int connectfd = -1;
    int tmpfd = -1;
    int ret;
    int flags = 0;
    pchat_svr_t psvr = (pchat_svr_t) arg;
    socklen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    DEBUG_INFO("m_bindsock %d accept",psvr->m_bindsock);
    SETERRNO(0);    
    connectfd = accept(psvr->m_bindsock, (struct sockaddr*)&addr, &socklen);
    if (connectfd < 0) {
        GETERRNO_DIRECT(ret);
        if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR || ret == 0) {
            /*for next time*/
            return 0;
        }
        fprintf(stderr, "accept error [%d]\n", ret);
        goto fail;
    }

    flags = fcntl(connectfd, F_GETFD, 0);
    ret = fcntl(connectfd, F_SETFD, flags | O_NONBLOCK);
    if (ret < 0) {
        close(connectfd);
        connectfd = -1;
        return 0;
    }

    flags = 1;
    ret = setsockopt(connectfd,IPPROTO_TCP,TCP_NODELAY,&flags,sizeof(flags));
    if (ret < 0) {
        close(connectfd);
        connectfd = -1;
        return 0;
    }

    DEBUG_INFO("accept fd %d",connectfd);

    ret = add_server_client_socket(psvr, connectfd);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    tmpfd = connectfd;
    connectfd = -1;

    ret = add_uxev_callback(pev, tmpfd, READ_EVENT, read_server_notify, arg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return 0;
    fail:
    if (connectfd >= 0) {
        close(connectfd);
    }
    connectfd = -1;
    SETERRNO(ret);
    return ret;
}



int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int port = 3390;
    void* pev = NULL;
    int exitfd = -1;
    pchat_svr_t psvr = NULL;
    int flags;

    init_log_verbose(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        port = atoi(parsestate->leftargs[0]);
    }

    exitfd = init_sighandler();
    if (exitfd < 0) {
        GETERRNO(ret);
        goto out;
    }
    flags = fcntl(exitfd,F_GETFD);
    ret = fcntl(exitfd,F_SETFD,flags | O_NONBLOCK);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "init_uxev error[%d]\n", ret);
        goto out;
    }

    ret = add_uxev_callback(pev, exitfd, READ_EVENT, exit_fd_notify, NULL);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "add exit_fd_notify error[%d]\n", ret);
        goto out;
    }

    psvr = __alloc_chatsvr(port);
    if (psvr == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = add_uxev_callback(pev, psvr->m_bindsock, READ_EVENT, accept_server_notify, psvr);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("add_uxev_callback error[%d]",ret);
        goto out;
    }

    DEBUG_INFO("exitfd %d m_bindsock %d",exitfd, psvr->m_bindsock);
    ret = loop_uxev(pev);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("loop_uxev error[%d]",ret);
        goto out;
    }
    ret = 0;
    out:
    free_uxev(&pev);
    fini_sighandler();
    exitfd = -1;
    __free_chatsvr(&psvr);
    SETERRNO(ret);
    return ret;
}

typedef struct __chatcli {
    char* m_ip;
    void* m_pev;
    int m_insertsock;
    int m_insertstdin;
    int m_insertexit;
    int m_inserttimeout;
    int m_port;
    void* m_sock;
    int m_stdinfd;
    int m_sockfd;
    int m_exithd;
    uint64_t m_timeoutid;


    uint8_t* m_prdbuf;
    int m_rdsize;
    int m_rdlen;
    int m_rdsidx;
    int m_rdeidx;

    uint8_t* m_pwbuf;
    int m_wleft;
    uint8_t** m_ppwbufs;
    int* m_ppwlens;
    int m_wbufsize;

    uint8_t* m_stdinrdbuf;
    int m_stdinrdsize;
    int m_stdinrdsidx;
    int m_stdinrdeidx;
    int m_stdinrdlen;

    uint32_t m_evttype;
    int m_inrd;
    int m_inwr;
    int m_inconn;
} chatcli_t, *pchatcli_t;

void __free_chatcli(pchatcli_t* ppcli)
{
    if (ppcli && *ppcli) {
        int i;
        pchatcli_t pcli = *ppcli;
        if (pcli->m_insertsock > 0) {
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);
            pcli->m_insertsock = 0;
        }

        if (pcli->m_insertstdin > 0) {
            delete_uxev_callback(pcli->m_pev,pcli->m_stdinfd);
            pcli->m_insertstdin = 0;
        }

        if (pcli->m_insertexit > 0) {
            delete_uxev_callback(pcli->m_pev,pcli->m_exithd);
            pcli->m_insertexit = 0;
        }

        if (pcli->m_inserttimeout > 0) {
            del_uxev_timer(pcli->m_pev,pcli->m_timeoutid);
            pcli->m_inserttimeout = 0;
        }


        if (pcli->m_ip) {
            free(pcli->m_ip);
        }
        pcli->m_ip = NULL;
        free_socket(&pcli->m_sock);
        pcli->m_inrd = 0;
        pcli->m_inwr = 0;
        pcli->m_inconn = 0;
        pcli->m_stdinfd = -1;
        pcli->m_sockfd = -1;
        pcli->m_exithd = -1;
        pcli->m_timeoutid = 0;
        if (pcli->m_pwbuf) {
            free(pcli->m_pwbuf);
        }
        pcli->m_pwbuf = NULL;
        pcli->m_wleft = 0;

        if (pcli->m_ppwbufs) {
            for(i=0;i<pcli->m_wbufsize;i++) {
                if (pcli->m_ppwbufs[i] != NULL) {
                    free(pcli->m_ppwbufs[i]);
                    pcli->m_ppwbufs[i] = NULL;
                }
            }
            free(pcli->m_ppwbufs);
            pcli->m_ppwbufs = NULL;
        }

        if (pcli->m_ppwlens) {
            free(pcli->m_ppwlens);
            pcli->m_ppwlens = NULL;
        }

        pcli->m_wbufsize = 0;

        if (pcli->m_prdbuf) {
            free(pcli->m_prdbuf);
            pcli->m_prdbuf = NULL;
        }

        pcli->m_rdsize = 0;
        pcli->m_rdlen = 0;
        pcli->m_rdsidx = 0;
        pcli->m_rdeidx = 0;

        if (pcli->m_stdinrdbuf) {
            free(pcli->m_stdinrdbuf);
            pcli->m_stdinrdbuf = NULL;
        }
        pcli->m_stdinrdsize = 0;
        pcli->m_stdinrdsidx = 0;
        pcli->m_stdinrdeidx = 0;
        pcli->m_stdinrdlen = 0;

        free(pcli);
        *ppcli = NULL;
    }
}

int __write_stdout_chatcli(pchatcli_t pcli)
{
    uint8_t* pwbuf=NULL;
    int i;
    int cidx;
    int ret;

    if (pcli->m_rdlen == 0) {
        return 0;       
    }

    pwbuf = (uint8_t*) malloc(pcli->m_rdlen + 1);
    if (pwbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    memset(pwbuf,0,pcli->m_rdlen + 1);
    for(i=0;i<pcli->m_rdlen;i++) {
        cidx = pcli->m_rdsidx + i;
        cidx %= pcli->m_rdsize;
        pwbuf[i] = pcli->m_prdbuf[cidx];
    }

    pcli->m_rdlen = 0;
    pcli->m_rdsidx = pcli->m_rdeidx;

    fprintf(stdout,"%s",pwbuf);
    fflush(stdout);
    free(pwbuf);
    pwbuf = NULL;
    return 0;
fail:
    if (pwbuf)  {
        free(pwbuf);
        pwbuf = NULL;
    }
    SETERRNO(ret);
    return ret;
}

int chat_cli_proc(void* pev, uint64_t sock, int event, void* arg);
int chat_cli_timeout(void* pev, uint64_t timeid, int event, void* arg);

int __read_socket_chatcli(pchatcli_t pcli) 
{
    int ret;
    DEBUG_INFO("__read_socket_chatcli");
    if (pcli->m_inrd == 0) {
        DEBUG_INFO("__read_socket_chatcli");
        while(1) {
            if (pcli->m_rdlen == pcli->m_rdsize) {
                ret = __write_stdout_chatcli(pcli);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
            }

            ret = read_tcp_socket(pcli->m_sock,&(pcli->m_prdbuf[pcli->m_rdeidx]),1);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            } else if (ret == 0) {
                ret = __write_stdout_chatcli(pcli);
                if (ret < 0)  {
                    GETERRNO(ret);
                    goto fail;
                }
                pcli->m_inrd = 1;
                break;
            }
            pcli->m_rdlen += 1;
            pcli->m_rdeidx += 1;
            pcli->m_rdeidx %= pcli->m_rdsize;
            DEBUG_INFO("m_rdeidx %d",pcli->m_rdeidx);
        }
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __write_socket_chatcli(pchatcli_t pcli)
{
    int ret;
    int i;
    if (pcli->m_inwr == 0) {
        while(1) {
            if (pcli->m_pwbuf != NULL) {
                ret = write_tcp_socket(pcli->m_sock,pcli->m_pwbuf,pcli->m_wleft);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                } else if (ret == 0) {
                    pcli->m_inwr = 1;
                    break;
                }
                free(pcli->m_pwbuf);
                pcli->m_pwbuf = NULL;
                pcli->m_wleft = 0;
            }

            if (pcli->m_ppwbufs && pcli->m_ppwlens) {
                if (pcli->m_ppwbufs[0] != NULL) {
                    pcli->m_pwbuf = pcli->m_ppwbufs[0];
                    pcli->m_wleft = pcli->m_ppwlens[0];
                    for(i=1;i<pcli->m_wbufsize;i++) {
                        pcli->m_ppwlens[(i-1)] = pcli->m_ppwlens[i];
                        pcli->m_ppwbufs[(i-1)] = pcli->m_ppwbufs[i];
                    }
                    pcli->m_ppwbufs[(pcli->m_wbufsize - 1)] = NULL;
                    pcli->m_ppwlens[(pcli->m_wbufsize-1)] = 0;
                }
            }

            if (pcli->m_pwbuf == NULL) {
                pcli->m_inwr = 0;
                break;
            }
        }
    }
    return 0;

fail:
    SETERRNO(ret);
    return ret;
}

int __insert_chatcli_socket_write(pchatcli_t pcli)
{
    uint8_t* pwbuf= NULL;
    int wlen = 0;
    int fidx = -1;
    uint8_t** ppwbufs=NULL;
    int* ppwlens = NULL;
    int wbufsize=0;
    int ret;
    int i;
    int cidx;

    if (pcli->m_stdinrdlen == 0) {
        return 0;
    }

    wlen = pcli->m_stdinrdlen ;
    pwbuf = (uint8_t*) malloc(wlen + 1);
    if (pwbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pwbuf,0,wlen + 1);

    for(i=0;i<pcli->m_stdinrdlen;i++) {
        cidx = pcli->m_stdinrdsidx + i;
        cidx %= pcli->m_stdinrdsize;
        pwbuf[i] = pcli->m_stdinrdbuf[cidx];
    }

    pcli->m_stdinrdlen = 0;
    pcli->m_stdinrdsidx = pcli->m_stdinrdeidx;

    if (pcli->m_pwbuf == NULL) {
        pcli->m_pwbuf = pwbuf;
        pcli->m_wleft = wlen;
        pwbuf = NULL;
        wlen =  0;
    } else {
        for(i=0;i<pcli->m_wbufsize;i++) {
            if (pcli->m_ppwbufs[i] == NULL) {
                fidx = i;
                break;
            }
        }

        if (fidx >= 0) {
            pcli->m_ppwbufs[fidx] = pwbuf;
            pcli->m_ppwlens[fidx] = wlen;
            pwbuf = NULL;
            wlen = 0;
        } else {
            if (pcli->m_wbufsize == 0) {
                wbufsize = 4;
            } else {
                wbufsize = pcli->m_wbufsize << 1;
            }

            ppwbufs = (uint8_t**) malloc(sizeof(*ppwbufs) * wbufsize);
            ppwlens = (int*) malloc(sizeof(*ppwlens) * wbufsize);
            if (ppwbufs == NULL || ppwlens == NULL) {
                GETERRNO(ret);
                goto fail;
            }
            memset(ppwbufs,0, sizeof(*ppwbufs) * wbufsize);
            memset(ppwlens,0, sizeof(*ppwlens) * wbufsize);
            if (pcli->m_wbufsize > 0) {
                memcpy(ppwbufs,pcli->m_ppwbufs,sizeof(*ppwbufs) * pcli->m_wbufsize);
                memcpy(ppwlens,pcli->m_ppwlens,sizeof(*ppwlens) * pcli->m_wbufsize);
            }

            ppwbufs[pcli->m_wbufsize] = pwbuf;
            ppwlens[pcli->m_wbufsize] = wlen;
            pwbuf = NULL;
            wlen = 0;
            if (pcli->m_ppwbufs) {
                free(pcli->m_ppwbufs);
            }
            pcli->m_ppwbufs = ppwbufs;
            if (pcli->m_ppwlens) {
                free(pcli->m_ppwlens);
            }
            pcli->m_ppwlens = ppwlens;
            ppwbufs = NULL;
            ppwlens = NULL;
            pcli->m_wbufsize = wbufsize;
        }
    }

    ret = __write_socket_chatcli(pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    return 1;
fail:
    if (ppwbufs) {
        free(ppwbufs);
    }
    ppwbufs = NULL;
    if (ppwlens) {
        free(ppwlens);
    }
    ppwlens = NULL;

    if (pwbuf) {
        free(pwbuf);
    }
    pwbuf = NULL;
    wlen = 0;
    SETERRNO(ret);
    return ret;
}

int __read_stdin_chatcli(pchatcli_t pcli)
{
    int ret;
    while(1) {
        if (pcli->m_stdinrdlen == pcli->m_stdinrdsize) {
            ret = __insert_chatcli_socket_write(pcli);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }

        ret = read(pcli->m_stdinfd,&(pcli->m_stdinrdbuf[pcli->m_stdinrdeidx]),1);
        if (ret < 0) {
            GETERRNO(ret);
            if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR) {
                ret = __insert_chatcli_socket_write(pcli);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                break;
            }
            ERROR_INFO("failed [%d]",ret);
            goto fail;
        } else if (ret == 0) {
            ret = __insert_chatcli_socket_write(pcli);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            break;
        }

        pcli->m_stdinrdeidx += 1;
        pcli->m_stdinrdeidx %= pcli->m_stdinrdsize;
        pcli->m_stdinrdlen += 1;
        DEBUG_INFO("read %d",pcli->m_stdinrdeidx);
    }


    if (pcli->m_insertstdin == 0) {
        ret = add_uxev_callback(pcli->m_pev,pcli->m_stdinfd,READ_EVENT,chat_cli_proc,pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        pcli->m_insertstdin = 1;
        DEBUG_INFO("insert stdin");
    }

    return 0;

fail:
    SETERRNO(ret);
    return ret;
}


int __insert_socket_chatcli(pchatcli_t pcli)
{
    int insertsock = 0;
    int removesock = 0;
    int ret;

    if(pcli->m_inrd || pcli->m_inwr || pcli->m_inconn) {
        if ((pcli->m_evttype & READ_EVENT) == 0 && (pcli->m_inrd > 0 )) {
            insertsock = 1;
        }
        if ((pcli->m_evttype & WRITE_EVENT) == 0 && (pcli->m_inwr > 0 || pcli->m_inconn > 0 )) {
            insertsock = 1;
        }


        if ((pcli->m_evttype & READ_EVENT) != 0 && ( pcli->m_inrd == 0)) {
            insertsock = 1;
        }

        if ((pcli->m_evttype & WRITE_EVENT) != 0 && ((pcli->m_inwr == 0 && pcli->m_inconn == 0 ))) {
            insertsock = 1;
        }
    }

    if (pcli->m_inrd == 0 && pcli->m_inwr == 0 && pcli->m_inconn == 0) {
        removesock = 1;
    }

    if (insertsock > 0) {
        pcli->m_evttype = 0;
        if ((pcli->m_inrd > 0 )) {
            pcli->m_evttype |= READ_EVENT;
        }

        if (pcli->m_inwr > 0 || pcli->m_inconn > 0) {
            pcli->m_evttype |= WRITE_EVENT;
        }

        if (pcli->m_insertsock > 0) {
            assert(pcli->m_sockfd >= 0);
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);
            pcli->m_insertsock = 0;
        }

        pcli->m_sockfd = get_tcp_real_handle(pcli->m_sock);
        DEBUG_INFO("add [%d] sockfd m_evttype 0x%x",pcli->m_sockfd,pcli->m_evttype);
        ret = add_uxev_callback(pcli->m_pev,pcli->m_sockfd,pcli->m_evttype,chat_cli_proc,pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        pcli->m_insertsock = 1;
    }

    if (removesock > 0) {
        if (pcli->m_insertsock > 0) {
            delete_uxev_callback(pcli->m_pev,pcli->m_sockfd);   
        }
        pcli->m_insertsock = 0;
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

pchatcli_t __alloc_chatcli(const char* ip, int port,void* pev, int readfd,int exithd)
{
    pchatcli_t pcli = NULL;
    int ret;

    pcli = (pchatcli_t) malloc(sizeof(*pcli));
    if (pcli == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    memset(pcli, 0, sizeof(*pcli));
    pcli->m_ip = NULL;
    pcli->m_pev = pev;
    pcli->m_port = 0;
    pcli->m_sock = NULL;
    pcli->m_insertsock = 0;
    pcli->m_insertstdin = 0;
    pcli->m_insertexit = 0;
    pcli->m_stdinfd = readfd;
    pcli->m_exithd = exithd;
    pcli->m_sockfd = -1;
    pcli->m_timeoutid = 0;


    pcli->m_pwbuf = NULL;
    pcli->m_wleft = 0;
    pcli->m_ppwbufs = NULL;
    pcli->m_ppwlens = NULL;
    pcli->m_wbufsize = 0;


    pcli->m_inconn = 0;
    pcli->m_inrd = 0;
    pcli->m_inwr = 0;

    pcli->m_evttype = 0;

    pcli->m_prdbuf = NULL;
    pcli->m_rdsize = 0;
    pcli->m_rdlen = 0;
    pcli->m_rdsidx = 0;
    pcli->m_rdeidx = 0;

    pcli->m_stdinrdbuf = NULL;
    pcli->m_stdinrdsize = 0;
    pcli->m_stdinrdsidx = 0;
    pcli->m_stdinrdeidx = 0;
    pcli->m_stdinrdlen = 0;

    pcli->m_ip = strdup(ip);
    if (pcli->m_ip == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    pcli->m_port = port;

    pcli->m_sock = connect_tcp_socket(pcli->m_ip,pcli->m_port,NULL,0,0);
    if (pcli->m_sock == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pcli->m_rdsize = 256;
    pcli->m_prdbuf = (uint8_t*)malloc(pcli->m_rdsize);
    if (pcli->m_prdbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pcli->m_stdinrdsize = 256;
    pcli->m_stdinrdbuf = (uint8_t*)malloc(pcli->m_stdinrdsize);
    if (pcli->m_stdinrdbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pcli->m_sockfd = get_tcp_connect_handle(pcli->m_sock);
    if (pcli->m_sockfd < 0) {
        DEBUG_INFO("connected");
        /*now to read*/
        ret = __read_socket_chatcli(pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        ret = __read_stdin_chatcli(pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    } else {
        DEBUG_INFO("sockfd %d",pcli->m_sockfd);
        pcli->m_inconn = 1;
        ret = add_uxev_timer(pcli->m_pev,5000,0,&pcli->m_timeoutid,chat_cli_timeout,pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        pcli->m_inserttimeout = 1;
    }

    ret = __insert_socket_chatcli(pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = add_uxev_callback(pcli->m_pev,pcli->m_exithd,READ_EVENT,chat_cli_proc,pcli);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    pcli->m_insertexit = 1;

    return pcli;
    fail:
    __free_chatcli(&pcli);
    SETERRNO(ret);
    return NULL;
}


int chat_cli_timeout(void* pev, uint64_t timeid, int event, void* arg)
{
    pchatcli_t pcli = (pchatcli_t)arg;
    DEBUG_INFO("timeout ");
    break_uxev(pev);
    fprintf(stderr, "connect %s:%d timeout\n", pcli->m_ip, pcli->m_port);
    return 0;
}

int chat_cli_proc(void* pev, uint64_t sock, int event,void* arg)
{
    pchatcli_t pcli = (pchatcli_t) arg;
    int completed;
    int ret;
    DEBUG_INFO("sock 0x%x event 0x%x",sock,event);
    if (sock == (uint64_t)pcli->m_sockfd) {
        if ((event & READ_EVENT) != 0) {
            if (pcli->m_inrd > 0) {
                completed = complete_tcp_read(pcli->m_sock);
                if (completed > 0) {
                    pcli->m_inrd = 0;
                    /*to make one step*/
                    pcli->m_rdlen += 1;
                    pcli->m_rdeidx += 1;
                    pcli->m_rdeidx %= pcli->m_rdsize;
                    ret = __read_socket_chatcli(pcli);
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                }
            }
        }

        if ((event & WRITE_EVENT) != 0) {
            if (pcli->m_inwr > 0) {
                completed = complete_tcp_write(pcli->m_sock);
                if (completed > 0) {
                    pcli->m_inwr = 0;
                    ret = __write_socket_chatcli(pcli);
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                }
            }  else if (pcli->m_inconn > 0) {
                completed = complete_tcp_connect(pcli->m_sock);
                if (completed > 0) {
                    if (pcli->m_inserttimeout > 0)  {
                        del_uxev_timer(pcli->m_pev,pcli->m_timeoutid);
                        pcli->m_inserttimeout = 0;
                    }

                    pcli->m_inconn = 0;
                    ret = __read_socket_chatcli(pcli);
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                    ret = __read_stdin_chatcli(pcli);
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                }
            }
        }

        ret=  __insert_socket_chatcli(pcli);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (sock == (uint64_t)pcli->m_exithd) {
        ret = break_uxev(pev);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (sock == (uint64_t)pcli->m_stdinfd) {
        if ((event & READ_EVENT) != 0) {
            ret = __read_stdin_chatcli(pcli);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }
    }

    return 0;

fail:
    SETERRNO(ret);
    return ret;
}

int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* ip = (char*)"127.0.0.1";
    int port = 4091;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    pchatcli_t pcli = NULL;
    void* pev=NULL;
    struct termios term,oldterm;
    int exithd;
    int echodisabled =  0;
    int flags;


    init_log_verbose(pargs);

    if (parsestate->leftargs) {
        if (parsestate->leftargs[0]) {
            ip = parsestate->leftargs[0];
            if (parsestate->leftargs[1]) {
                port = atoi(parsestate->leftargs[1]);
            }
        }
    }

    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not init_uxev error[%d]",ret);
        goto out;
    }

    ret = tcgetattr(fileno(stdin),&oldterm);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("tcgetattr error [%d]",ret);
        goto out;
    }
    memcpy(&term,&oldterm,sizeof(oldterm));

    term.c_lflag &= ~(ECHO | ICANON);

    ret = tcsetattr(fileno(stdin),TCSAFLUSH,&term);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("tcsetattr error [%d]",ret);
        goto out;
    }
    echodisabled = 1;

    flags = fcntl(fileno(stdin),F_GETFL,0);
    fcntl(fileno(stdin),F_SETFL, O_NONBLOCK | flags);

    exithd = init_sighandler();
    if (exithd < 0) {
        GETERRNO(ret);
        ERROR_INFO("cannot init init_sighandler error [%d]", ret);
        goto out;
    }

    pcli = __alloc_chatcli(ip,port,pev,fileno(stdin),exithd);
    if (pcli == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }


    ret = loop_uxev(pev);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (echodisabled) {
        tcsetattr(fileno(stdin),TCSAFLUSH,&oldterm);
        echodisabled = 0;
    }

    __free_chatcli(&pcli);
    free_uxev(&pev);
    fini_sighandler();
    SETERRNO(ret);
    return ret;
}

int noechopass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    struct termios term;
    int stdinfd = fileno(stdin);
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char passwd[256];
    char* ptr=NULL;

    init_log_verbose(pargs);

    ret = tcgetattr(stdinfd,&term);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "tcgetattr error %d\n", ret);
        goto out;
    }

    term.c_lflag &= ~ECHO;

    ret = tcsetattr(stdinfd,0,&term);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "tcsetattr error %d\n", ret);
        goto out;
    }

    fprintf(stdout,"please enter password:");
    fflush(stdout);
    memset(passwd,0,sizeof(passwd));
    fgets(passwd,sizeof(passwd),stdin);
    ptr = passwd;
    while(*ptr != '\0') {
        if (*ptr == '\r' || *ptr == '\n') {
            *ptr = '\0';
            break;
        }
        ptr ++;
    }

    term.c_lflag |= ECHO;
    ret = tcsetattr(stdinfd,0,&term);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "retcsetattr error %d\n", ret);
        goto out;
    }

    fprintf(stdout,"\npassword [%s]\n",passwd);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}