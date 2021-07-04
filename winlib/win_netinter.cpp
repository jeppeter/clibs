#pragma warning(push)

#pragma warning(disable:4668)
#pragma warning(disable:4820)
#pragma warning(disable:4365)
#pragma warning(disable:4574)

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <win_netinter.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_types.h>

#pragma warning(pop)

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")


#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif

int __fill_addr(char* pbuf, int bufsize, struct sockaddr *psockaddr, const char *fmt, ...)
{
    int ret;
    TCHAR *pIpAddr = NULL;
    int ipaddrsize = 0;
    char* pcipaddr = NULL;
    int cipaddrsize = 0;
    TCHAR *pIpRet = NULL;
    struct sockaddr_in *psock4addr = NULL;
    struct sockaddr_in6 *psock6addr = NULL;
    char* pnotice = NULL;
    int noticesize = 0;
    va_list ap = NULL;

    if (fmt != NULL) {
        va_start(ap, fmt);
        ret = vsnprintf_safe(&pnotice, &noticesize, fmt, ap);
        if (ret < 0) {
            goto fail;
        }
    }
    if (psockaddr->sa_family == AF_INET) {
get_ip4_addr_again:
        psock4addr = (struct sockaddr_in*) psockaddr;
        pIpRet = (TCHAR*)InetNtop(AF_INET, &(psock4addr->sin_addr), pIpAddr, (size_t)ipaddrsize);
        if (pIpRet == NULL) {
            ret = WSAGetLastError() ? -(int) WSAGetLastError() : -1;
            if (ret != -WSAEINVAL) {
                ERROR_INFO("trans (%s) address error(%d)", pnotice ? pnotice : "Unknown", ret);
                goto fail;
            }
            if (ipaddrsize == 0) {
                ipaddrsize = 32*sizeof(TCHAR);
            } else {
                ipaddrsize <<= 1;
            }

            if (pIpAddr) {
                free(pIpAddr);
            }
            pIpAddr = NULL;
            pIpAddr = (TCHAR*) malloc((size_t)ipaddrsize);
            if (pIpAddr == NULL) {
                GETERRNO(ret);
                ERROR_INFO("can not alloc(%d) error(%d)", ipaddrsize, ret);
                goto fail;
            }
            goto get_ip4_addr_again;
        }
        ret = TcharToAnsi(pIpAddr, &pcipaddr, &cipaddrsize);
        if (ret < 0) {
            goto fail;
        }
        strncpy_s(pbuf, (size_t)bufsize, pcipaddr, (size_t)bufsize);
    } else if (psockaddr->sa_family == AF_INET6) {
get_ip6_addr_again:
        psock6addr = (struct sockaddr_in6*) psockaddr;
        pIpRet = (TCHAR*)InetNtop(AF_INET6, &(psock6addr->sin6_addr), pIpAddr, (size_t)ipaddrsize);
        if (pIpRet == NULL) {
            ret = WSAGetLastError() ? -(int) WSAGetLastError() : -1;
            if (ret != -WSAEINVAL) {
                ERROR_INFO("trans (%s) address error(%d)", pnotice ? pnotice : "Unknown", ret);
                goto fail;
            }
            if (ipaddrsize == 0) {
                ipaddrsize = 64*sizeof(TCHAR);
            } else {
                ipaddrsize <<= 1;
            }
            if (pIpAddr) {
                free(pIpAddr);
            }
            pIpAddr = NULL;
            pIpAddr = (TCHAR*) malloc((size_t)ipaddrsize);
            if (pIpAddr == NULL) {
                GETERRNO(ret);
                ERROR_INFO("can not alloc(%d) error(%d)", ipaddrsize, ret);
                goto fail;
            }
            goto get_ip6_addr_again;
        }
        ret = TcharToAnsi(pIpAddr, &pcipaddr, &cipaddrsize);
        if (ret < 0) {
            goto fail;
        }
        strncpy_s(pbuf, (size_t)bufsize,pcipaddr, (size_t)bufsize);
    } else {
        memset(pbuf, 0, (size_t)bufsize);
    }


    TcharToAnsi(NULL, &pcipaddr, &cipaddrsize);
    if (pIpAddr) {
        free(pIpAddr);
    }
    pIpAddr = NULL;
    ipaddrsize = 0;
    vsnprintf_safe(&pnotice, &noticesize, NULL, ap);
    return 0;
fail:
    TcharToAnsi(NULL, &pcipaddr, &cipaddrsize);
    if (pIpAddr) {
        free(pIpAddr);
    }
    pIpAddr = NULL;
    ipaddrsize = 0;
    vsnprintf_safe(&pnotice, &noticesize, NULL, ap);
    SETERRNO(-ret);
    return ret;
}

int __get_mask(char* pbuf, int bufsize, ADDRESS_FAMILY inettype, PIP_ADAPTER_PREFIX padapterprefix, const char* fmt, ...)
{
    PIP_ADAPTER_PREFIX pfirst = NULL, plast = NULL, pcurprefix = NULL;
    int cnt = 0;
    struct sockaddr *psockaddr;
    struct sockaddr_in *psock4addr;
    struct sockaddr_in6 *psock6addr;
    uint8_t result[16], sockaddr[32];
    uint8_t *pf8, *pl8;
    int socklen, i;
    char* pstr = NULL;
    int ssize = 0;
    va_list ap = NULL;
    int ret = -1;
    int nret = 0;

    if (fmt) {
        va_start(ap, fmt);
        ret = vsnprintf_safe(&pstr, &ssize, fmt, ap);
        if (ret < 0) {
            goto fail;
        }
    }

    pcurprefix = padapterprefix;
    cnt = 0;
    while (pcurprefix) {
        psockaddr = (struct sockaddr*)pcurprefix->Address.lpSockaddr;
        if (psockaddr->sa_family == inettype) {
            if (cnt == 0) {
                pfirst = pcurprefix;
            } else if (cnt == 2) {
                plast = pcurprefix;
            }
            cnt ++;
        }
        pcurprefix = pcurprefix->Next;
    }

    if (pfirst && plast) {
        memset(result, 0xff, sizeof(result));
        memset(sockaddr, 0, sizeof(sockaddr));

        /*now we should make the result*/
        socklen = 0;
        if (inettype == AF_INET) {
            psock4addr = (struct sockaddr_in*) pfirst->Address.lpSockaddr;
            pf8 = (uint8_t*) & (psock4addr->sin_addr);
            psock4addr = (struct sockaddr_in*) plast->Address.lpSockaddr;
            pl8 = (uint8_t*) & (psock4addr->sin_addr);
            socklen = 4;

            for (i = 0; i < socklen; i++) {
                if (pl8[i] != pf8[i]) {
                    result[i] = (uint8_t)(pl8[i] & pf8[i]);
                }
            }

            psockaddr = (struct sockaddr*) sockaddr;
            psock4addr = (struct sockaddr_in*) sockaddr;
            psockaddr->sa_family = AF_INET;
            memcpy(&(psock4addr->sin_addr), result, (size_t)socklen);
            ret = __fill_addr(pbuf, bufsize, psockaddr, "%s", pstr ? pstr : "Unknown");
            if (ret < 0) {
                goto fail;
            }
            nret = ret;
        } else if (inettype == AF_INET6) {
            psock6addr = (struct sockaddr_in6*)pfirst->Address.lpSockaddr;
            pf8 = (uint8_t*) & (psock6addr->sin6_addr);
            psock6addr = (struct sockaddr_in6*)plast->Address.lpSockaddr;
            pl8 = (uint8_t*) & (psock6addr->sin6_addr);
            socklen = 16;
            for (i = 0; i < socklen; i++) {

                if (pl8[i] != pf8[i]) {
                    result[i] = (uint8_t)(pl8[i] & pf8[i]);
                } else if (pl8[i] == 0) {
                    result[i] = 0;
                }
            }

            psockaddr = (struct sockaddr*) sockaddr;
            psock6addr = (struct sockaddr_in6*) sockaddr;
            psockaddr->sa_family = AF_INET6;
            memcpy(&(psock6addr->sin6_addr), result, (size_t)socklen);
            ret = __fill_addr(pbuf, bufsize, psockaddr, "%s", pstr ? pstr : "Unknown");
            if (ret < 0) {
                goto fail;
            }
            nret = ret;
        }


    }

    vsnprintf_safe(&pstr, &ssize, NULL, ap);
    return nret;

fail:
    vsnprintf_safe(&pstr, &ssize, NULL, ap);
    SETERRNO(-ret);
    return ret;
}

int get_all_adapter_info(int freed, char* pfilter, pnet_inter_info_t* ppinfos, int *pinfonum)
{
    pnet_inter_info_t pRetInfo = *ppinfos;
    int retinfos = *pinfonum;
    int retsize = 0;
    int nret;
    int ret;
    void *pbuffer = NULL;
    int bufsize = 0;
    char* pformatbuf = NULL;
    int formatsize = 0;
    char* pansibuf = NULL;
    int ansisize = 0;
    ULONG  outsize = 0;
    DWORD dret;
    int curidx;
    int isok;
    PIP_ADAPTER_ADDRESSES pAddress = NULL, pcuraddr = NULL;
    ULONG family, flags;
    int i;
    int prefixsize = 0;

    if (freed) {
        if (*ppinfos) {
            free(*ppinfos);
        }
        *ppinfos = NULL;
        *pinfonum = 0;
        return 0;
    }

    family = AF_UNSPEC;
    flags = GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
get_addr_again:
    pAddress = (PIP_ADAPTER_ADDRESSES)pbuffer;
    outsize = (ULONG)bufsize;
    dret =  GetAdaptersAddresses(family, flags, NULL, pAddress, &outsize);
    if (dret != ERROR_SUCCESS) {
        if (dret != ERROR_BUFFER_OVERFLOW) {
            ret = - (int) dret;
            ERROR_INFO("can not get adapter address error(%d)", ret);
            goto fail;
        }

        if (bufsize == 0) {
            bufsize = (int)outsize;
        } else {
            bufsize <<= 1;
        }
        if (pbuffer) {
            free(pbuffer);
        }
        pbuffer = NULL;
        pbuffer = malloc((size_t)bufsize);
        if (pbuffer == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc(%d) error(%d)", bufsize, ret);
            goto fail;
        }
        goto get_addr_again;
    }

fill_again:
    curidx = 0;
    pcuraddr = pAddress;
    while (pcuraddr != NULL) {
        isok = 0;
        if (pfilter == NULL ) {
            isok = 1;
        } else if (pfilter) {
            if (pcuraddr->FriendlyName) {
                ret = UnicodeToAnsi(pcuraddr->FriendlyName, &pansibuf, &ansisize);
                if (ret < 0) {
                    goto fail;
                }
                if (_stricmp(pansibuf, pfilter) == 0) {
                    isok = 1;
                }

            }
        }

        if (isok) {
            if (curidx >= retinfos || pRetInfo == NULL) {
                goto alloc_infos;
            }
            strncpy_s(pRetInfo[curidx].m_adaptername, sizeof(pRetInfo[curidx].m_adaptername), pcuraddr->AdapterName, sizeof(pRetInfo[curidx].m_adaptername));
            if (pcuraddr->FriendlyName) {
                ret = UnicodeToAnsi(pcuraddr->FriendlyName, &pansibuf, &ansisize);
                if (ret < 0) {
                    goto fail;
                }
                strncpy_s(pRetInfo[curidx].m_adapternickname, sizeof(pRetInfo[curidx].m_adapternickname),pansibuf, sizeof(pRetInfo[curidx].m_adapternickname));
            }

            memset(pRetInfo[curidx].m_adaptermac, 0, sizeof(pRetInfo[curidx].m_adaptermac));
            if (pformatbuf) {
                memset(pformatbuf, 0, (size_t)formatsize);
            }
            for (i = 0; i < (int) pcuraddr->PhysicalAddressLength; i++) {
                if (i == 0) {
                    ret = append_snprintf_safe(&pformatbuf, &formatsize, "%02x", pcuraddr->PhysicalAddress[i]);
                } else {
                    ret = append_snprintf_safe(&pformatbuf, &formatsize, ":%02x", pcuraddr->PhysicalAddress[i]);
                }

                if (ret < 0) {
                    goto fail;
                }
            }

            strncpy_s(pRetInfo[curidx].m_adaptermac,  sizeof(pRetInfo[curidx].m_adaptermac),pformatbuf, sizeof(pRetInfo[curidx].m_adaptermac));
            pRetInfo[curidx].m_mtu = (int)pcuraddr->Mtu;
            if (pcuraddr->FirstUnicastAddress) {
                PIP_ADAPTER_UNICAST_ADDRESS pcuruni = pcuraddr->FirstUnicastAddress;
                /*now we should get the ip address */
                while (pcuruni) {
                    struct sockaddr* psockaddr = pcuruni->Address.lpSockaddr;
                    if (psockaddr->sa_family == AF_INET) {
                        ret = __fill_addr(pRetInfo[curidx].m_adapterip4, sizeof(pRetInfo[curidx].m_adapterip4),
                                          psockaddr, "[%d]%s ipv4", curidx, pRetInfo[curidx].m_adapternickname);
                        if (ret < 0) {
                            goto fail;
                        }
                    } else if (psockaddr->sa_family == AF_INET6) {
                        ret = __fill_addr(pRetInfo[curidx].m_adapterip6, sizeof(pRetInfo[curidx].m_adapterip6),
                                          psockaddr, "[%d]%s ipv6", curidx, pRetInfo[curidx].m_adapternickname);
                        if (ret < 0) {
                            goto fail;
                        }
                    }
                    pcuruni = pcuruni->Next;
                }
            }

            /*now get the dns address*/
            if (pcuraddr->FirstDnsServerAddress) {
                ret = __fill_addr(pRetInfo[curidx].m_adapterdns, sizeof(pRetInfo[curidx].m_adapterdns),
                                  pcuraddr->FirstDnsServerAddress->Address.lpSockaddr, "[%d]%s dns", curidx, pRetInfo[curidx].m_adapternickname);
                if (ret < 0) {
                    goto fail;
                }
            }

            if (pcuraddr->FirstGatewayAddress) {
                ret = __fill_addr(pRetInfo[curidx].m_adaptergw, sizeof(pRetInfo[curidx].m_adaptergw),
                                  pcuraddr->FirstGatewayAddress->Address.lpSockaddr, "[%d]%s gateway", curidx, pRetInfo[curidx].m_adapternickname);
                if (ret < 0) {
                    goto fail;
                }
            }

            if (pcuraddr->FirstPrefix) {
                ret = __get_mask(pRetInfo[curidx].m_adaptermask4, sizeof(pRetInfo[curidx].m_adaptermask4), AF_INET,
                                 pcuraddr->FirstPrefix, "[%d]%s mask4", curidx, pRetInfo[curidx].m_adapternickname);
                if (ret < 0) {
                    goto fail;
                }

                ret = __get_mask(pRetInfo[curidx].m_adaptermask6, sizeof(pRetInfo[curidx].m_adaptermask6), AF_INET6,
                                 pcuraddr->FirstPrefix, "[%d]%s mask6", curidx, pRetInfo[curidx].m_adapternickname);
                if (ret < 0) {
                    goto fail;
                }
            }
            curidx ++;
        }
        pcuraddr = pcuraddr->Next;
    }

    nret = curidx;

    UnicodeToAnsi(NULL, &pansibuf, &ansisize);
    append_snprintf_safe(&pformatbuf, &formatsize, NULL);
    prefixsize = 0;
    if (pbuffer) {
        free(pbuffer);
    }
    pbuffer = NULL;
    bufsize = 0;
    outsize = 0;


    if (*ppinfos && pRetInfo != *ppinfos) {
        free(*ppinfos);
    }
    *ppinfos = pRetInfo;
    *pinfonum = retinfos;

    return nret;
fail:
    UnicodeToAnsi(NULL, &pansibuf, &ansisize);
    append_snprintf_safe(&pformatbuf, &formatsize, NULL);
    if (pRetInfo && pRetInfo != *ppinfos) {
        free(pRetInfo);
    }
    pRetInfo = NULL;
    prefixsize = 0;
    if (pbuffer) {
        free(pbuffer);
    }
    pbuffer = NULL;
    bufsize = 0;
    outsize = 0;
    SETERRNO(-ret);
    return ret;

alloc_infos:
    if (pRetInfo && pRetInfo != *ppinfos) {
        free(pRetInfo);
    }
    pRetInfo = NULL;
    if (retinfos == 0) {
        retinfos = 2;
    } else {
        retinfos <<= 1;
    }

    retsize = (int)(retinfos * sizeof(*pRetInfo));
    pRetInfo = (pnet_inter_info_t)malloc((size_t)retsize);
    if (pRetInfo == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc(%d) error(%d)", retsize, ret);
        goto fail;
    }
    memset(pRetInfo, 0, (size_t)retsize);
    goto fill_again;
#if 0    
    ret = -ERROR_INVALID_DATA;
    SETERRNO(-ret);
    return ret;
#endif
}



int __set_adapter(pnet_inter_info_t pinfo, int idx,int forced)
{
    /*now we should give the */
    pinfo = pinfo;
    idx = idx;
    forced = forced;
    return 0;
}


int set_adapter_info(pnet_inter_info_t pinfo)
{
#if 0
    pnet_inter_info_t pinfos=NULL;
    int infosize=0;
    int infonum=0;
    int infoidx=-1, adpidx=-1;
    int ret;


    get_all_adapter_info(1,NULL,&pinfos,&infosize);    
    return 0;
fail_reset:
    if (infoidx >= 0) {
        /*now we should give the set*/
        __set_adapter(&(pinfos[infoidx]),adpidx,1);
    }
fail:
    get_all_adapter_info(1,NULL,&pinfos,&infosize);
    SETERRNO(ret);
    return ret;
#endif
    pinfo = pinfo;
    return 0;
}

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif