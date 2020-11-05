
int findwindow_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i, j;
    int pid = -1;
    int ret = 0;
    int totalret = 0;
    HWND* pwnd = NULL;
    pargs_options_t poption = (pargs_options_t) popt;
    argv = argv;
    argc = argc;
    int wndsize = 0;
    init_log_level(poption);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            pid = atoi(parsestate->leftargs[i]);
            ret = get_win_handle_by_classname(poption->m_classname, pid, &pwnd, &wndsize);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "can not get [%d] class[%s] error[%d]\n", pid, poption->m_classname, ret);
                continue;
            }
            fprintf(stdout, "get [%d] class [%s]:", pid, poption->m_classname);
            for (j = 0; j < ret; j++) {
                if ((j % 5) == 0) {
                    fprintf(stdout, "\n    ");
                }
                fprintf(stdout, " 0x%p", pwnd[j]);
            }
            fprintf(stdout, "\n");
        }

    } else {
        ret = get_win_handle_by_classname(poption->m_classname, -1, &pwnd, &wndsize);
        if (ret < 0) {
            GETERRNO(ret);
            totalret = ret;
            fprintf(stderr, "can not get [%s] on pid[%d] error[%d]\n", poption->m_classname, pid, ret);
            goto out;
        }
        fprintf(stdout, "get class [%s]:", poption->m_classname);
        for (j = 0; j < ret; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n    ");
            }
            fprintf(stdout, " 0x%p", pwnd[j]);
        }
        fprintf(stdout, "\n");

    }

    ret = totalret;
out:
    get_win_handle_by_classname(NULL, -1, &pwnd, &wndsize);
    SETERRNO(-ret);
    return ret;
}

int winverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int totalret = 0;
    int ret;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs) {
        i = 0;
        while (parsestate->leftargs[i] != NULL) {
            ret = verify_windows_pe(parsestate->leftargs[i]);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "[%d] verify [%s] error[%d]\n", i, parsestate->leftargs[i], ret);
            } else {
                fprintf(stdout, "[%d]verify [%s] succ\n", i, parsestate->leftargs[i]);
            }
            i ++;
        }
    }

    SETERRNO(totalret);
    return totalret;
}

int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int cnt = 0;
    int idx = 0;
    HWND hwnd = NULL;
    UINT msg = 0;
    WPARAM wparam = 0;
    LPARAM lparam = 0;
    LRESULT lret;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs != NULL) {
        for (cnt = 0; parsestate->leftargs[cnt] != NULL; cnt ++) {

        }
    }

    if (cnt < 4 || (cnt % 4) != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "sendmsg hwnd msg wparam lparam\n");
        goto out;
    }


    while (parsestate->leftargs[idx] != NULL) {
        GET_OPT_TYPE(hwnd, "get hwnd", HWND);
        GET_OPT_TYPE(msg, "get msg", UINT);
        GET_OPT_TYPE(wparam, "get wparam", WPARAM);
        GET_OPT_TYPE(lparam, "get lparam", LPARAM);

        lret = SendMessage(hwnd, msg, wparam, lparam);
#if _M_X64
        fprintf(stdout, "send [%p] msg[%d:0x%x] with wparam [%lld:0x%llx] lparam[%lld:0x%llx] ret[%lld]\n",
                hwnd, msg, msg,
                wparam, wparam,
                lparam, lparam, lret);
#else
        fprintf(stdout, "send [%p] msg[%d:0x%x] with wparam [%d:0x%x] lparam[%ld:0x%lx] ret[%ld]\n",
                hwnd, msg, msg,
                wparam, wparam,
                lparam, lparam, lret);
#endif
        if (pargs->m_timeout > 0) {
            SleepEx((DWORD)pargs->m_timeout, TRUE);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pcompname = NULL;
    int compnamesize = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int num;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    num = atoi(parsestate->leftargs[0]);
    if (num < 1 || num > 7) {
        ERROR_INFO("not valid type [%d]", num);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }
    DEBUG_INFO("num %d", num);

    if (num & COMPUTER_NAME_DNS) {
        ret = get_computer_name(COMPUTER_NAME_DNS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "DNS computer name [%s]\n", pcompname);
    }

    if (num & COMPUTER_NAME_NETBIOS) {
        ret = get_computer_name(COMPUTER_NAME_NETBIOS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "NETBIOS computer name [%s]\n", pcompname);
    }

    if (num & COMPUTER_NAME_PHYS) {
        ret = get_computer_name(COMPUTER_NAME_PHYS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "PHYS computer name [%s]\n", pcompname);
    }

    ret = 0;
out:
    get_computer_name(COMPUTER_NAME_NONE, &pcompname, &compnamesize);
    SETERRNO(ret);
    return ret;
}

int setcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* compname = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int num;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    num = atoi(parsestate->leftargs[0]);
    compname = parsestate->leftargs[1];
    if (num < 1 || num > 7) {
        ERROR_INFO("not valid type [%d]", num);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    if (num & COMPUTER_NAME_DNS) {
        ret = set_computer_name(COMPUTER_NAME_DNS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set DNS compname [%s] succ\n", compname);
    }

    if (num & COMPUTER_NAME_NETBIOS) {
        ret = set_computer_name(COMPUTER_NAME_NETBIOS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set NETBIOS compname [%s] succ\n", compname);
    }

    if (num & COMPUTER_NAME_PHYS) {
        ret = set_computer_name(COMPUTER_NAME_PHYS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set PHYS compname [%s] succ\n", compname);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cp = 0;
    int ret = 0;

    argc = argc;
    argv = argv;
    popt = popt;
    parsestate = parsestate;

    cp = get_codepage();
    if (cp < 0) {
        ret = cp;
        fprintf(stderr, "can not get code page error[%d]\n", ret);
        goto out;
    }
    fprintf(stdout, "code page [%d]\n", cp);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int setcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cp = 437;
    int idx = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        fprintf(stderr, "no codepage specified\n");
        ret = -ERROR_INVALID_PARAMETER;
    }

    GET_OPT_INT(cp, "code page");
    ret = set_codepage(cp);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set code page [%d] error[%d]\n", cp, ret);
        goto out;
    }
    fprintf(stdout, "set code page[%d] succ\n", cp);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int winver_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    argc = argc;
    argv = argv;
    parsestate = parsestate;

    fprintf(stdout, "win7 %s\n", is_win7() ? "true" : "false");
    fprintf(stdout, "win10 %s\n", is_win10() ? "true" : "false");

    return 0;
}


int getsess_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);

    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_desktop_session();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get desktop session [%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "session [%d]\n", ret);

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
