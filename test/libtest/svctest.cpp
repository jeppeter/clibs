
int existsvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    int ret;
    char* svcname = NULL;
    int exist = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argv = argv;
    argc = argc;

    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            svcname = parsestate->leftargs[i];
            exist = is_service_exist(svcname);
            if (exist < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%s] check error[%d]\n", svcname, ret );
                goto out;
            }
            fprintf(stdout, "%s %s\n", svcname, exist ? "exists" : "not exists" );
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svcstate_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int i;
    char* name;
    char* mode;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc ;
    argv = argv;

    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            name = parsestate->leftargs[i];
            ret = service_running_mode(name);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "%s can not get running mode [%d]", name, ret);
                goto out;
            }
            switch (ret) {
            case SVC_STATE_UNKNOWN:
                mode = "unknown";
                break;
            case SVC_STATE_STOPPED:
                mode = "stopped";
                break;
            case SVC_STATE_START_PENDING:
                mode = "start pending";
                break;
            case SVC_STATE_RUNNING:
                mode = "running";
                break;
            case SVC_STATE_STOP_PENDING:
                mode = "stop pending";
                break;
            case SVC_STATE_PAUSED:
                mode = "paused";
                break;
            case SVC_STATE_PAUSE_PENDING:
                mode = "pause pending";
                break;
            case SVC_STATE_CONTINUE_PENDING:
                mode = "continue pending";
                break;
            default:
                fprintf(stderr, "[%s] get state [%d]\n", name, ret);
                ret = -1;
                goto out;
            }
            fprintf(stdout, "%s mode %s\n", name, mode);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
int svchdl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cnt = 0;
    int ret;
    char* name = NULL;
    int i;
    char* action = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc;
    argv = argv;

    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 2) {
        fprintf(stderr, "need at least 2 args\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    action = parsestate->leftargs[0];

    if (strcmp(action, "start") == 0 || strcmp(action, "stop") == 0) {
    } else {
        fprintf(stderr, "not support handle [%s]\n", action);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    for (i = 1; i < cnt; i++) {
        name = parsestate->leftargs[i];
        if (strcmp(action, "start") == 0) {
            ret = start_service(name, pargs->m_timeout);
        } else if (strcmp(action, "stop") == 0) {
            ret = stop_service(name, pargs->m_timeout);
        } else {
            ret = -ERROR_INVALID_PARAMETER;
        }

        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "%s %s failed error[%d]\n", action, name, ret);
            goto out;
        }
        fprintf(stdout, "%s %s succ\n", action, name);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svcmode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cnt = 0;
    char* mode = NULL;
    char* name = NULL;
    int modeset = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc;
    argv = argv;


    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 1) {
        fprintf(stderr, "need at least one arg\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }
    name = parsestate->leftargs[0];

    if (cnt == 1) {
        ret = get_service_start_mode(name);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] start mode error[%d]\n", name, ret);
            goto out;
        }

        switch (ret) {
        case SVC_START_ON_UNKNOWN:
            mode = "unknown";
            break;
        case SVC_START_ON_BOOT:
            mode = "boot";
            break;
        case SVC_START_ON_SYSTEM:
            mode = "system";
            break;
        case SVC_START_ON_AUTO:
            mode = "auto";
            break;
        case SVC_START_ON_DEMAND:
            mode = "demand";
            break;
        case SVC_START_ON_DISABLED:
            mode = "disabled";
            break;
        default:
            fprintf(stderr, "[%s] start mode [%d] error\n", name, ret);
            ret = -ERROR_INTERNAL_ERROR;
            goto out;
        }
        fprintf(stdout, "[%s] start mode [%s]\n", name, mode);
    } else {
        mode = parsestate->leftargs[1];
        if (strcmp(mode , "boot") == 0) {
            modeset = SVC_START_ON_BOOT;
        } else if (strcmp(mode, "system") == 0) {
            modeset = SVC_START_ON_SYSTEM;
        } else if (strcmp(mode, "auto") == 0) {
            modeset = SVC_START_ON_AUTO;
        } else if (strcmp(mode, "demand") == 0) {
            modeset = SVC_START_ON_DEMAND;
        } else if (strcmp(mode, "disabled") == 0) {
            modeset = SVC_START_ON_DISABLED;
        } else {
            fprintf(stderr, "not supported start mode [%s]\n", mode);
            ret = - ERROR_INVALID_PARAMETER;
            goto out;
        }

        ret = config_service_start_mode(name, modeset);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] config start mode [%s] error[%d]\n", name, mode, ret);
            goto out;
        }
        fprintf(stdout, "[%s] config start mode [%s] succ\n", name , mode);
    }

    ret = 0;

out:
    SETERRNO(ret);
    return ret;
}

int __mk_svc_handler(pextargs_state_t parsestate, pargs_options_t pargs, int drivemode)
{
    char* binpath = NULL;
    char* svcname = NULL;
    int svcnamesize = 0;
    int allocname = 0;
    char* desc = NULL;
    int descsize = 0;
    int allocdesc = 0;
    int startmode = SVC_START_ON_DEMAND;
    char* pstart = NULL;
    int idx = 0;
    char* pcurptr = NULL;
    char* lastptr = NULL;
    int ret;

    REFERENCE_ARG(pargs);

    binpath = parsestate->leftargs[idx];
    idx ++;

    if (parsestate->leftargs[idx]) {
        svcname = parsestate->leftargs[idx];
        idx ++;
    } else {
        pcurptr = strrchr(binpath, '\\');
        if (pcurptr) {
            pcurptr ++;
        } else {
            pcurptr = binpath;
        }
        ret = snprintf_safe(&svcname, &svcnamesize, "%s", pcurptr);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        lastptr = svcname + strlen(svcname);
        while (lastptr != svcname) {
            if (*lastptr == '.') {
                *lastptr = '\0';
                break;
            }
            lastptr --;
        }
        allocname = 1;
    }

    if (parsestate->leftargs[idx]) {
        desc = parsestate->leftargs[idx];
        idx ++;
    } else {
        ret = snprintf_safe(&desc, &descsize, "%s description", svcname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        allocdesc = 1;
    }

    if (parsestate->leftargs[idx]) {
        pstart = parsestate->leftargs[idx];
        idx ++;
        if (_stricmp(pstart, "demand") == 0) {
            startmode = SVC_START_ON_DEMAND;
        } else if (_stricmp(pstart, "auto") == 0) {
            startmode = SVC_START_ON_AUTO;
        } else if (_stricmp(pstart, "boot") == 0) {
            startmode = SVC_START_ON_BOOT;
        } else if (_stricmp(pstart, "system") == 0) {
            startmode = SVC_START_ON_SYSTEM;
        } else if (_stricmp(pstart, "disable") == 0) {
            startmode = SVC_START_ON_DISABLED;
        } else {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("[%s] not support type start mode", pstart);
            goto out;
        }
    }

    if (drivemode) {
        ret = create_driver(svcname, desc, binpath, startmode);
    } else {
        ret = create_service(svcname, desc, binpath, startmode);
    }
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("create %s [%s] [%s] [%s] mode[%d] error[%d]", drivemode ? "driver" : "service",
                   svcname, desc, binpath, startmode, ret);
        goto out;
    }

    fprintf(stdout, "create %s [%s] [%s] [%s] mode[%d] succ\n", drivemode ? "driver" : "service",
            svcname, desc, binpath, startmode);
    ret = 0;
out:
    if (allocdesc) {
        snprintf_safe(&desc, &descsize, NULL);
    }
    desc = NULL;
    descsize = 0;
    allocdesc = 0;
    if (allocname) {
        snprintf_safe(&svcname, &svcnamesize, NULL);
    }
    svcname = NULL;
    svcnamesize = 0;
    allocname = 0;
    SETERRNO(ret);
    return ret;
}


int mkdrv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    return __mk_svc_handler(parsestate, pargs, 1);
}
int mksvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    return __mk_svc_handler(parsestate, pargs, 0);
}
