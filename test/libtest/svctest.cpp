
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
