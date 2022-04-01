
int mntdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* mntdir = NULL;
    int mntsize = 0;
    int i;
    char* dev = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        dev = parsestate->leftargs[i];
        ret = dev_get_mntdir(dev, &mntdir, &mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]", dev, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", dev, mntdir);
        } else {
            fprintf(stdout, "[%s] not mounted\n", dev);
        }
    }

    ret = 0;
out:
    dev_get_mntdir(NULL, &mntdir, &mntsize);
    SETERRNO(ret);
    return ret;
}

int getmnt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* mntdir = NULL;
    int mntsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* prealpath = NULL;
    int realsize = 0;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = realpath_safe(path, &prealpath, &realsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get real path for [%s] error[%d]\n", path, ret);
            goto out;
        }
        ret = path_get_mntdir(prealpath, &mntdir, &mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]", path, ret);
            goto out;
        }
        fprintf(stdout, "[%s] mount [%s]\n", path, mntdir);
    }

    ret = 0;
out:
    realpath_safe(NULL, &prealpath, &realsize);
    path_get_mntdir(NULL, &mntdir, &mntsize);
    SETERRNO(ret);
    return ret;
}


int getdev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pdev = NULL;
    int devsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_dev(path, &pdev, &devsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", path, pdev);
        } else {
            fprintf(stdout, "[%s] not device mount\n", path);
        }

    }

    ret = 0;
out:
    mntdir_get_dev(NULL, &pdev, &devsize);
    SETERRNO(ret);
    return ret;
}

int getfstype_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfstype = NULL;
    int fssize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_fstype(path, &pfstype, &fssize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", path, pfstype);
        } else {
            fprintf(stdout, "[%s] not mount directory\n", path);
        }

    }

    ret = 0;
out:
    mntdir_get_fstype(NULL, &pfstype, &fssize);
    SETERRNO(ret);
    return ret;
}

int realpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* prealpath = NULL;
    int realsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = realpath_safe(path, &prealpath, &realsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]realpath error[%d]\n", path, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] realpath [%s]\n", i, path, prealpath);
    }

    ret = 0;
out:
    realpath_safe(NULL, &prealpath, &realsize);
    SETERRNO(ret);
    return ret;
}

