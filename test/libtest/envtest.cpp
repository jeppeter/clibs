
int getexe_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pwhole = NULL;
    int wholesize = 0;
    init_log_level(pargs);
    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_executable_wholepath(0, &pwhole, &wholesize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "get whole path error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "whole path [%s]\n", pwhole);

    ret = 0;
out:
    get_executable_wholepath(1, &pwhole, &wholesize);
    SETERRNO(ret);
    return ret;
}

int getexedir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pwhole = NULL;
    int wholesize = 0;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_executable_dirname(0, &pwhole, &wholesize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "get whole path error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "whole path dirname [%s]\n", pwhole);

    ret = 0;
out:
    get_executable_dirname(1, &pwhole, &wholesize);
    SETERRNO(ret);
    return ret;
}

int vsinsted_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* version = NULL;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i++) {
        version = parsestate->leftargs[i];
        ret = is_visual_studio_installed(version);
        if (ret < 0) {
            fprintf(stdout, "%s not installed\n", version);
        } else {
            fprintf(stdout, "%s installed\n", version);
        }
    }

    return 0;
}

int okpassword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* user = NULL;
    char* password = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    user = parsestate->leftargs[0];
    password = parsestate->leftargs[1];

    ret = user_password_ok(user, password);
    if (ret < 0) {
        fprintf(stderr, "logon [%s:%s] error[%d]\n", user, password, ret);
        goto out;
    }

    fprintf(stdout, "logon [%s][%s] succ\n", user, password);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getenvval_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* varname=NULL;
    char* valstr=NULL;
    size_t valsize=0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        varname = parsestate->leftargs[i];
        ret = _dupenv_s(&valstr,&valsize,varname);
        if (ret == 0) {
            fprintf(stdout,"[%s]=[%s]\n",varname,valstr);
        } else {
            fprintf(stdout,"[%s] not set\n",varname);
        }

        if (valstr) {
            free(valstr);
        }
        valstr = NULL;
        valsize = 0;
    }

    ret = 0;
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    SETERRNO(ret);
    return ret;
}
