
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
