
int mktemp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* templstr = NULL;
    int templsize = 0;
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            ret = mktempfile_safe(parsestate->leftargs[i], &templstr, &templsize);
            //ret = 0;
            if (ret < 0) {
                fprintf(stderr, "can not parse [%s] error(%d)\n", parsestate->leftargs[i], ret);
                goto out;
            }
            fprintf(stdout, "[%d]%s => %s\n", i, parsestate->leftargs[i], templstr);
        }
    }
out:
    get_temp_pipe_name(NULL, &templstr, &templsize);
    return ret;
}

int fullpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfullpath = NULL;
    int fullsize = 0;
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i ++) {
            ret = get_full_path(parsestate->leftargs[i], &pfullpath, &fullsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%d][%s] => [%s]\n", i, parsestate->leftargs[i], pfullpath);
        }
    }

    ret = 0;
out:
    get_full_path(NULL, &pfullpath, &fullsize);
    SETERRNO(-ret);
    return ret;
}

int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* dirname = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        dirname = parsestate->leftargs[i];
        ret = create_directory(dirname);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("create [%s] error[%d]", dirname, ret);
            goto out;
        }
        fprintf(stdout, "create %s [%s]\n", dirname, ret > 0 ? "created" : "exists");
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

typedef struct __enum_dir {
    FILE* m_fp;
    char* m_lastdir;
    int m_indent;
    int m_depth;
} enum_dir_t, *penum_dir_t;

int __print_directory(char* basedir, char* curdir, char* curpat, void* arg)
{
#if 0
    REFERENCE_ARG(basedir);
    REFERENCE_ARG(curdir);
    REFERENCE_ARG(curpat);
    REFERENCE_ARG(arg);
    return 1;
#else
    int i, j;
    int curdepth = 0;
    char* pcurptr = NULL;
    int ret;

    penum_dir_t penum = (penum_dir_t) arg;
    if (penum->m_lastdir == NULL) {
        fprintf(penum->m_fp, "%s\n", basedir);
        penum->m_depth = 1;
    } else if (strcmp(penum->m_lastdir, curdir) != 0) {
        pcurptr = curdir + strlen(basedir);
        curdepth = 1;
        /*skip \ */
        pcurptr ++;
        while (1) {
            if ( pcurptr == NULL || *pcurptr == '\0') {
                break;
            }
            curdepth ++;
            pcurptr = strchr(pcurptr, '\\');
            if (pcurptr != NULL) {
                /*skip the \\ */
                pcurptr ++;
            }
        }
        penum->m_depth = curdepth;
    }

    for (i = 0; i < penum->m_depth; i++) {
        for (j = 0; j < penum->m_indent; j++) {
            fprintf(penum->m_fp, " ");
        }
    }
    fprintf(penum->m_fp, "%s\n", curpat);
    if (penum->m_lastdir) {
        free(penum->m_lastdir);
    }
    penum->m_lastdir = NULL;
    penum->m_lastdir = _strdup(curdir);
    if (penum->m_lastdir == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    return 1;
fail:
    SETERRNO(ret);
    return ret;
#endif
}

int enumdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    enum_dir_t enumdir;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* basedir = NULL;
    int ret;
    FILE* fp = stdout;


    memset(&enumdir, 0, sizeof(enumdir));
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    if (pargs->m_output != NULL) {
        ret = fopen_s(&fp, pargs->m_output, "w");
        if (ret != 0) {
            GETERRNO(ret);
            ERROR_INFO("open %s error[%d]", pargs->m_output, ret);
            goto out;
        }
    }

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        basedir = parsestate->leftargs[i];
        if (enumdir.m_lastdir) {
            free(enumdir.m_lastdir);
        }
        enumdir.m_lastdir = NULL;
        enumdir.m_depth = 0;
        enumdir.m_indent = 4;
        enumdir.m_fp = fp;

        ret = enumerate_directory(basedir, __print_directory, &enumdir);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("enumerate directory [%s] error[%d]", basedir, ret);
            goto out;
        }
    }

    ret = 0;
out:
    if (enumdir.m_lastdir) {
        free(enumdir.m_lastdir);
    }
    enumdir.m_lastdir = NULL;

    if (fp != stdout && fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    SETERRNO(ret);
    return ret;
}

int outputdebug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    int idx=0;
    int times = 10;
    uint64_t appsize=(1ULL<<20);
    output_debug_cfg_t cfg={0};
    int loglevel=BASE_LOG_DEFAULT;
    char* appfile=NULL;
    uint64_t cursize;
    int i;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    GET_OPT_INT(times,"times");
    GET_OPT_NUM64(appsize,"appsize");
    cfg.m_ppoutcreatefile = pargs->m_outfiles;
    cfg.m_ppoutappendfile = pargs->m_appfiles;

    if (pargs->m_verbose <= 0) {
        loglevel = BASE_LOG_FATAL;
    } else if (pargs->m_verbose == 1) {
        loglevel = BASE_LOG_ERROR;
    } else if (pargs->m_verbose == 2) {
        loglevel = BASE_LOG_WARN;
    } else if (pargs->m_verbose == 3) {
        loglevel = BASE_LOG_INFO;
    } else if (pargs->m_verbose == 4) {
        loglevel = BASE_LOG_DEBUG;
    } else {
        loglevel = BASE_LOG_TRACE;
    }

    for (i=0;pargs->m_appfiles && pargs->m_appfiles[i];i++) {
        appfile = pargs->m_appfiles[i];
        SETERRNO(0);
        cursize = get_file_size(appfile);
        GETERRNO_DIRECT(ret);
        if (ret == 0) {
            if (cursize >= appsize) {
                fprintf(stdout,"will delete [%d][%s]\n",i,appfile);
                ret = delete_file(appfile);
                if (ret < 0) {
                    GETERRNO(ret);
                    fprintf(stderr, "can not delete [%s] error[%d]\n", appfile,ret);
                    goto out;
                }
            }
        }
    }

    if (pargs->m_disablecon != 0) {
        cfg.m_disableflag |= WINLIB_CONSOLE_DISABLED;
    }
    if (pargs->m_disablefile != 0) {
        cfg.m_disableflag |= WINLIB_FILE_DISABLED;
    }

    if (pargs->m_disabledb != 0) {
        cfg.m_disableflag |= WINLIB_DBWIN_DISABLED;
    }

    ret = InitOutputEx(loglevel,&cfg);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"init output error[%d]\n",ret);
        goto out;
    }

    for (i=0;i<times;i++) {
        FATAL_INFO("debug line[%d]",i);
        ERROR_INFO("debug line[%d]",i);
        WARN_INFO("debug line[%d]",i);
        INFO_INFO("debug line[%d]",i);
        DEBUG_INFO("debug line[%d]",i);
        TRACE_INFO("debug line[%d]",i);
        FATAL_BUFFER(&cfg,sizeof(cfg));
        FATAL_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
        ERROR_BUFFER(&cfg,sizeof(cfg));
        ERROR_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
        WARN_BUFFER(&cfg,sizeof(cfg));
        WARN_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
        INFO_BUFFER(&cfg,sizeof(cfg));
        INFO_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
        DEBUG_BUFFER(&cfg,sizeof(cfg));
        DEBUG_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
        TRACE_BUFFER(&cfg,sizeof(cfg));
        TRACE_BUFFER_FMT(&cfg,sizeof(cfg),"cfg [%p]",&cfg);
    }

    /**/
    ret = 0;
out:
    FiniOutput();
    SETERRNO(ret);
    return ret;

}