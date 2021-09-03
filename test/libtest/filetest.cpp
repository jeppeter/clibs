
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
    int idx = 0;
    int times = 10;
    uint64_t appsize = (1ULL << 20);
    output_debug_cfg_t cfg = {0};
    int loglevel = BASE_LOG_DEFAULT;
    int i;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    GET_OPT_INT(times, "times");
    GET_OPT_NUM64(appsize, "appsize");
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


    if (pargs->m_disablecon != 0) {
        cfg.m_disableflag |= WINLIB_CONSOLE_DISABLED;
    }
    if (pargs->m_disablefile != 0) {
        cfg.m_disableflag |= WINLIB_FILE_DISABLED;
    }

    if (pargs->m_disabledb != 0) {
        cfg.m_disableflag |= WINLIB_DBWIN_DISABLED;
    }

    ret = InitOutputEx(loglevel, &cfg);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "init output error[%d]\n", ret);
        goto out;
    }

    for (i = 0; i < times; i++) {
        FATAL_INFO("debug line[%d]", i);
        ERROR_INFO("debug line[%d]", i);
        WARN_INFO("debug line[%d]", i);
        INFO_INFO("debug line[%d]", i);
        DEBUG_INFO("debug line[%d]", i);
        TRACE_INFO("debug line[%d]", i);
        FATAL_BUFFER(&cfg, sizeof(cfg));
        FATAL_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
        ERROR_BUFFER(&cfg, sizeof(cfg));
        ERROR_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
        WARN_BUFFER(&cfg, sizeof(cfg));
        WARN_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
        INFO_BUFFER(&cfg, sizeof(cfg));
        INFO_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
        DEBUG_BUFFER(&cfg, sizeof(cfg));
        DEBUG_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
        TRACE_BUFFER(&cfg, sizeof(cfg));
        TRACE_BUFFER_FMT(&cfg, sizeof(cfg), "cfg [%p]", &cfg);
    }

    /**/
    ret = 0;
out:
    FiniOutput();
    SETERRNO(ret);
    return ret;

}

#define   MAX_APPEND_FILE_SIZE   (10 << 20)

int init_write_file_debug(int loglvl)
{
    char* appendfile[2];
    char* outfile[2];
    char* appname = NULL;
    int appsize = 0;
    char* app2name = NULL;
    int app2size = 0;
    char* outname = NULL;
    int outsize = 0;
    output_debug_cfg_t cfg;
    int ret;
    char* pfulldir = NULL;
    int fulldirsize = 0;
    uint64_t appfilesize = 0;
    void* pfile = NULL;
    memset(appendfile, 0, sizeof(appendfile));
    memset(outfile, 0, sizeof(outfile));
    ret = get_executable_dirname(0, &pfulldir, &fulldirsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = snprintf_safe(&appname, &appsize, "%s\\idvtools_append.log", pfulldir);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    ret = snprintf_safe(&app2name, &app2size, "%s\\idvtools_append.log.2", pfulldir);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    ret = snprintf_safe(&outname, &outsize, "%s\\idvtools_output.log", pfulldir);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pfile = open_file(appname, READ_MODE);
    ERROR_INFO("open [%s] return [%p]",appname, pfile);
    if (pfile != NULL) {
        SETERRNO(0);
        appfilesize = get_file_size(pfile);
        GETERRNO_DIRECT(ret);
        if (ret == 0) {
            close_file(&pfile);
            if (appfilesize >= MAX_APPEND_FILE_SIZE) {
                ret = copy_file_force(appname, app2name);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("copy [%s] => [%s] error[%d]", appname, app2name, ret);
                    goto fail;
                }
                ret = delete_file(appname);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not delete [%s]", appname);
                    goto fail;
                }
            }
        }
    }
    close_file(&pfile);

    memset(&cfg, 0, sizeof(cfg));
    appendfile[0] = appname;
    appendfile[1] = NULL;
    outfile[0] = outname;
    outfile[1] = NULL;
    cfg.m_ppoutcreatefile = outfile;
    cfg.m_ppoutappendfile =  appendfile;
    ERROR_INFO("will init loglvl %d", loglvl);

    ret = InitOutputEx(loglvl, &cfg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("append file [%s] output file [%s]", appname, outname);

    close_file(&pfile);
    snprintf_safe(&app2name, &app2size, NULL);
    snprintf_safe(&appname, &appsize, NULL);
    snprintf_safe(&outname, &outsize, NULL);
    get_executable_dirname(1, &pfulldir, &fulldirsize);
    return 0;
fail:
    close_file(&pfile);
    INIT_LOG(loglvl);
    ERROR_INFO("fail init error[%d]", ret);
    snprintf_safe(&app2name, &app2size, NULL);
    snprintf_safe(&appname, &appsize, NULL);
    snprintf_safe(&outname, &outsize, NULL);
    get_executable_dirname(1, &pfulldir, &fulldirsize);
    SETERRNO(ret);
    return ret;
}

int idvtooloutput_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    int cnt=10;
    int idx=0;
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(popt);
    init_write_file_debug(BASE_LOG_DEBUG);
    GET_OPT_INT(cnt,"cnt");
    for (i=0;i<cnt ;i++) {
        DEBUG_INFO("output [%d]",i);    
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

#define PARSE_VALUE(vnum,typev,note)                                                              \
do{                                                                                               \
    if (pcurptr != NULL) {                                                                        \
        ret = parse_number(pcurptr,&num,&pendptr);                                                \
        if (ret < 0) {                                                                            \
            GETERRNO(ret);                                                                        \
            fprintf(stderr,"parse [%s:%d] [%s] error[%d]\n",__FILE__,__LINE__,pcurptr,ret);       \
            goto fail;                                                                            \
        }                                                                                         \
        vnum = (typev) num;                                                                       \
        pcurptr = pendptr;                                                                        \
        if (*pcurptr == ';') {                                                                    \
            pcurptr ++;                                                                           \
        }                                                                                         \
        if (*pcurptr == '\0') {                                                                   \
            pcurptr = NULL;                                                                       \
        }                                                                                         \
        fprintf(stderr,"parse [%s:%d] [%s] [%s]\n",__FILE__,__LINE__,note,pcurptr != NULL ? pcurptr : "NULL" );\
    }                                                                                             \
} while(0)

int parse_cfgs(OutputCfg& cfgs, const char* line)
{
    OutfileCfg* pcfg=NULL;
    char* fname=NULL;
    int level = BASE_LOG_ERROR;
    int fmtflag = WINLIB_OUTPUT_ALL_MASK;
    int type = WINLIB_DEBUGOUT_FILE_TRUNC;
    int maxfiles = 0;
    uint64_t size = 0;
    char* pcurptr = (char*)line;
    int len=0;
    uint64_t num;
    char* pendptr=NULL;
    int ret;
    pcfg = new OutfileCfg();
    if (strncmp(line,"stderr;",7)==0) {
        pcurptr += 7;
        type = WINLIB_DEBUGOUT_FILE_STDERR;
        if (*pcurptr == '\0') {
            pcurptr = NULL;
        }
    } else if (strncmp(line,"background;",11) == 0) {
        pcurptr += 11;
        type = WINLIB_DEBUGOUT_FILE_BACKGROUND;
        if (*pcurptr == '\0') {
            pcurptr = NULL;
        }
    }  else {
        pcurptr = strchr((char*)line,';');
        if (pcurptr != NULL) {
            pcurptr ++;
        }

        if (pcurptr == NULL) {
            fname = _strdup(line);
        } else {
            len = (int)(pcurptr - line);
            fname = (char*)malloc((size_t)len);
            if (fname == NULL) {
                GETERRNO(ret);
                goto fail;
            }
            memset(fname,0,(size_t)len);
            memcpy(fname, line, (size_t)(len-1));
        }        

        if (*pcurptr == '\0') {
            pcurptr = NULL;
        }
    }

    PARSE_VALUE(type,int,"type");
    PARSE_VALUE(level,int,"level");
    PARSE_VALUE(fmtflag,int,"fmtflag");
    PARSE_VALUE(size,uint64_t,"size");
    PARSE_VALUE(maxfiles,int,"maxfiles");

    ret = pcfg->set_file_type(fname,type,size,maxfiles);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set file type error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }
    ret = pcfg->set_level(level);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set level error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }
    ret = pcfg->set_format(fmtflag);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set format error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }

    ret = cfgs.insert_config(*pcfg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (fname) {
        free(fname);
    }
    fname = NULL;
    if (pcfg){
        delete pcfg;
    }
    pcfg = NULL;
    return 0;
fail:
    if (fname) {
        free(fname);
    }
    fname = NULL;
    if (pcfg){
        delete pcfg;
    }
    pcfg = NULL;
    SETERRNO(ret);
    return ret;
}


int outputdebugex_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    int idx = 0;
    int times = 10;
    int i;
    OutputCfg cfgs;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    GET_OPT_INT(times, "times");

    for(i=0;pargs->m_exlogs && pargs->m_exlogs[i];i++) {
        ret = parse_cfgs(cfgs,pargs->m_exlogs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "parse [%d] [%s] error[%d]\n",i, pargs->m_exlogs[i], ret);
            goto out;
        }
    }

    ret = InitOutputEx2(&cfgs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }




    for (i = 0; i < times; i++) {
        FATAL_INFO("debug line[%d]", i);
        ERROR_INFO("debug line[%d]", i);
        WARN_INFO("debug line[%d]", i);
        INFO_INFO("debug line[%d]", i);
        DEBUG_INFO("debug line[%d]", i);
        TRACE_INFO("debug line[%d]", i);
        FATAL_BUFFER(pargs, sizeof(*pargs));
        FATAL_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
        ERROR_BUFFER(pargs, sizeof(*pargs));
        ERROR_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
        WARN_BUFFER(pargs, sizeof(*pargs));
        WARN_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
        INFO_BUFFER(pargs, sizeof(*pargs));
        INFO_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
        DEBUG_BUFFER(pargs, sizeof(*pargs));
        DEBUG_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
        TRACE_BUFFER(pargs, sizeof(*pargs));
        TRACE_BUFFER_FMT(pargs, sizeof(*pargs), "cfg [%p]", pargs);
    }

    /**/
    ret = 0;
out:
    FiniOutput();
    SETERRNO(ret);
    return ret;
}