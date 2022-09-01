
int split_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* splitchars = NULL;
    char* instr = NULL;
    int i, j;
    int cnt = 0;
    char** pparrs = NULL;
    int arrsize = 0, arrlen = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }
    argc = argc;
    argv = argv;
    init_log_verbose(pargs);


    if (cnt < 1) {
        ret = -EINVAL;
        fprintf(stderr, "[spltichars] instr ... to set\n");
        goto out;
    }

    if (cnt == 1) {
        instr = parsestate->leftargs[0];
        ret = split_chars(instr, NULL, &pparrs, &arrsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "split [%s] error[%d]", instr, ret);
            goto out;
        }
        arrlen = ret;
        fprintf(stdout, "split [%s] with NULL\n", instr);
        for (i = 0; i < arrlen; i++) {
            fprintf(stdout, "    [%d]=[%s]\n", i, pparrs[i]);
        }
    } else {
        splitchars = parsestate->leftargs[0];
        for (i = 1; i < cnt; i++) {
            instr = parsestate->leftargs[i];
            ret = split_chars(instr, splitchars, &pparrs, &arrsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "split [%s] with [%s] error[%d]\n", instr, splitchars, ret);
                goto out;
            }
            arrlen = ret;
            fprintf(stdout, "split [%s] with [%s]\n", instr, splitchars);
            for (j = 0; j < arrlen; j++) {
                fprintf(stdout, "    [%d]=[%s]\n", j, pparrs[j]);
            }
        }
    }

    ret = 0;
out:
    split_chars(NULL, NULL, &pparrs, &arrsize);
    SETERRNO(ret);
    return ret;
}

int splitre_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* splitchars = NULL;
    char* instr = NULL;
    int i, j;
    int cnt = 0;
    char** pparrs = NULL;
    int arrsize = 0, arrlen = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }
    argc = argc;
    argv = argv;
    init_log_verbose(pargs);


    if (cnt < 2) {
        ret = -EINVAL;
        fprintf(stderr, "splti_regular_expression instr ... to set\n");
        goto out;
    }

    splitchars = parsestate->leftargs[0];
    for (i = 1; i < cnt; i++) {
        instr = parsestate->leftargs[i];
        ret = split_chars_re(instr, splitchars , REGEX_NONE, &pparrs, &arrsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "split [%s] with [%s] error[%d]\n", instr, splitchars, ret);
            goto out;
        }
        arrlen = ret;
        fprintf(stdout, "split [%s] with [%s]\n", instr, splitchars);
        for (j = 0; j < arrlen; j++) {
            fprintf(stdout, "    [%d]=[%s]\n", j, pparrs[j]);
        }
    }

    ret = 0;
out:
    split_chars_re(NULL, NULL, REGEX_NONE, &pparrs, &arrsize);
    SETERRNO(ret);
    return ret;
}

int fmttime_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    const char* fmtstr=NULL;
    const char* fmtval=NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int idx=0;
    struct tm tmval;
    char* pbuf=NULL;
    int bufsize=0;
    int ret;
    char* pret=NULL;

    /*
        in %x %x format 12/10/22 12:30:50
        2022-12-10 12:30:50
    */
    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[idx]) {
        fmtstr = parsestate->leftargs[idx];
        idx += 1;
        if (parsestate->leftargs && parsestate->leftargs[idx]) {
            fmtval = parsestate->leftargs[idx];
            idx += 1;
        }
    }

    if (fmtstr == NULL || fmtval == NULL) {
        ret = -EINVAL;
        goto out;
    }

    memset(&tmval,0,sizeof(tmval));
    pret = strptime(fmtval,fmtstr,&tmval);
    if (pret == NULL) {
        GETERRNO(ret);
        ERROR_INFO("val [%s] fmt [%s] error[%d]", fmtval,fmtstr,ret);
        goto out;
    }

    bufsize = 100;
fmt_again:
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;

    pbuf = (char*)malloc(bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = strftime(pbuf,bufsize,"%Y-%m-%d %H:%M:%S",&tmval);
    if (ret >= (bufsize - 1)) {
        bufsize <<= 1;
        goto fmt_again;
    } else if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("strftime error[%d]", ret);
        goto out;
    }

    fprintf(stdout,"[%s] => [%s] = [%s]\n", fmtstr,fmtval, pbuf);
    ret = 0;
out:
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;
    bufsize = 0;


    SETERRNO(ret);
    return ret;
}