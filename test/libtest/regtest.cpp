int regbinget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* pregop = NULL;
    int ret;
    int cnt = 0;
    char* path = NULL;
    char* property = NULL;
    void* pdata = NULL;
    int datasize = 0;
    int nret;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 2) {
        fprintf(stderr, "at least path and property\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    property = parsestate->leftargs[1];

    pregop = open_hklm(path, ACCESS_KEY_READ);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]", path, ret);
        goto out;
    }

    ret = query_hklm_binary(pregop, property, &pdata, &datasize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] property binary error[%d]\n", property, ret);
        goto out;
    }

    nret = ret;
    fprintf(stdout, "get [%s].[%s] data [%d]\n", path, property, nret);
    __debug_buf(stdout, (char*)pdata, nret);
    ret = 0;

out:
    query_hklm_binary(NULL, NULL, &pdata, &datasize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}
int regbinset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* pregop = NULL;
    int ret;
    int cnt = 0;
    char* path = NULL;
    char* property = NULL;
    unsigned char* pdata = NULL;
    unsigned char* ptmpdata = NULL;
    int datasize = 0;
    int datalen = 0;
    int curch = 0;
    int offset = 0;
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 4 || ((cnt - 2) % 2 != 0)) {
        fprintf(stderr, "at least path and property\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    property = parsestate->leftargs[1];

    pregop = open_hklm(path, ACCESS_KEY_READ | ACCESS_KEY_WRITE);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]", path, ret);
        goto out;
    }

    ret = query_hklm_binary(pregop, property, (void**)&pdata, &datasize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] property binary error[%d]\n", property, ret);
        goto out;
    }

    datalen = ret;
    fprintf(stdout, "[%s].[%s] datalen[%d]\n", path, property, datalen);
    __debug_buf(stdout, (char*)pdata, datalen);
    idx = 2;
    while (idx < cnt) {
        GET_OPT_INT(offset, "offset");
        GET_OPT_INT(curch, "ch");

        if (offset >= datasize) {
            datasize = (offset + 1);
            ptmpdata = (unsigned char*)malloc((size_t)datasize);
            if (ptmpdata == NULL) {
                fprintf(stderr, "alloc %d error[%d]\n", datasize, ret);
                goto out;
            }
            memset(ptmpdata, 0, (size_t)datasize);
            if (datalen > 0) {
                memcpy(ptmpdata, pdata, (size_t)datalen);
            }
            if (pdata != NULL) {
                free(pdata);
            }
            pdata = ptmpdata;
            ptmpdata = NULL;
            datalen = datasize;
        }

        pdata[offset] = (unsigned char)curch;
    }

    fprintf(stdout, "[%s].[%s] set [%d]\n", path, property, datalen );
    __debug_buf(stdout, (char*)pdata, datalen);

    ret = set_hklm_binary(pregop, property, pdata, datalen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set [%s].[%s] error[%d]\n", path, property, ret);
        goto out;
    }
    fprintf(stdout, "set success\n");
    ret = 0;
out:
    if (ptmpdata) {
        free(ptmpdata);
    }
    ptmpdata = NULL;
    query_hklm_binary(NULL, NULL, (void**)&pdata, &datasize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}

int setregstr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* path;
    char* key;
    char* val;
    void* pregop = NULL;
    int idx = 0;
    int cnt = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx] ; idx++) {
        cnt ++;
    }

    if (cnt < 3) {
        fprintf(stderr, "need path key val\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    key = parsestate->leftargs[1];
    val = parsestate->leftargs[2];

    pregop = open_hklm(path, ACCESS_KEY_ALL);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] for write [%d]\n", path, ret);
        goto out;
    }

    ret = set_hklm_string(pregop, key, val);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s].[%s] value [%s] error[%d]\n", path, key, val, ret);
        goto out;
    }

    fprintf(stdout, "write [%s].[%s] value [%s] succ\n", path, key, val);
    ret = 0;
out:
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}

int regenumkey_handler(int argc, char* argv[], pextargs_state_t parsestate, void*popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* path;
    void* pregop = NULL;
    int idx = 0;
    char** items=NULL;
    int itemsize=0;
    int itemlen=0;
    int i;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx] ; idx++) {
        path = parsestate->leftargs[idx];
        pregop = open_hklm(path, ACCESS_KEY_READ);
        if (pregop == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not open [%s] for read [%d]\n", path, ret);
            goto out;
        }

        ret = enum_hklm_keys(pregop,&items,&itemsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not enum [%s] error[%d]\n",path,ret);
            goto out;
        }
        itemlen = ret;

        fprintf(stdout,"%s size[%d]\n",path,itemsize);
        for(i=0;i<itemlen;i++) {
            fprintf(stdout,"    [%d]%s\n",i,items[i]);
        }
        close_hklm(&pregop);
    }

    ret = 0;
out:
    enum_hklm_keys(NULL,&items,&itemsize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;    
}

int regenumvalue_handler(int argc, char* argv[], pextargs_state_t parsestate, void*popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* path;
    void* pregop = NULL;
    int idx = 0;
    char** items=NULL;
    int itemsize=0;
    int itemlen=0;
    int i;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx] ; idx++) {
        path = parsestate->leftargs[idx];
        pregop = open_hklm(path, ACCESS_KEY_READ);
        if (pregop == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not open [%s] for write [%d]\n", path, ret);
            goto out;
        }

        ret = enum_hklm_values(pregop,&items,&itemsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not enum [%s] error[%d]\n",path,ret);
            goto out;
        }
        itemlen = ret;

        fprintf(stdout,"%s size [%d] %p\n",path,itemsize,items);
        for(i=0;i<itemlen;i++) {
            fprintf(stdout,"    [%d]%s\n",i,items[i]);
        }
        close_hklm(&pregop);
    }

    ret = 0;
out:
    enum_hklm_values(NULL,&items,&itemsize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;    
}

int regdel_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* subkey = NULL;
    char* path = NULL;
    void* preg = NULL;
    int ret;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        switch (i) {
        case 0:
            subkey = parsestate->leftargs[i];
            break;
        case 1:
            path = parsestate->leftargs[i];
            break;
        default:
            break;
        }
    }

    if (subkey == NULL || path == NULL) {
        fprintf(stderr, "need subkey and path\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    preg = open_hklm(subkey,ACCESS_KEY_ALL);
    if (preg == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]\n",subkey, ret);
        goto out;
    }

    ret = delete_hklm_value(preg,path);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "delete [%s].[%s] error[%d]\n", subkey,path, ret);
        goto out;
    }

    fprintf(stdout, "delete [%s].[%s] succ\n",subkey,path);
    ret = 0;
out:
    close_hklm(&preg);
    SETERRNO(ret);
    return ret;
}