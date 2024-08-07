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
    debug_buffer(stdout, (char*)pdata, nret, NULL);
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
    debug_buffer(stdout, (char*)pdata, datalen, NULL);
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
    debug_buffer(stdout, (char*)pdata, datalen, NULL);

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
    char** items = NULL;
    int itemsize = 0;
    int itemlen = 0;
    int i;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx] ; idx++) {
        path = parsestate->leftargs[idx];
        pregop = open_reg_key(pargs->m_regkey,path, ACCESS_KEY_READ);
        if (pregop == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not open [%s] for read [%d]\n", path, ret);
            goto out;
        }

        ret = enum_hklm_keys(pregop, &items, &itemsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not enum [%s] error[%d]\n", path, ret);
            goto out;
        }
        itemlen = ret;

        fprintf(stdout, "%s size[%d]\n", path, itemsize);
        for (i = 0; i < itemlen; i++) {
            fprintf(stdout, "    [%d]%s\n", i, items[i]);
        }
        close_hklm(&pregop);
    }

    ret = 0;
out:
    enum_hklm_keys(NULL, &items, &itemsize);
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
    char** items = NULL;
    int itemsize = 0;
    int itemlen = 0;
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

        ret = enum_hklm_values(pregop, &items, &itemsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not enum [%s] error[%d]\n", path, ret);
            goto out;
        }
        itemlen = ret;

        fprintf(stdout, "%s size [%d] %p\n", path, itemsize, items);
        for (i = 0; i < itemlen; i++) {
            fprintf(stdout, "    [%d]%s\n", i, items[i]);
        }
        close_hklm(&pregop);
    }

    ret = 0;
out:
    enum_hklm_values(NULL, &items, &itemsize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}

int regdelvalue_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
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

    preg = open_hklm(subkey, ACCESS_KEY_ALL);
    if (preg == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]\n", subkey, ret);
        goto out;
    }

    ret = delete_hklm_value(preg, path);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "delete [%s].[%s] error[%d]\n", subkey, path, ret);
        goto out;
    }

    fprintf(stdout, "delete [%s].[%s] succ\n", subkey, path);
    ret = 0;
out:
    close_hklm(&preg);
    SETERRNO(ret);
    return ret;
}

int regdelkey_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* keyname = NULL;
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
            keyname = parsestate->leftargs[i];
            break;
        case 1:
            subkey = parsestate->leftargs[i];
            break;
        case 2:
            path = parsestate->leftargs[i];
            break;
        default:
            break;
        }
    }

    if ( keyname == NULL || subkey == NULL || path == NULL) {
        fprintf(stderr, "need  keyname subkey and path\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    preg = open_reg_key( keyname , subkey, ACCESS_KEY_ALL);
    if (preg == NULL) {
        GETERRNO(ret);
        if (ret != -ERROR_FILE_NOT_FOUND) {
            fprintf(stderr, "can not open [%s] error[%d]\n", subkey, ret);
            goto out;
        } else {
            goto succ;
        }
    }

    ret = delete_reg_key(preg, path);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "delete [%s].[%s].[%s] error[%d]\n", keyname, subkey, path,  ret);
        goto out;
    }
succ:
    fprintf(stdout, "delete [%s].[%s].[%s] succ\n", keyname, subkey, path);
    ret = 0;
out:
    close_hklm(&preg);
    SETERRNO(ret);
    return ret;
}

int setregdword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* keyname = NULL;
    char* subkey = NULL;
    char* path = NULL;
    void* preg = NULL;
    int ret;
    int i;
    DWORD value = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        switch (i) {
        case 0:
            keyname = parsestate->leftargs[i];
            break;
        case 1:
            subkey = parsestate->leftargs[i];
            break;
        case 2:
            path = parsestate->leftargs[i];
            break;
        case 3:
            value = (DWORD)atoi(parsestate->leftargs[i]);
            break;
        default:
            break;
        }
    }

    if ( keyname == NULL || subkey == NULL || path == NULL) {
        fprintf(stderr, "need  keyname subkey and path\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    preg = open_reg_key( keyname , subkey, ACCESS_KEY_ALL);
    if (preg == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]\n", subkey, ret);
        goto out;
    }

    ret = set_hklm_dword(preg, path, value);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set [%s] value [%ld] error[%d]\n", path, value, ret);
        goto out;
    }
    fprintf(stdout, "set [%s].[%s].[%s] value [%ld] succ\n", keyname, subkey, path, value);
    ret = 0;
out:
    close_hklm(&preg);
    SETERRNO(ret);
    return ret;
}

int queryregdword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* keyname = NULL;
    char* subkey = NULL;
    char* path = NULL;
    void* preg = NULL;
    int ret;
    int i;
    uint32_t value = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        switch (i) {
        case 0:
            keyname = parsestate->leftargs[i];
            break;
        case 1:
            subkey = parsestate->leftargs[i];
            break;
        case 2:
            path = parsestate->leftargs[i];
            break;
        default:
            break;
        }
    }

    if ( keyname == NULL || subkey == NULL || path == NULL) {
        fprintf(stderr, "need  keyname subkey and path\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    preg = open_reg_key( keyname , subkey, ACCESS_KEY_READ);
    if (preg == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]\n", subkey, ret);
        goto out;
    }

    ret = query_hklm_dword(preg, path, &value);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] error[%d]\n", path,  ret);
        goto out;
    }
    fprintf(stdout, "get [%s].[%s].[%s] value [%d] succ\n", keyname, subkey, path, value);
    ret = 0;
out:
    close_hklm(&preg);
    SETERRNO(ret);
    return ret;
}

HKEY __name2_to_hkey(const char* pkeyname)
{
    HKEY hkey = NULL;
    int ret=0;
    if (_stricmp(pkeyname, "HKEY_LOCAL_MACHINE") == 0) {
        hkey = HKEY_LOCAL_MACHINE;
    } else if (_stricmp(pkeyname, "HKEY_CLASSES_ROOT") == 0) {
        hkey = HKEY_CLASSES_ROOT;
    } else if (_stricmp(pkeyname, "HKEY_CURRENT_CONFIG") == 0) {
        hkey = HKEY_CURRENT_CONFIG;
    } else if (_stricmp(pkeyname, "HKEY_CURRENT_USER") == 0) {
        hkey = HKEY_CURRENT_USER;
    } else if (_stricmp(pkeyname, "HKEY_USERS") == 0) {
        hkey = HKEY_USERS;
    } else if (_stricmp(pkeyname, "HKEY_PERFORMANCE_DATA") == 0) {
        hkey = HKEY_PERFORMANCE_DATA;
    } else if (_stricmp(pkeyname, "HKEY_PERFORMANCE_NLSTEXT") == 0) {
        hkey = HKEY_PERFORMANCE_NLSTEXT;
    } else {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("not vali keyname [%s]", pkeyname);
        goto fail;
    }

    return hkey;
fail:
    SETERRNO(ret);
    return NULL;
}


int load_hive(char* file,char* keyname, char* subkey)
{
    TCHAR* tfile=NULL;
    int tfsize=0;
    TCHAR* tsub=NULL;
    int tsubsize=0;
    int ret;
    LSTATUS lret;
    int enblrestore=0;
    int enblbackup=0;
    int enbldbg=0;
    HKEY hkey = NULL;

    if (file == NULL || keyname == NULL || subkey == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    ret = AnsiToTchar(file,&tfile,&tfsize);
    if (ret <0) {
        GETERRNO(ret);
        goto fail;
    }

    hkey = __name2_to_hkey(keyname);
    if (hkey == NULL) {
        GETERRNO(ret);
        goto fail;
    }


    ret = AnsiToTchar(subkey,&tsub,&tsubsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = enable_restore_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enblrestore = 1;

    ret = enable_backup_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enblbackup = 1;

    ret = enable_debug_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enbldbg = 1;

    lret = RegLoadKey(hkey,tsub,tfile);
    if (lret != ERROR_SUCCESS) {
        GETERRNO(ret);
        ERROR_INFO("RegLoadKey [%s].[%s] error [%d] lret [%d]",keyname,subkey,ret,lret);
        goto fail;
    }


    if (enbldbg != 0) {
        disable_debug_priv();
    }
    enbldbg = 0;

    if (enblbackup != 0) {
        disable_backup_priv();
    }
    enblbackup = 0;
    if (enblrestore != 0) {
        disable_restore_priv();
    }
    enblrestore =  0;
    AnsiToTchar(NULL,&tsub,&tsubsize);
    AnsiToTchar(NULL,&tfile,&tfsize);


    return 0;
fail:
    if (enbldbg != 0) {
        disable_debug_priv();
    }
    enbldbg = 0;

    if (enblbackup != 0) {
        disable_backup_priv();
    }
    enblbackup = 0;
    if (enblrestore != 0) {
        disable_restore_priv();
    }
    enblrestore =  0;
    AnsiToTchar(NULL,&tsub,&tsubsize);
    AnsiToTchar(NULL,&tfile,&tfsize);
    SETERRNO(ret);
    return ret;
}

int loadhive_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* keyname = NULL;
    char* subkey = NULL;
    char* fname = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        switch (i) {
        case 0:
            fname = parsestate->leftargs[i];
            break;
        case 1:
            subkey = parsestate->leftargs[i];
            break;
        default:
            break;
        }
    }

    if ( fname == NULL || subkey == NULL) {
        fprintf(stderr, "need  fname subkey\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    keyname = pargs->m_regkey;
    ret = load_hive(fname,keyname,subkey);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "load [%s] [%s].[%s] error[%d]\n", fname,keyname,subkey,ret);
        goto out;
    }

    fprintf(stdout,"load [%s] [%s].[%s] succ\n",fname,keyname,subkey);
    while(1) {
        SleepEx(1000,TRUE);
    }

    ret = 0;

out:
    SETERRNO(ret);
    return ret;    
}


int savehive_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* keyname = NULL;
    char* fname = NULL;
    char* subkey = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        switch (i) {
        case 1:
            fname = parsestate->leftargs[i];
            break;
        case 0:
            subkey = parsestate->leftargs[i];
            break;
        default:
            break;
        }
    }

    if ( fname == NULL || subkey == NULL) {
        fprintf(stderr, "need  fname and subkey \n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    keyname = pargs->m_regkey;
    ret = save_hive(fname,keyname,subkey);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "save [%s] [%s].[%s] error[%d]\n", fname,keyname,subkey,ret);
        goto out;
    }

    fprintf(stdout,"save [%s] [%s].[%s] succ\n",fname,keyname,subkey);
    ret = 0;

out:
    SETERRNO(ret);
    return ret;
}