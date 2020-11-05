typedef int (*m_enable_priv_func_t)(void);
typedef int (*m_disable_priv_func_t)(void);
typedef int (*m_get_priv_func_t)(void);

typedef struct __priv_funcs
{
    char* m_name;
    m_enable_priv_func_t m_enfunc;
    m_disable_priv_func_t m_disfunc;
    m_get_priv_func_t m_getfunc;
} priv_funcs_t, *ppriv_funcs_t;


static priv_funcs_t st_priv_funcs [] =
{
    {"security", enable_security_priv, disable_security_priv, is_security_priv},
    {"takeown", enable_takeown_priv, disable_takeown_priv, is_takeown_priv},
    {"restore", enable_restore_priv, disable_restore_priv, is_restore_priv},
    {"backup", enable_backup_priv, disable_backup_priv, is_backup_priv},
    {"impersonate", enable_impersonate_priv, disable_impersonate_priv, is_impersonate_priv},
    {"audit", enable_audit_priv, disable_audit_priv, is_audit_priv},
    {"debug", enable_debug_priv, disable_debug_priv, is_debug_priv},
    {"tcb", enable_tcb_priv, disable_tcb_priv, is_tcb_priv},
    {NULL, NULL, NULL, NULL}
};

ppriv_funcs_t __find_priv_funcs(char* name, ppriv_funcs_t plast)
{
    int i;
    if (name == NULL) {
        if (plast == NULL) {
            if (st_priv_funcs[0].m_name != NULL) {
                return &(st_priv_funcs[0]);
            }
            return NULL;
        }

        for (i = 0; st_priv_funcs[i].m_name != NULL; i++) {
            if (&(st_priv_funcs[i]) == plast) {
                if (st_priv_funcs[(i + 1)].m_name != NULL) {
                    return &(st_priv_funcs[i + 1]);
                }
            }
        }
        return NULL;
    }

    for (i = 0; st_priv_funcs[i].m_name; i++) {
        if (_stricmp(st_priv_funcs[i].m_name, name) == 0) {
            return &(st_priv_funcs[i]);
        }
    }
    return NULL;
}

int call_priv_func(ppriv_funcs_t privfunc, pargs_options_t pargs)
{
    int ret;
    int val;
    int enabled = 0;

    if (pargs->m_privenable) {
        ret = privfunc->m_enfunc();
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("enable [%s] error[%d]", privfunc->m_name, ret);
            goto fail;
        }
        enabled = 1;
    }

    ret = privfunc->m_getfunc();
    if ( ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get [%s] error[%d]", privfunc->m_name, ret);
        goto fail;
    }

    val = ret;

    if (pargs->m_privenable) {
        ret = privfunc->m_disfunc();
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("disable [%s] error[%d]", privfunc->m_name, ret);
            goto fail;
        }
        enabled = 0;
    }

    return val;
fail:
    if (enabled) {
        privfunc->m_disfunc();
        enabled = 0;
    }
    SETERRNO(ret);
    return ret;

}

int checkpriv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    ppriv_funcs_t privfunc = NULL;
    int ret;
    char* privname;

    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    if (parsestate->leftargs == NULL || parsestate->leftargs[0] == NULL) {
        privfunc = NULL;
        while (1) {
            privfunc = __find_priv_funcs(NULL, privfunc);
            if (privfunc == NULL) {
                break;
            }
            ret = call_priv_func(privfunc, pargs);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%s]=[%d]\n", privfunc->m_name, ret);
        }
    }  else {
        for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
            privname = parsestate->leftargs[i];
            privfunc = __find_priv_funcs(privname, NULL);
            if (privfunc == NULL) {
                fprintf(stderr, "no [%s] found\n", privname);
                continue;
            }
            ret = call_priv_func(privfunc, pargs);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%s]=[%d]\n", privfunc->m_name, ret);
        }
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
