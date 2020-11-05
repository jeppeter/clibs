
int get_max_str(int a, const char* str)
{
    int b = 0;
    if (str != NULL) {
        b = (int)strlen(str);
    }
    if (a > b) {
        return a;
    }
    return b;
}



int getacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int i, j;
    void* pacl = NULL;
    const char* fname;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* user = NULL;
    int usersize = 0;
    char* action = NULL;
    int actionsize = 0;
    char* right = NULL;
    int rightsize = 0;
    char* inherit = NULL;
    int inheritsize = 0;
    char* owner = NULL, *group = NULL;
    int ownersize = 0, grpsize = 0;
    int maxownersize = 0;
    int maxgroupsize = 0;
    int maxusersize = 0;
    int maxactionsize = 0;
    int maxrightsize = 0;
    int maxinheritsize = 0;
    int maxfilesize = 0;
    init_log_level(pargs);
    argc = argc;
    argv = argv;


    if (parsestate->leftargs) {
        ret = snprintf_safe(&user, &usersize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&action, &actionsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&right, &rightsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&inherit, &inheritsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&owner, &ownersize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&group, &grpsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            fname = parsestate->leftargs[i];
            maxfilesize = get_max_str(maxfilesize, fname);
            ret = get_file_acls(fname, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%d][%s] acl error[%d]\n", i, fname, ret);
                goto out;
            }

            ret = get_file_owner(pacl, &owner, &ownersize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] owner error[%d]\n", fname, ret);
                goto out;
            }
            maxownersize = get_max_str(maxownersize, owner);

            ret = get_file_group(pacl, &group, &grpsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] group error[%d]\n", fname, ret);
                goto out;
            }
            maxgroupsize = get_max_str(maxgroupsize, group);


            j = 0;
            while (1) {
                ret = get_sacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl user error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxusersize = get_max_str(maxusersize, user);

                ret = get_sacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl action error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxactionsize = get_max_str(maxactionsize, action);

                ret = get_sacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl right error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxrightsize = get_max_str(maxrightsize, right);

                ret = get_sacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxinheritsize = get_max_str(maxinheritsize, inherit);

                j ++;
            }
            j = 0;
            while (1) {
                ret = get_dacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxusersize = get_max_str(maxusersize, user);

                ret = get_dacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl action error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxactionsize = get_max_str(maxactionsize, action);

                ret = get_dacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl right error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxrightsize = get_max_str(maxrightsize, right);

                ret = get_dacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxinheritsize = get_max_str(maxinheritsize, inherit);
                j ++;
            }
        }

        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            fname = parsestate->leftargs[i];
            ret = get_file_acls(fname, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%d][%s] acl error[%d]\n", i, fname, ret);
                goto out;
            }

            ret = get_file_owner(pacl, &owner, &ownersize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] owner error[%d]\n", fname, ret);
                goto out;
            }


            ret = get_file_group(pacl, &group, &grpsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] group error[%d]\n", fname, ret);
                goto out;
            }


            j = 0;
            while (1) {
                ret = get_sacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl user error[%d]\n", i, fname, ret);
                    goto out;
                }
                ret = get_sacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl action error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_sacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl right error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_sacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }

                fprintf(stdout, "[%03d][%03d]%-5s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", i, j, "sacl",
                        maxfilesize + 1, fname, maxownersize + 1 , owner,
                        maxgroupsize + 1, group, maxusersize + 1, user,
                        maxactionsize + 1 , action, maxrightsize + 1 , right,
                        maxinheritsize + 1, inherit);

                j ++;
            }
            j = 0;
            while (1) {
                ret = get_dacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl action error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl right error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }

                fprintf(stdout, "[%03d][%03d]%-5s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", i, j, "dacl",
                        maxfilesize + 1, fname, maxownersize + 1 , owner,
                        maxgroupsize + 1, group, maxusersize + 1, user,
                        maxactionsize + 1 , action, maxrightsize + 1 , right,
                        maxinheritsize + 1, inherit);
                j ++;
            }
        }
    }
    ret = 0;
out:
    get_file_group(NULL, &group, &grpsize);
    get_file_owner(NULL, &owner, &ownersize);
    get_sacl_inheritance(NULL, 0, &inherit, &inheritsize);
    get_sacl_right(NULL, 0, &right, &rightsize);
    get_sacl_action(NULL, 0, &action, &actionsize);
    get_sacl_user(NULL, 0, &user, &usersize);
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int setowner_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* owner = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need owner files...\n");
        goto out;
    }
    owner = parsestate->leftargs[0];
    for (i = 1; parsestate->leftargs[i] != NULL; i++) {
        fname = parsestate->leftargs[i];
        ret = set_file_owner(fname, owner);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%d][%s] set owner error[%d]\n", i, fname, ret);
            goto out;
        }

        fprintf(stdout, "[%d][%s] owner [%s] succ\n", i, fname, owner);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getsid_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    char* psidstr = NULL;
    int strsize = 0;
    char* username = NULL;
    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i ++) {
        username = parsestate->leftargs[i];
        ret = get_name_sid(username, &psidstr, &strsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%d][%s] sid error[%d]\n", i, username, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] sid [%s]\n", i, username, psidstr);
    }

    ret = 0;
out:
    get_name_sid(NULL, &psidstr, &strsize);
    SETERRNO(ret);
    return ret;
}

int setgroup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* group = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need group files...\n");
        goto out;
    }
    group = parsestate->leftargs[0];
    for (i = 1; parsestate->leftargs[i] != NULL; i++) {
        fname = parsestate->leftargs[i];
        ret = set_file_group(fname, group);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%d][%s] set group error[%d]\n", i, fname, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] group [%s] succ\n", i, fname, group);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int removesacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    void* pacl = NULL;
    const char* usage = "fname username action right [inherit] to remove the sacl";
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }

    ret = remove_sacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] remove sacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] remove sacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int removedacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to remove the dacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }


    ret = remove_dacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] remove dacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] remove dacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int addsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to add the sacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }


    ret = add_sacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] add sacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] add sacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}


int adddacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to add the dacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }

    ret = add_dacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] add dacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] add dacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int __get_security_descriptor_from_string_2(char* sddl, PSECURITY_DESCRIPTOR* ppdp)
{
    int ret;
    BOOL bret;
    TCHAR* ptsddl = NULL;
    int tsddlsize = 0;
    ULONG dpsize = 0;
    if (sddl == NULL) {
        if (ppdp && *ppdp) {
            LocalFree(*ppdp);
            *ppdp = NULL;
        }
        return 0;
    }
    if (ppdp == NULL || *ppdp != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        GETERRNO(ret);
        return ret;
    }

    ret = AnsiToTchar(sddl, &ptsddl, &tsddlsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = ConvertStringSecurityDescriptorToSecurityDescriptor(ptsddl, SDDL_REVISION_1, ppdp, &dpsize);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not convert [%s] to security_descriptor error[%d]", sddl, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptsddl, &tsddlsize);
    return (int)GetSecurityDescriptorLength(*ppdp);
fail:
    AnsiToTchar(NULL, &ptsddl, &tsddlsize);
    SETERRNO(ret);
    return ret;
}

static int __get_dacl_from_descriptor(PSECURITY_DESCRIPTOR psdp, PACL* ppacl)
{
    BOOL bacldefault, bacl;
    BOOL bret;
    PACL acl = NULL;
    int ret;
    int retval = 1;

    bacl = FALSE;
    bacldefault = FALSE;
    bret = GetSecurityDescriptorDacl(psdp, &bacl, &acl, &bacldefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get acl error[%d]", ret);
        goto fail;
    }

    if (!bacl) {
        retval = 0;
        acl = NULL;
    }
    if (ppacl && acl != NULL) {
        *ppacl = acl;
    }

    return retval;
fail:
    SETERRNO(ret);
    return NULL;
}

static int __get_sid_name(PSID psid, char** ppstr, int *pstrsize)
{
    SID_NAME_USE siduse;
    TCHAR* ptuser = NULL, *ptdomain = NULL;
    DWORD tusersize = 0, tuserlen = 0;
    DWORD tdomainsize = 0, tdomainlen = 0;
    char* pname = NULL, *pdomain = NULL;
    int namesize = 0, namelen = 0, domainsize = 0, domainlen = 0;
    int ret;
    BOOL bret;
    int retlen;

    if (psid == NULL) {
        return snprintf_safe(ppstr, pstrsize, NULL);
    }

    tusersize = 32;
    tdomainsize = 32;
try_get_sid_old:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    ptuser = (TCHAR*) malloc(tusersize * sizeof(TCHAR));
    if (ptuser == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tusersize * sizeof(TCHAR), ret);
        goto fail;
    }

    ptdomain = (TCHAR*)malloc(tdomainsize * sizeof(TCHAR));
    if (ptdomain == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tdomainsize * sizeof(TCHAR), ret);
        goto fail;
    }
    tuserlen = tusersize;
    tdomainlen = tdomainsize;
    bret = LookupAccountSid(NULL, psid, ptuser, &tuserlen, ptdomain, &tdomainlen, &siduse);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            tusersize = tuserlen << 1;
            tdomainsize = tdomainlen << 1;
            goto try_get_sid_old;
        }
        ERROR_INFO("get sid error [%d]", ret);
        goto fail;
    }
    ret = TcharToAnsi(ptuser, &pname, &namesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    namelen = ret;

    ret = TcharToAnsi(ptdomain, &pdomain, &domainsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    domainlen = ret;

    if (domainlen > 0) {
        DEBUG_INFO("domain [%s] name [%s]", pdomain, pname);
        ret = snprintf_safe(ppstr, pstrsize, "%s\\%s", pdomain, pname);
    } else {
        ret = snprintf_safe(ppstr, pstrsize, "%s", pname);
    }
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    return retlen;
fail:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    SETERRNO(ret);
    return ret;
}


static void __debug_access_inner_2(PEXPLICIT_ACCESS pcuracc, const char* prefix)
{
    PSID psid = NULL;
    int ret;
    char* name = NULL;
    int namesize = 0;
    DEBUG_INFO("%s grfAccessPermissions [0x%lx]", prefix, pcuracc->grfAccessPermissions);
    if ((pcuracc->grfAccessPermissions & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL) {
        DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_ALL);
    } else {
        if (pcuracc->grfAccessPermissions & DELETE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_DELETE);
        }
        if (pcuracc->grfAccessPermissions & READ_CONTROL) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_READ_CONTROL);
        }
        if (pcuracc->grfAccessPermissions & WRITE_DAC) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_DAC);
        }
        if (pcuracc->grfAccessPermissions & WRITE_OWNER) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_OWNER);
        }
        if (pcuracc->grfAccessPermissions & SYNCHRONIZE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_SYNCHRONIZE);
        }
    }


    switch (pcuracc->grfAccessMode) {
    case NOT_USED_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_NOT_USED);
        break;
    case GRANT_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_GRANT);
        break;
    case SET_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_SET);
        break;
    case DENY_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_DENY);
        break;
    case REVOKE_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_REVOKE);
        break;
    case SET_AUDIT_SUCCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_SUCC);
        break;
    case SET_AUDIT_FAILURE:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_FAIL);
        break;
    default:
        DEBUG_INFO("%s grfAccessMode [0x%lx]", prefix, pcuracc->grfAccessMode);
    }

    DEBUG_INFO("%s grfInheritance [0x%x]", prefix, pcuracc->grfInheritance);
    if (pcuracc->grfInheritance == 0) {
        if ((pcuracc->grfInheritance & NO_INHERITANCE) == NO_INHERITANCE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_NO_INHERITANCE);
        }
    } else {
        if ((pcuracc->grfInheritance & CONTAINER_INHERIT_ACE) == CONTAINER_INHERIT_ACE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_CONTAINER_INHERIT_ACE);
        }

        if ((pcuracc->grfInheritance & INHERIT_NO_PROPAGATE) == INHERIT_NO_PROPAGATE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_NO_PROPAGATE);
        }

        if ((pcuracc->grfInheritance & INHERIT_ONLY) == INHERIT_ONLY) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_ONLY);
        }
        if ((pcuracc->grfInheritance & OBJECT_INHERIT_ACE) == OBJECT_INHERIT_ACE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_OBJECT_INHERIT_ACE);
        }
        if ((pcuracc->grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT) == SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        }
    }

    DEBUG_INFO("%s pMultipleTrustee [%p]", prefix, pcuracc->Trustee.pMultipleTrustee);
    DEBUG_INFO("%s MultipleTrusteeOperation [0x%x]", prefix, pcuracc->Trustee.MultipleTrusteeOperation);
    DEBUG_INFO("%s TrusteeForm [0x%x]", prefix, pcuracc->Trustee.TrusteeForm);
    DEBUG_INFO("%s TrusteeType [0x%x]", prefix, pcuracc->Trustee.TrusteeType);

    if (pcuracc->Trustee.TrusteeForm == TRUSTEE_IS_SID  &&
            pcuracc->Trustee.TrusteeType == TRUSTEE_IS_UNKNOWN &&
            pcuracc->Trustee.ptstrName != NULL) {
        psid = (PSID) pcuracc->Trustee.ptstrName;
        ret = __get_sid_name(psid, &name, &namesize);
        if (ret > 0) {
            DEBUG_INFO("%s name [%s]", prefix, name);
        }
    }
    __get_sid_name(NULL, &name, &namesize);
    return;
}

static void __debug_access_2(PEXPLICIT_ACCESS paccess, int accnum)
{
    char* prefix = NULL;
    int prefixsize = 0;
    int ret;
    int i;
    for (i = 0; i < accnum; i++) {
        ret = snprintf_safe(&prefix, &prefixsize, "[%d]", i);
        if (ret > 0) {
            __debug_access_inner_2(&(paccess[i]), prefix);
        }
    }
    snprintf_safe(&prefix, &prefixsize, NULL);
    return;
}

static void __free_trustee_2(PTRUSTEE* pptrustee);

static void __release_trustee_2(PTRUSTEE ptrustee)
{
    if (ptrustee) {
        __free_trustee_2(&(ptrustee->pMultipleTrustee));
        ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ptrustee->TrusteeForm = TRUSTEE_IS_SID;
        ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
        if (ptrustee->ptstrName) {
            LocalFree(ptrustee->ptstrName);
            ptrustee->ptstrName = NULL;
        }
    }
    return;
}

static void __free_trustee_2(PTRUSTEE *pptrustee)
{
    PTRUSTEE ptrustee = NULL;
    if (pptrustee && *pptrustee) {
        ptrustee = *pptrustee;
        __release_trustee_2(ptrustee);
        LocalFree(ptrustee);
        *pptrustee = NULL;
    }
    return ;
}


static int __init_trustee_2(PTRUSTEE ptrustee)
{
    memset(ptrustee, 0 , sizeof(*ptrustee));
    ptrustee->pMultipleTrustee = NULL;
    ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ptrustee->TrusteeForm = TRUSTEE_IS_SID;
    ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
    ptrustee->ptstrName = NULL;
    return 0;
}


static int __init_explicit_access_2(PEXPLICIT_ACCESS pacc)
{
    memset(pacc, 0 , sizeof(*pacc));
    pacc->grfAccessPermissions = 0;
    pacc->grfAccessMode = NOT_USED_ACCESS;
    pacc->grfInheritance = NO_INHERITANCE;
    return __init_trustee_2(&(pacc->Trustee));
}

static void __release_explicit_access_2(PEXPLICIT_ACCESS pacc)
{
    if (pacc) {
        __release_trustee_2(&(pacc->Trustee));
    }
    return;
}

static void __free_explicit_access_array_2(PEXPLICIT_ACCESS *ppacc, int *psize)
{
    if (ppacc && *ppacc && psize ) {
        int i;
        PEXPLICIT_ACCESS pacc = NULL;
        int size = *psize;
        pacc = *ppacc;
        for (i = 0; i < size; i++) {
            __release_explicit_access_2(&(pacc[i]));
        }
        LocalFree(pacc);
    }
    if (ppacc) {
        *ppacc = NULL;
    }
    if (psize) {
        *psize = 0;
    }
    return;
}

static PEXPLICIT_ACCESS __alloc_explicit_access_array_2(int size)
{
    PEXPLICIT_ACCESS pnewacc = NULL;
    int sz = size;
    int ret;
    int i;

    pnewacc = (PEXPLICIT_ACCESS)LocalAlloc(LMEM_FIXED, sizeof(*pnewacc) * sz);
    if (pnewacc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*pnewacc)*sz, ret);
        goto fail;
    }
    memset(pnewacc, 0, sizeof(*pnewacc) * sz);
    for (i = 0; i < sz; i++) {
        ret = __init_explicit_access_2(&(pnewacc[i]));
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    return pnewacc;
fail:
    __free_explicit_access_array_2(&pnewacc, &sz);
    SETERRNO(ret);
    return NULL;
}

static int __copy_sid_2(PSID osid, PSID* ppnsid)
{
    int sidsize = 0;
    int ret;
    BOOL bret;

    if (osid == NULL) {
        if (ppnsid && *ppnsid) {
            LocalFree(*ppnsid);
            *ppnsid = NULL;
        }
        return 0;
    }

    if (ppnsid  == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    sidsize = MIN_SID_SIZE;
copy_sid_again:
    if (*ppnsid != NULL) {
        LocalFree(*ppnsid);
    }
    *ppnsid = NULL;
    *ppnsid = (PSID)LocalAlloc(LMEM_FIXED, (SIZE_T)sidsize);
    if ((*ppnsid) == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sidsize, ret);
        goto fail;
    }
    bret = CopySid((DWORD)sidsize, (*ppnsid), osid);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            sidsize <<= 1;
            goto copy_sid_again;
        }
        ERROR_INFO("copy sid error[%d]", ret);
        goto fail;
    }
    return sidsize;
fail:
    if (*ppnsid) {
        LocalFree(*ppnsid);
        *ppnsid = NULL;
    }
    SETERRNO(ret);
    return ret;
}

static int __trans_aceflags_to_inherit_2(BYTE flags, DWORD * pinherit)
{
    DWORD inherit = 0;

    if (flags == FAILED_ACCESS_ACE_FLAG) {
        inherit |= INHERIT_NO_PROPAGATE;
    }

    if (flags == CONTAINER_INHERIT_ACE) {
        inherit |= CONTAINER_INHERIT_ACE;
    }
    if (flags == FAILED_ACCESS_ACE_FLAG) {
        inherit |= NO_INHERITANCE;
    }
    if (flags == INHERIT_ONLY_ACE) {
        inherit |= INHERIT_ONLY_ACE;
    }

    if (flags == INHERITED_ACE) {
        inherit |= INHERIT_ONLY;
    }
    if (flags == NO_PROPAGATE_INHERIT_ACE) {
        inherit |= NO_PROPAGATE_INHERIT_ACE;
    }
    if (flags == OBJECT_INHERIT_ACE) {
        inherit |= OBJECT_INHERIT_ACE;
    }
    if (flags == SUCCESSFUL_ACCESS_ACE_FLAG) {
        inherit |= SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    }
    *pinherit = inherit;
    return 0;
}

static int __get_explicit_access_2(PACL acl, PEXPLICIT_ACCESS *ppaccess, int *psize)
{
    int accnum = 0;
    int ret;
    PEXPLICIT_ACCESS pretaccess = NULL;
    int retsize = 0;
    void* curp;
    ACE_HEADER* pheader = NULL;
    int i;
    BOOL bret;
    PEXPLICIT_ACCESS pcuracc = NULL;
    PACCESS_ALLOWED_ACE pallowace = NULL;
    PACCESS_ALLOWED_CALLBACK_ACE pallowcallbackace = NULL;
    PACCESS_ALLOWED_CALLBACK_OBJECT_ACE pallowcallbackobjace = NULL;
    PACCESS_ALLOWED_OBJECT_ACE pallowobjace = NULL;
    ACCESS_DENIED_ACE* pdenyace = NULL;
    PACCESS_DENIED_CALLBACK_ACE pdenycallbackace = NULL;
    PACCESS_DENIED_CALLBACK_OBJECT_ACE pdenycallbackobjace = NULL;
    PACCESS_DENIED_OBJECT_ACE pdenyobjace = NULL;

    if (acl == NULL) {
        if (ppaccess && *ppaccess) {
            LocalFree(*ppaccess);
            *ppaccess = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (ppaccess == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretaccess = *ppaccess;
    retsize = *psize;

    if (*ppaccess != NULL || *psize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (retsize < acl->AceCount || pretaccess == NULL) {
        retsize = acl->AceCount;
        pretaccess = __alloc_explicit_access_array_2(retsize);
        if (pretaccess == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    } else {
        for (i = 0; i < retsize; i++) {
            __release_explicit_access_2(&(pretaccess[i]));
            ret = __init_explicit_access_2(&(pretaccess[i]));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }
    }

    /*now we should give the output*/
    accnum = 0;
    for (i = 0; i < acl->AceCount; i++) {
        /*now to give the count*/
        bret = GetAce(acl, (DWORD)i, &curp);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("get [%d] error[%d]", i, ret);
            goto fail;
        }
        pheader = (ACE_HEADER*) curp;
        pcuracc = &(pretaccess[accnum]);
        switch (pheader->AceType) {
        case ACCESS_ALLOWED_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_ACE_TYPE][%d]", i, pheader->AceType);
            pallowace = (PACCESS_ALLOWED_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            pallowcallbackace = (PACCESS_ALLOWED_CALLBACK_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowcallbackace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowcallbackace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowcallbackace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pallowcallbackobjace = (PACCESS_ALLOWED_CALLBACK_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowcallbackobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowcallbackobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowcallbackobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_COMPOUND_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pallowobjace = (PACCESS_ALLOWED_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_ACE_TYPE][%d]", i, pheader->AceType);
            pdenyace = (ACCESS_DENIED_ACE*) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenyace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenyace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenyace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            pdenycallbackace = (PACCESS_DENIED_CALLBACK_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenycallbackace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenycallbackace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenycallbackace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pdenycallbackobjace = (PACCESS_DENIED_CALLBACK_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenycallbackobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenycallbackobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenycallbackobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pdenyobjace = (PACCESS_DENIED_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenyobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenyobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenyobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_MAX_MS_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_MAX_MS_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case ACCESS_MAX_MS_V2_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_MAX_MS_V2_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_ALARM_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_MANDATORY_LABEL_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        default:
            ERROR_INFO("[%d] type [%d]", pheader->AceType);
            break;
        }

    }

    if (*ppaccess && *ppaccess != pretaccess) {
        __free_explicit_access_array_2(ppaccess, psize);
    }
    *ppaccess = pretaccess;
    *psize = retsize;
    DEBUG_INFO("get [%p] ppaccess [%p] size [%d]", acl, *ppaccess, *psize);
    __debug_access_2(*ppaccess, accnum);
    return accnum;

fail:
    if (pretaccess && pretaccess != *ppaccess) {
        __free_explicit_access_array_2(&pretaccess, &retsize);
    } else if (pretaccess != NULL) {
        for (i = 0; i < retsize; i++) {
            __release_explicit_access_2(&(pretaccess[i]));
        }
    }
    pretaccess = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

#pragma comment(lib,"Advapi32.lib")

int dumpsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    PSECURITY_DESCRIPTOR pdp = NULL;
    char* sddl = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            sddl = parsestate->leftargs[i];
            ret = __get_security_descriptor_from_string_2(sddl, &pdp);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not change [%d][%s] error[%d]\n", i, sddl, ret);
                goto out;
            }
            DEBUG_BUFFER_FMT(pdp, ret, "[%d][sacl][%s]", i , sddl);
            __get_security_descriptor_from_string_2(NULL, &pdp);
        }
    }

    ret = 0;
out:
    __get_security_descriptor_from_string_2(NULL, &pdp);
    SETERRNO(ret);
    return ret;
}



int dumpdacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    PSECURITY_DESCRIPTOR pdp = NULL;
    char* sddl = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    PACL pacl = NULL;
    PEXPLICIT_ACCESS paccess = NULL;
    int accsize = 0;
    int accnum = 0;
    int dpsize = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            sddl = parsestate->leftargs[i];
            ret = __get_security_descriptor_from_string_2(sddl, &pdp);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not change [%d][%s] error[%d]\n", i, sddl, ret);
                goto out;
            }
            dpsize = ret;

            ret = __get_dacl_from_descriptor(pdp, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d][%s]can not get dacl error[%d]", i, sddl, ret);
                goto out;
            } else if (ret == 0) {
                fprintf(stdout, "[%d][%s] no dacl\n", i, sddl);
                goto next_one;
            }


            ret = __get_explicit_access_2(pacl, &paccess, &accsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d][%s]can not get explicit access error[%d]\n", i, sddl, ret);
                goto out;
            }
            accnum = ret;

            DEBUG_BUFFER_FMT(pdp, dpsize, "[%d][dacl][%s] for [%d] explicit access", i , sddl, accnum);
next_one:
            __get_explicit_access_2(NULL, &paccess, &accsize);
            accnum = 0;
            __get_security_descriptor_from_string_2(NULL, &pdp);
        }
    }

    ret = 0;
out:
    __get_explicit_access_2(NULL, &paccess, &accsize);
    __get_security_descriptor_from_string_2(NULL, &pdp);
    SETERRNO(ret);
    return ret;
}
