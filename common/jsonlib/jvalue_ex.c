#include <jvalue_ex.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmn_strop.h>
#include <cmn_args.h>
#include <cmn_output_debug.h>


#if defined(_MSC_VER) && _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif


void free_jvalue(jvalue** ppj)
{
  if (ppj && *ppj) {
    jvalue_destroy(*ppj);
    *ppj = NULL;
  }
  return;
}

int add_jobject(jvalue* pj, const char* pkey, const char* value)
{
    jvalue* pinsertval = NULL;
    jvalue* getval = NULL;
    jvalue* parsepj = NULL;
    long double dbl;
    char* quotekey = NULL;
    int qksize = 0;
    char* parsestr = NULL;
    int parsesize = 0;
    int parselen = 0;
    int ret = 0;
    jvalue* pjret = NULL;
    char* pretstr = NULL;
    uint64_t num = 0;
    int64_t inum = 0;
    int added = 1;
    char* unquotestr = NULL;
    int unquotesize = 0;
    if (str_nocase_cmp(value, "null") == 0) {
        pinsertval = jnull_create();
    } else if (str_case_cmp(value, "false") == 0) {
        pinsertval = jbool_create(0);
    } else if (str_case_cmp(value, "true") == 0) {
        pinsertval = jbool_create(1);
    } else {
        ret = parse_int((char*)value, &inum, &pretstr);
        if (ret >= 0 && pretstr != NULL && pretstr[0] == '\0') {
            pinsertval = jint64_create(inum);
        } else {
            ret = parse_number((char*)value, &num, &pretstr);
            if (ret >= 0 && pretstr != NULL && pretstr[0] == '\0') {
                pinsertval = jint64_create((int64_t)num);
            } else {
                ret = parse_long_double((char*)value, &dbl, &pretstr);
                if (ret >= 0 && pretstr != NULL && pretstr[0] == '\0') {
                    pinsertval = jreal_create((double)dbl);
                } else {
                    ret = check_valid_simple_string(value);
                    if (ret > 0) {
                        ret = unquote_string(&unquotestr, &unquotesize, (char*)value);
                        if (ret >= 0) {
                            pinsertval = jstring_create(unquotestr, &ret);
                            unquote_string(&unquotestr, &unquotesize, NULL);
                        } else {
                            GETERRNO(ret);
                            SETERRNO(ret);
                            return ret;
                        }

                    }
                }
            }
        }
    }
    if (pinsertval != NULL) {
        pjret = jobject_put(pj, pkey, pinsertval, &ret);
        if (ret > 0) {
            if (ret > 0) {
                ret = -ret;
            }
            if (ret == 0) {
                ret = -1;
            }
            ERROR_INFO( "insert key[%s] value [%s] error[%d]\n", pkey, value, ret);
            free_jvalue(&pinsertval);
            return ret;
        }
        free_jvalue(&pjret);
        /*not destroy inserted value*/
        return added;
    }

    ret = quote_string(&quotekey, &qksize, "%s", pkey);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now we do not detect whether the value is ,so we should use */
    ret = snprintf_safe(&parsestr, &parsesize, "{ %s : %s }", quotekey, value);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    parsepj = jvalue_read(parsestr, (unsigned int*)&parselen);
    if (parsepj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not parse -----------\n%s\nerror [%d]", parsestr, ret);
        goto fail;
    }

    getval = jobject_get(parsepj, pkey);
    if (getval == NULL) {
        GETERRNO(ret);
        ERROR_INFO("no [%s] found\n%s", pkey, parsestr);
        goto fail;
    }

    switch (getval->type) {
    case JSTRING:
    case JARRAY:
    case JOBJECT:
        break;
    default:
        ret = -CMN_EINVAL;
        ERROR_INFO("not valid type [%d] JNULL[%d] for\n%s", getval->type, JNULL, value);
        goto fail;
    }

    pinsertval = jvalue_clone(getval);
    if (pinsertval == NULL) {
        GETERRNO(ret);
        ERROR_INFO("clone value  error[%d]", ret);
        goto fail;
    }

    /*now insert it*/
    pjret = jobject_put(pj, pkey, pinsertval, &ret);
    if (ret > 0) {
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO( "insert key[%s] value [%s] error[%d]\n", pkey, value, ret);
        goto fail;
    }

    pinsertval = NULL;
    free_jvalue(&pjret);
    free_jvalue(&parsepj);
    snprintf_safe(&parsestr, &parsesize, NULL);
    quote_string(&quotekey, &qksize, NULL);

    return added;
fail:
  free_jvalue(&pinsertval);
  free_jvalue(&pjret);
  free_jvalue(&parsepj);

    snprintf_safe(&parsestr, &parsesize, NULL);
    quote_string(&quotekey, &qksize, NULL);
    SETERRNO(ret);
    return ret;
}
