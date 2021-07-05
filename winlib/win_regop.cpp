#include <win_regop.h>
#include <win_types.h>
#include <win_output_debug.h>
#include <win_uniansi.h>
#include <tchar.h>


#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif

#define  REG_OP_MAGIC     0x448213
#pragma warning(disable:4996)

typedef struct _regop_t {
    uint32_t m_magic;
    uint32_t m_reserv1;
    HKEY m_reghdl;
} regop_t, *pregop_t;

#define GETLRET(ret,lret) do{ ret = lret; if (ret > 0) { ret = -ret ;} if (ret == 0 ){ret = -1;} } while(0)

void __close_regop(pregop_t* ppregop)
{
    if (ppregop != NULL && *ppregop != NULL) {
        pregop_t pregop =  * ppregop;
        if (pregop->m_magic == REG_OP_MAGIC) {
            LONG lret;
            if (pregop->m_reghdl != NULL) {
                lret = RegCloseKey(pregop->m_reghdl);
                if (lret != ERROR_SUCCESS) {
                    ERROR_INFO("can not close key (0x%p) error(%ld)", pregop->m_reghdl, lret);
                }
                pregop->m_reghdl = NULL;
            }
            free(pregop);
        } else {
            ERROR_INFO("0x%p not valid regop", pregop);
        }
        *ppregop = NULL;
    }
    return ;
}

void close_hklm(void** ppregop)
{
    return __close_regop((pregop_t*)ppregop);
}

void* __open_reg(HKEY hkey, const char* psubkey, REGSAM keyaccess)
{
    pregop_t pregop = NULL;
    int ret;
    LONG lret;
    TCHAR *ptsub = NULL;
    int tsubsize = 0;
    pregop = (pregop_t)malloc(sizeof(*pregop));
    if (pregop == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc(%d) error(%d)", sizeof(*pregop), ret);
        goto fail;
    }
    memset(pregop, 0, sizeof(*pregop));
    pregop->m_magic = REG_OP_MAGIC;
    pregop->m_reghdl = NULL;
    ret = AnsiToTchar(psubkey, &ptsub, &tsubsize);
    if (ret < 0) {
        goto fail;
    }

    lret = RegOpenKeyEx(hkey, ptsub, 0, keyaccess, &(pregop->m_reghdl));
    if (lret != ERROR_SUCCESS) {
        GETLRET(ret, lret);
        if (ret != -ERROR_FILE_NOT_FOUND) {
            ERROR_INFO("can not open(%s) with access (%d) error(%d)", psubkey, keyaccess, ret);
        }
        goto fail;
    }

    AnsiToTchar(NULL, &ptsub, &tsubsize);
    return pregop;
fail:
    AnsiToTchar(NULL, &ptsub, &tsubsize);
    __close_regop(&pregop);
    SETERRNO(-ret);
    return NULL;
}


void* open_hklm(const char* psubkey, int accessmode)
{
    REGSAM regaccess = 0;
    if (accessmode & ACCESS_KEY_READ) {
        regaccess |= KEY_READ;
    }

    if (accessmode & ACCESS_KEY_WRITE) {
        regaccess |= KEY_WRITE;
    }

    if (accessmode & ACCESS_KEY_ALL) {
        regaccess = KEY_ALL_ACCESS ;
    }
    return __open_reg(HKEY_LOCAL_MACHINE, psubkey, regaccess);
}

int __query_key_value(pregop_t pregop, const char* path, LPDWORD lptype, LPBYTE pdata, int datasize)
{
    DWORD retdatasize = 0;
    int ret;
    LONG lret;
    TCHAR* ptpath = NULL;
    int tpathsize = 0;

    ret = AnsiToTchar(path, &ptpath, &tpathsize);
    if (ret < 0) {
        goto fail;
    }

    retdatasize = (DWORD)datasize;
    lret = RegQueryValueEx(pregop->m_reghdl, ptpath, NULL, lptype, pdata, &retdatasize);
    if (lret != ERROR_SUCCESS) {
        GETLRET(ret, lret);
        if (ret != -ERROR_MORE_DATA) {
            ERROR_INFO("can not query (%s) error(%d)", path, ret);    
        }        
        goto fail;
    }

    AnsiToTchar(NULL, &ptpath, &tpathsize);
    return (int)retdatasize;
fail:
    AnsiToTchar(NULL, &ptpath, &tpathsize);
    SETERRNO(-ret);
    return ret;
}

int __set_key_value(pregop_t pregop, const char* path, DWORD regtype,void* pdata,int datasize)
{
	TCHAR* ptpath=NULL;
	int tpathsize=0;
	LONG lret;
	int ret;

	ret = AnsiToTchar(path,&ptpath,&tpathsize);
	if (ret < 0) {
		goto fail;
	}

	lret = RegSetValueEx(pregop->m_reghdl,ptpath,0,regtype,(const BYTE*)pdata,(DWORD)datasize);
	if (lret != ERROR_SUCCESS) {
		GETLRET(ret,lret);
		ERROR_INFO("set [%s] value error[%d]", path,ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptpath,&tpathsize);

	return datasize;
fail:
	AnsiToTchar(NULL,&ptpath,&tpathsize);
	SETERRNO(ret);
	return ret;
}


int query_hklm_string(void* pregop, const char* path, char** ppretval, int *pretsize)
{
    pregop_t pinner = (pregop_t) pregop;
    TCHAR *ptval = NULL;
    int tvalsize = 0;
    char* pansival = NULL;
    int ansivalsize = 0;
    int nret;
    DWORD regtype = REG_EXPAND_SZ;
    char* pretval = NULL;
    int retvalsize = 0;
    int ret;

    if (path == NULL) {
        if (ppretval && *ppretval) {
            free(*ppretval);
            *ppretval = NULL;
        }
        if (pretsize) {
            *pretsize = 0;
        }
        return 0;
    }

    if (ppretval == NULL || pretsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretval = *ppretval;
    retvalsize = *pretsize;

    if (pinner == NULL || pinner->m_magic != REG_OP_MAGIC) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    tvalsize = 1024;
try_again:
    if (ptval) {
        free(ptval);
    }
    ptval = NULL;
    ptval = (TCHAR*)malloc((size_t)tvalsize);
    if (ptval == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc(%d) error(%d)", tvalsize, ret);
        goto fail;
    }

    ret = __query_key_value(pinner, path, &regtype, (LPBYTE)ptval, tvalsize);
    if (ret < 0) {
        if (ret == -ERROR_MORE_DATA) {
            tvalsize <<= 1;
            goto try_again;
        }
        goto fail;
    }

    /*now all is ok*/
    ret = TcharToAnsi(ptval, &pansival, &ansivalsize);
    if (ret < 0) {
        goto fail;
    }
    nret = (int)strlen(pansival) + 1;

    if (retvalsize < nret || pretval == NULL) {
        if (retvalsize < nret) {
            retvalsize = nret;
        }
        pretval = (char*)malloc((size_t)retvalsize);
        if (pretval == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc(%d) error(%d)", retvalsize, ret);
            goto fail;
        }
    }

    strncpy_s(pretval, (size_t)nret, pansival, (size_t)nret);
    if (*ppretval && *ppretval != pretval) {
        free(*ppretval);
    }
    *ppretval = pretval;
    *pretsize = retvalsize;

    TcharToAnsi(NULL, &pansival, &ansivalsize);
    if (ptval) {
        free(ptval);
    }
    ptval = NULL;
    tvalsize = 0;
    return nret;
fail:
    TcharToAnsi(NULL, &pansival, &ansivalsize);
    if (ptval) {
        free(ptval);
    }
    ptval = NULL;
    tvalsize = 0;
    SETERRNO(-ret);
    return ret;
}


int query_hklm_binary(void* pregop, const char* path, void** ppdata, int *pdatasize)
{
    pregop_t pinner = (pregop_t) pregop;
    void *ptval = NULL;
    int tvalsize = 0;
    int nret;
    DWORD regtype ;
    void* pretval = *ppdata;
    int retsize = *pdatasize;
    int ret;

    if (path == NULL) {
        if (ppdata !=NULL && (*ppdata) != NULL) {
            free(*ppdata);
            *ppdata = NULL;
        }
        if (pdatasize) {
            *pdatasize = 0;
        }
        return 0;
    }

    if (ppdata == NULL || pdatasize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretval = *ppdata;
    retsize = *pdatasize;

    if (pinner == NULL || pinner->m_magic != REG_OP_MAGIC) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    tvalsize = 1024;
try_again:
    if (ptval) {
        free(ptval);
    }
    ptval = NULL;
    ptval = malloc((size_t)tvalsize);
    if (ptval == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc(%d) error(%d)", tvalsize, ret);
        goto fail;
    }

    regtype = REG_BINARY;
    ret = __query_key_value(pinner, path, &regtype, (LPBYTE)ptval, tvalsize);
    if (ret < 0) {
        if (ret == -ERROR_MORE_DATA) {
            tvalsize <<= 1;
            goto try_again;
        }
        goto fail;
    }

    if (regtype != REG_BINARY) {
        ret = -ERROR_INVALID_DATATYPE;
        ERROR_INFO("[%s] not valid type [0x%lx:%ld]", path, regtype, regtype);
        goto fail;
    }
    nret = ret;

    if (retsize < nret || pretval != NULL) {
        if (pretval != NULL && pretval != *ppdata) {
            free(pretval);
        }
        pretval = NULL;
        retsize = nret;
        pretval = malloc((size_t)nret);
        if (pretval == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", nret, ret);
            goto fail;
        }
    }
    memcpy(pretval, ptval, (size_t)nret);

    if (*ppdata && *ppdata != pretval) {
        free(*ppdata);
    }
    *ppdata = pretval;
    *pdatasize = retsize;

    if (ptval != NULL) {
    	free(ptval);
    }
    ptval = NULL;

    return nret;
fail:
	if (pretval != NULL && pretval != *ppdata) {
		free(pretval);
	}
	pretval = NULL;
	retsize = 0;

    if (ptval) {
        free(ptval);
    }
    ptval = NULL;
    tvalsize = 0;
    SETERRNO(-ret);
    return ret;
}


int set_hklm_binary(void* pregop1, const char* path, void* pdata, int size)
{
	pregop_t pregop = (pregop_t) pregop1;
	int ret;
	if (pdata == NULL || pregop == NULL  || pregop->m_magic != REG_OP_MAGIC || path == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	return __set_key_value(pregop,path,REG_BINARY,pdata,size);
}

int set_hklm_string(void* pregop1, const char* path, char* valstr)
{
    TCHAR* ptval=NULL;
    int valsize=0;
    int vallen=0;
    int ret;
    int nret;
    pregop_t pregop = (pregop_t) pregop1;

    if (pregop == NULL  || pregop->m_magic != REG_OP_MAGIC || path == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }


    ret = AnsiToTchar(valstr,&ptval,&valsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    vallen = (int)_tcslen(ptval);
    ret = __set_key_value(pregop,path, REG_EXPAND_SZ,ptval, (int)((vallen + 1) * sizeof(TCHAR)));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    nret = ret;


    AnsiToTchar(NULL,&ptval,&valsize);
    return nret;
fail:
    AnsiToTchar(NULL,&ptval,&valsize);
    SETERRNO(ret);
    return ret;
}

int set_hklm_sz(void* pregop1, const char* path, char* valstr)
{
    TCHAR* ptval=NULL;
    int valsize=0;
    int vallen=0;
    int ret;
    int nret;
    pregop_t pregop = (pregop_t) pregop1;

    if (pregop == NULL  || pregop->m_magic != REG_OP_MAGIC || path == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }


    ret = AnsiToTchar(valstr,&ptval,&valsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    vallen = (int)_tcslen(ptval);
    ret = __set_key_value(pregop,path, REG_SZ,ptval, (int)((vallen + 1) * sizeof(TCHAR)));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    nret = ret;


    AnsiToTchar(NULL,&ptval,&valsize);
    return nret;
fail:
    AnsiToTchar(NULL,&ptval,&valsize);
    SETERRNO(ret);
    return ret;
}