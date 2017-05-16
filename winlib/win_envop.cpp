#include <win_envop.h>
#include <win_err.h>

int get_env_variable(char* envvar,char** ppenvval,int* pvalsize)
{
	char* penv=NULL;
	char* pretval =NULL;
	int retsize=0;
	int vallen = 0,ret=0;
	size_t slen = 0;


	if (envvar == NULL) {
		if (ppenvval && *ppenvval) {
			free(*ppenvval);
		}
		if (ppenvval) {
			*ppenvval = NULL;
		}
		if (pvalsize) {
			*pvalsize = 0;
		}
		return 0;
	}

	if (ppenvval == NULL || pvalsize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	pretval = *ppenvval;
	retsize = *pvalsize;
	penv = getenv(envvar);
	if (penv == NULL) {
		ret = -ERROR_NOT_FOUND;
		goto fail;
	}
	slen = strlen(penv) + 1;
	if ((int)slen > retsize || pretval == NULL) {
		retsize = (int)slen;
		pretval = (char*)malloc((size_t)retsize);
		if (pretval == NULL) {
			GETERRNO(ret);
			ERROR_INFO("can not alloc[%d] error[%d]",retsize,ret);
			goto fail;
		}
	}

	strncpy(pretval,penv,(size_t)retsize);

	if (*ppenvval && *ppenvval != pretval) {
		free(*ppenvval);
	}
	*ppenvval = pretval;
	*pvalsize = retsize;
	return vallen;
fail:
	if (pretval && pretval != *ppenvval) {
		free(pretval);
	}
	pretval = NULL;	
	SETERRNO(-ret);
	return ret;
}