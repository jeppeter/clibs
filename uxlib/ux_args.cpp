
#include <ux_args.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>

void free_args(char*** pppargs)
{
	int i;
	char** ppargs= NULL;
	if (pppargs && *pppargs) {
		ppargs = *pppargs;
		for (i=0;ppargs[i] != NULL;i++) {
			free(ppargs[i]);
			ppargs[i] = NULL;
		}
		free(ppargs);
		*pppargs = NULL;
	}
	return;
}

char** copy_args(int argc,char *argv[])
{
	char** args=NULL;
	int ret;
	int cnt=4;
	int i;

try_again:
	free_args(&args);
	args = (char**)malloc(sizeof(*args) * cnt);
	if (args == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(args,0, sizeof(*args) * cnt);
	i = 0;
	for (i=0;;i++) {
		if (i >= (cnt-1)) {
			cnt <<= 1;
			goto try_again;
		}
		if (argv[i] == NULL) {
			break;
		}
		args[i] = strdup(argv[i]);
		if (args[i] == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}
	return args;
fail:
	free_args(&args);
	SETERRNO(ret);
	return NULL;
}

int  parse_number(char* str,uint64_t *pnum,char** ppend)
{
	char* pcurptr=str;
	int ret;
	int base = 10;
	uint64_t llnum;
	if (str == NULL || pnum == NULL) {
		ret = -EINVAL;
		goto fail;
	}
	if (strncasecmp(pcurptr,"0x",2) == 0) {
		base = 16;
		pcurptr += 2;
	} else if (strncasecmp(pcurptr,"x",1) == 0) {
		base = 16;
		pcurptr += 1;
	}

	SETERRNO(0);
	llnum = strtoull(pcurptr,ppend,base);
	if (llnum == ULLONG_MAX) {
		GETERRNO_DIRECT(ret);
		if (ret == - ERANGE) {
			goto fail;
		}
	}
	*pnum = llnum;
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int  parse_int(char* str,int64_t* pnum,char**ppend)
{
	char* pcurptr=str;
	int ret;
	int base = 10;
	int64_t llnum;
	if (str == NULL || pnum == NULL) {
		ret = -EINVAL;
		goto fail;
	}
	if (strncasecmp(pcurptr,"0x",2) == 0) {
		base = 16;
		pcurptr += 2;
	} else if (strncasecmp(pcurptr,"x",1) == 0) {
		base = 16;
		pcurptr += 1;
	}

	SETERRNO(0);
	llnum = strtoll(pcurptr,ppend,base);
	if (llnum == LLONG_MAX) {
		GETERRNO_DIRECT(ret);
		if (ret == - ERANGE) {
			goto fail;
		}
	}
	*pnum = llnum;
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int  parse_long_double(char* str, long double *pdbl, char** ppend)
{
	int ret;
	long double retdbl;
	char* pretstr=NULL;

	if (pdbl == NULL || str == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	SETERRNO(0);
	retdbl = strtold(str,&pretstr);
	if (retdbl == 0.0 && str == pretstr) {
		ret = -EINVAL;
		goto fail;
	} else if (retdbl == HUGE_VALL) {
		GETERRNO(ret);
		if (ret == -ERANGE) {
			goto fail;
		}
	}
	*pdbl = retdbl;
	if (ppend) {
		*ppend = pretstr;
	}
	return 0;
fail:
	SETERRNO(ret);
	return;
}