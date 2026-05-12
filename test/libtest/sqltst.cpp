typedef struct _sqlite3_func {
	HMODULE m_mod;
	sqlite3_open_v2_func_t m_openfunc;
	sqlite3_exec_func_t m_execfunc;
	sqlite3_close_func_t m_closefunc;
} sqlite3_func_t,*psqlite3_func_t;

void free_sqlite3_func(psqlite3_func_t* ppfunc)
{
	if (ppfunc && *ppfunc) {
		psqlite3_func_t pfunc = *ppfunc;
		if (pfunc->m_mod != NULL) {
			FreeLibraryA(pfunc->m_mod);
		}
		pfunc->m_mod = NULL;
		memset(pfunc,0,sizeof(*pfunc));
		free(pfunc);
		*ppfunc = NULL;
	}
}

#define  GET_FUNC(pfunc,funcname,funcmem,functype)                                                \
do{                                                                                               \
	pfunc->funcmem = (functype) ::GetProcAddress(pfunc->m_mod, funcname);                         \
	if (pfunc->funcmem == NULL) {                                                                 \
		GETERRNO(ret);                                                                            \
		ERROR_INFO("GetProcAddress [%s] error %d", funcname, ret);                                \
		goto fail;                                                                                \
	}                                                                                             \
}

psqlite3_func_t init_sqlite3_func(char* dllfile)
{
	psqlite3_func_t pfunc = NULL;

	pfunc = malloc(sizeof(*pfunc));
	if (pfunc == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pfunc, 0, sizeof(*pfunc));
	pfunc->m_mod = LoadLibraryA(dllfile);
	if (pfunc->m_mod == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not load [%s] error %d", dllfile,ret);
		goto fail;
	}

	GET_FUNC(pfunc,"sqlite3_open_v2",m_openfunc,sqlite3_open_v2_func_t);
	GET_FUNC(pfunc,"sqlite3_exec",m_execfunc,sqlite3_exec_func_t);
	GET_FUNC(pfunc,"sqlite3_close",m_closefunc,sqlite3_close_func_t);


	return pfunc;
fail:
	free_sqlite3_func(&pfunc);
	SETERRNO(ret);
	return NULL;
}


int sql3exec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	HMODULE hmod= NULL;
	psqlite3_func_t pfunc = NULL;
	sqlite3* pdb= NULL;
	char* dbfile = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_level(pargs);

	for(i=0;)

	if (pargs->m_sqldllfile == NULL) {
		ret = - ERROR_INVALID_PARAMETER;
		fprintf(stderr, "no sqldllfile set\n");
		goto out;
	}


	pfunc = init_sqlite3_func(pargs->m_sqldllfile);
	if (pfunc == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = pfunc->m_openfunc()


out:
	if (pdb != NULL) {
		pfunc->m_closefunc(pdb);
	}
	pdb = NULL;
	free_sqlite3_func(&pfunc);

	SETERRNO(ret);
	return ret;
}