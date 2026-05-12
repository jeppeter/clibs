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

	pfunc->m_openfunc = (sqlite3_open_v2_func_t)GetProcAddress(pfunc->m_mod, "sqlite3_open_v2");
	if (pfunc->m_openfunc == NULL) {
		GETERRNO(ret);
		ERROR_INFO("GetProcAddress [sqlite3_open_v2] error %d", ret);
		goto fail;
	}

	pfunc->m_execfunc = (sqlite3_exec_func_t) GetProcAddress(pfunc->m_mod,"sqlite3_exec");
	



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
	sqlite3_open_v2_func_t openfunc = NULL;
	sqlite3_exec_func_t execfunc = NULL;
	sqlite3_close_func_t closefunc=NULL;
	sqlite3* pdb= NULL;
	char* dbfile = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_level(pargs);

	if (pargs->m_sqldllfile == NULL) {
		ret = - ERROR_INVALID_PARAMETER;
		fprintf(stderr, "no sqldllfile set\n");
		goto out;
	}

	hmod = LoadLibraryA(pargs->m_sqldllfile);
	if (hmod == NULL) {
		GETERRNO(ret);
		fprintf(stderr,"can not load [%s] error %d\n",pargs->m_sqldllfile,ret);
		goto out;
	}

	openfunc = GetProcAddress(hmod,"sqlite3_open_v2");
	if (openfunc )



out:
	SETERRNO(ret);
	return ret;
}