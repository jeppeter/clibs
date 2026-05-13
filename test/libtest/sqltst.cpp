typedef struct _sqlite3_func {
	HMODULE m_mod;
	sqlite3_open_v2_func_t m_openfunc;
	sqlite3_exec_func_t m_execfunc;
	sqlite3_close_func_t m_closefunc;
	sqlite3_free_func_t m_freefunc;
} sqlite3_func_t,*psqlite3_func_t;

void free_sqlite3_func(psqlite3_func_t* ppfunc)
{
	if (ppfunc && *ppfunc) {
		psqlite3_func_t pfunc = *ppfunc;
		if (pfunc->m_mod != NULL) {
			FreeLibrary(pfunc->m_mod);
		}
		pfunc->m_mod = NULL;
		memset(pfunc,0,sizeof(*pfunc));
		free(pfunc);
		*ppfunc = NULL;
	}
}

#define  GET_FUNC(pfunc,funcname,funcmem,functype)                                                                         \
do{                                                                                                                        \
	pfunc->funcmem = reinterpret_cast<functype>(reinterpret_cast<void*>(::GetProcAddress(pfunc->m_mod, funcname)));        \
	if (pfunc->funcmem == NULL) {                                                                                          \
		GETERRNO(ret);                                                                                                     \
		ERROR_INFO("GetProcAddress [%s] error %d", funcname, ret);                                                         \
		goto fail;                                                                                                         \
	}                                                                                                                      \
}while(0)

psqlite3_func_t init_sqlite3_func(char* dllfile)
{
	psqlite3_func_t pfunc = NULL;
	int ret;

	pfunc = (psqlite3_func_t)malloc(sizeof(*pfunc));
	if (pfunc == NULL) {
		GETERRNO(ret);
		ERROR_INFO("pfunc error");
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
	GET_FUNC(pfunc,"sqlite3_free",m_freefunc,sqlite3_free_func_t);


	return pfunc;
fail:
	free_sqlite3_func(&pfunc);
	SETERRNO(ret);
	return NULL;
}

int sql_callback(void* n,int argc , char** argv,char** colname)
{
	int i;
	n = n;
	for(i=0;i<argc;i++) {
		fprintf(stdout,"[%s]=[%s]\n", colname[i],argv[i] ? argv[i] : "NULL");
	}
	return 0;
}


int sql3exec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret,lret;
	psqlite3_func_t pfunc = NULL;
	sqlite3* pdb= NULL;
	char* dbfile = NULL;
	char* sqlstmt=NULL;
	int i;
	char* errmsg=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		if (i == 0) {
			dbfile = parsestate->leftargs[i];
		} else if (i == 1) {
			sqlstmt = parsestate->leftargs[i];
		}
	}

	if (dbfile == NULL || sqlstmt == NULL) {
		ret  = - ERROR_INVALID_PARAMETER;
		fprintf(stderr,"no dbfile or sqlstmt set\n");
		goto out;
	}

	if (pargs->m_sqlrdonly != 0) {
		flags = SQLITE_OPEN_READONLY;
	}

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

	lret = pfunc->m_openfunc(dbfile,&pdb, flags,NULL);
	if (lret != SQLITE_OK) {
		GETERRNO(ret);
		ERROR_INFO("open [%s] error %d %d",dbfile,lret,ret);
		goto out;
	}


	lret = pfunc->m_execfunc(pdb,sqlstmt,sql_callback,NULL,&errmsg);
	if (lret != SQLITE_OK) {
		GETERRNO(ret);
		ERROR_INFO("[%s] sql [%s] error %d %s",dbfile,sqlstmt,lret,errmsg);
		goto out;
	}


	fprintf(stdout,"exec [%s] on [%s] succ\n",sqlstmt, dbfile);
	ret = 0;
out:
	if (errmsg) {
		pfunc->m_freefunc(errmsg);
	}
	errmsg = NULL;

	if (pdb != NULL) {
		pfunc->m_closefunc(pdb);
	}
	pdb = NULL;
	free_sqlite3_func(&pfunc);

	SETERRNO(ret);
	return ret;
}