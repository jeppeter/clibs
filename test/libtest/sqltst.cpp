typedef struct _sqlite3_func {
	HMODULE m_mod;
	sqlite3_open_v2_func_t m_openfunc;
	sqlite3_exec_func_t m_execfunc;
	sqlite3_close_func_t m_closefunc;
	sqlite3_free_func_t m_freefunc;

	sqlite3_prepare_v3_func_t m_preparefunc;
	sqlite3_bind_blob_func_t m_bindblobfunc;
	sqlite3_bind_blob64_func_t m_bindblob64func;
	sqlite3_bind_double_func_t m_binddoublefunc;
	sqlite3_bind_int_func_t m_bindintfunc;
	sqlite3_bind_int64_func_t m_bindint64func;
	sqlite3_bind_null_func_t m_bindnullfunc;
	sqlite3_bind_text_func_t m_bindtextfunc;
	sqlite3_step_func_t m_stepfunc;
	sqlite3_finalize_func_t m_finalizefunc;

	sqlite3_column_count_func_t m_colcountfunc;
	sqlite3_column_type_func_t m_coltypefunc;
	sqlite3_column_text_func_t m_coltextfunc;
	sqlite3_column_double_func_t m_coldblfunc;
	sqlite3_column_int_func_t m_colintfunc;
	sqlite3_column_int64_func_t m_colint64func;
	sqlite3_column_blob_func_t m_colblobfunc;
	sqlite3_column_bytes_func_t m_colbytesfunc;

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
	GET_FUNC(pfunc,"sqlite3_prepare_v3",m_preparefunc,sqlite3_prepare_v3_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_blob",m_bindblobfunc,sqlite3_bind_blob_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_blob64",m_bindblob64func,sqlite3_bind_blob64_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_double",m_binddoublefunc,sqlite3_bind_double_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_int",m_bindintfunc,sqlite3_bind_int_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_int64",m_bindint64func,sqlite3_bind_int64_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_null",m_bindnullfunc,sqlite3_bind_null_func_t);
	GET_FUNC(pfunc,"sqlite3_bind_text",m_bindtextfunc,sqlite3_bind_text_func_t);
	GET_FUNC(pfunc,"sqlite3_step",m_stepfunc,sqlite3_step_func_t);
	GET_FUNC(pfunc,"sqlite3_finalize",m_finalizefunc,sqlite3_finalize_func_t);

	GET_FUNC(pfunc,"sqlite3_column_count",m_colcountfunc,sqlite3_column_count_func_t);
	GET_FUNC(pfunc,"sqlite3_column_type",m_coltypefunc,sqlite3_column_type_func_t);
	GET_FUNC(pfunc,"sqlite3_column_text",m_coltextfunc,sqlite3_column_text_func_t);
	GET_FUNC(pfunc,"sqlite3_column_double",m_coldblfunc,sqlite3_column_double_func_t);
	GET_FUNC(pfunc,"sqlite3_column_int",m_colintfunc,sqlite3_column_int_func_t);
	GET_FUNC(pfunc,"sqlite3_column_int64",m_colint64func,sqlite3_column_int64_func_t);
	GET_FUNC(pfunc,"sqlite3_column_blob",m_colblobfunc,sqlite3_column_blob_func_t);
	GET_FUNC(pfunc,"sqlite3_column_bytes",m_colbytesfunc,sqlite3_column_bytes_func_t);


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

int parse_blob(char* curptr,unsigned char** ppbuf,int *psize)
{
	int retlen=0;
	int retsize=0;
	unsigned char* pretbuf=NULL;
	unsigned long long lval;
	char* pcur = curptr;
	int base;
	char* pendptr=NULL;
	unsigned char* ptmp =NULL;
	int ret;

	if (curptr == NULL) {
		if (ppbuf && *ppbuf) {
			free(*ppbuf);
			*ppbuf = NULL;
		}

		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppbuf == NULL || psize == NULL) {
		ret = - ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretbuf = *ppbuf;
	retsize = *psize;

	while(*pcur != '\0') {
		base = 10;
		if (_strnicmp(pcur,"0x",2)== 0) {
			pcur += 2;
			base = 16;
		} else if (_strnicmp(pcur,"x",1) == 0) {
			pcur += 1;
			base = 16;
		}
		lval = strtoull(pcur,&pendptr,base);
		if (retsize < (retlen + 1) || pretbuf == NULL) {
			if (retsize == 0) {
				retsize = 4;
			} else {
				retsize <<= 1;
			}

			ptmp = (unsigned char*)malloc((size_t)retsize);
			if (ptmp == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			memset(ptmp,0, (size_t)retsize);
			if (retlen > 0) {
				memcpy(ptmp,pretbuf,(size_t)retlen);
			}

			if (pretbuf != NULL && pretbuf != *ppbuf) {
				free(pretbuf);
			}
			pretbuf = ptmp;
			ptmp = NULL;
		}

		pretbuf[retlen] = (unsigned char) lval;
		retlen += 1;
		pcur = pendptr;
		if (*pcur == ',') {
			pcur += 1;
		}
	}

	if (*ppbuf && *ppbuf != pretbuf) {
		free(*ppbuf);
	}
	*ppbuf = pretbuf;
	*psize = retsize;
	return retlen;
fail:
	if (ptmp) {
		free(ptmp);
	}
	ptmp = NULL;

	if (pretbuf && pretbuf != *ppbuf) {
		free(pretbuf);
	}
	pretbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int prepare_args(psqlite3_func_t pfunc,sqlite3_stmt* stmt,int index,char* sqlstmt)
{
	char* curptr=NULL;
	char* pendptr=NULL;
	int val;
	sqlite3_int64 val64;
	int lret,ret;
	int base = 10;
	double dval;
	unsigned char* pbuf=NULL;
	int retsize=0;
	int retlen =0;
	if (_strnicmp(sqlstmt,"int:",4) == 0) {
		curptr = sqlstmt + 4;
		val = atoi(curptr);
		lret = pfunc->m_bindintfunc(stmt,index,val);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s].[%d] index [%d] error %d %d", sqlstmt,val,index,lret,ret);
			goto fail;
		}
	} else if (_strnicmp(sqlstmt,"int64:",6) == 0) {
		curptr = sqlstmt + 6;
		if (_strnicmp(curptr,"0x",2) == 0 ) {
			base = 16;
			curptr += 2;
		}  else if (_strnicmp(curptr,"x",1) == 0) {
			base = 16;
			curptr += 1;
		}

		val64 = (sqlite3_int64)strtoull(curptr,&pendptr,base);
		lret = pfunc->m_bindint64func(stmt,index,val64);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s].[%lld] index[%d] error %d %d", sqlstmt,val64, index,lret,ret);
			goto fail;
		}
	} else if (_strnicmp(sqlstmt,"blob:",5) == 0) {
		curptr = sqlstmt + 5;
		ret = parse_blob(curptr,&pbuf,&retsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("parse [%s] error %d", sqlstmt,ret);
			goto fail;
		}
		retlen = ret;
		lret = pfunc->m_bindblobfunc(stmt,index,pbuf,retlen,SQLITE_TRANSIENT);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s] index[%d] error %d %d", sqlstmt,index,lret,ret);
			goto fail;
		}

	} else if (_strnicmp(sqlstmt,"blob64:",7) == 0) {
		curptr += 7;
		ret = parse_blob(curptr,&pbuf,&retsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("parse [%s] error %d", sqlstmt,ret);
			goto fail;
		}
		retlen = ret;
		lret = pfunc->m_bindblob64func(stmt,index,pbuf,retlen,SQLITE_TRANSIENT);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s] index [%d] error %d %d", sqlstmt,index,lret,ret);
			goto fail;
		}
	} else if (_strnicmp(sqlstmt,"text:",5) == 0) {
		curptr += 5;
		lret = pfunc->m_bindtextfunc(stmt,index,curptr,-1,SQLITE_TRANSIENT);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s] index [%d] error %d %d", sqlstmt,index,lret,ret);
			goto fail;
		}
	} else if (_strnicmp(sqlstmt,"null:",5) == 0) {
		lret = pfunc->m_bindnullfunc(stmt,index);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s] error %d %d", sqlstmt,lret,ret);
			goto fail;
		}
	} else if (_strnicmp(sqlstmt,"double:",7) == 0) {
		curptr += 7;
		dval = strtod(curptr,&pendptr);
		lret = pfunc->m_binddoublefunc(stmt,index,dval);
		if (lret != SQLITE_OK) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s] index[%d] error %d %d", sqlstmt,index,lret,ret);
			goto fail;
		}
	} else {
		ret = - ERROR_INVALID_PARAMETER;
		ERROR_INFO("not support arg [%s]" , sqlstmt);
		goto fail;
	}

	parse_blob(NULL,&pbuf,&retsize);
	return 0;
fail:
	parse_blob(NULL,&pbuf,&retsize);
	SETERRNO(ret);
	return ret;
}


int sql3prepare_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret,lret;
	psqlite3_func_t pfunc = NULL;
	sqlite3* pdb= NULL;
	char* dbfile = NULL;
	char* sqlstmt=NULL;
	int i,j;
	pargs_options_t pargs = (pargs_options_t) popt;
	sqlite3_stmt* stmt = NULL;
	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
	int ltype;
	int lcount;
	sqlite3_int64 iv64;
	unsigned char* pb=NULL;
	int nbytes;
	char* pt;
	double dv;
	int totalv=0;

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

	lret = pfunc->m_preparefunc(pdb,sqlstmt,-1,0,&stmt,NULL);
	if (lret != SQLITE_OK) {
		GETERRNO(ret);
		ERROR_INFO("prepare_v3 [%s] error %d %d",sqlstmt,lret,ret);
		goto out;
	}

	for(i=2;parsestate->leftargs && parsestate->leftargs[i] ;i ++) {
		sqlstmt = parsestate->leftargs[i];
		ret = prepare_args(pfunc,stmt,i-1,sqlstmt);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
	}

	totalv = 0;
	while(1) {
		lret = pfunc->m_stepfunc(stmt);
		if (lret == SQLITE_DONE) {
			break;
		}
		if (lret != SQLITE_ROW) {
			GETERRNO(ret);
			ERROR_INFO("step error %d %d", lret,ret);
			goto out;
		}

		lcount = pfunc->m_colcountfunc(stmt);
		fprintf(stdout,"[%d]", totalv);
		for (i=0;i<lcount;i++) {
			ltype = pfunc->m_coltypefunc(stmt,i);
			if (ltype == SQLITE_INTEGER) {
				iv64 = pfunc->m_colint64func(stmt,i);
				fprintf(stdout," %lld[0x%llx]",iv64,iv64);
			} else if (ltype == SQLITE_FLOAT) {
				dv = pfunc->m_coldblfunc(stmt,i);
				fprintf(stdout," %f",dv);
			} else if (ltype == SQLITE_TEXT) {
				pt = (char*)pfunc->m_coltextfunc(stmt,i);
				fprintf(stdout, " %s",pt);
			} else if (ltype == SQLITE_BLOB) {
				pb = (unsigned char*)pfunc->m_colblobfunc(stmt,i);
				nbytes = pfunc->m_colbytesfunc(stmt,i);
				fprintf(stdout," ");
				for(j=0;j<nbytes;j+= 1) {
					if (j > 0) {
						fprintf(stdout,",");
					}
					fprintf(stdout,"0x%02x",pb[j]);
				}
			} else if (ltype == SQLITE_NULL) {
				fprintf(stdout," null");
			} else {
				ret = - ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%d].[%d].ltype %d not support",totalv,i, ltype);
				goto out;
			}
		}
		fprintf(stdout,"\n");
		totalv += 1;
	}

	fprintf(stdout,"[%s] [%s]", dbfile,parsestate->leftargs[1]);
	for(i=2;parsestate->leftargs&& parsestate->leftargs[i];i+=1) {
		fprintf(stdout," [%s]", parsestate->leftargs[i]);
	}

	fprintf(stdout," succ\n");

	ret = 0;
out:
	if (stmt != NULL) {
		pfunc->m_finalizefunc(stmt);
	}
	stmt = NULL;

	if (pdb != NULL) {
		pfunc->m_closefunc(pdb);
	}
	pdb = NULL;
	free_sqlite3_func(&pfunc);

	SETERRNO(ret);
	return ret;
}