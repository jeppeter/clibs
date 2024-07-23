
int createreg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* pkeyname = NULL;
	char* psubname = NULL;
	void* preg = NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if(parsestate->leftargs && parsestate->leftargs[0]) {
		pkeyname = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			psubname = parsestate->leftargs[1];
		}
	}

	if (pkeyname == NULL || psubname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "need pkeyname and psubname\n");
		goto out;
	}

	preg = create_reg_key(pkeyname,psubname,ACCESS_KEY_ALL);
	if (preg == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "create [%s].[%s] error [%d]\n", pkeyname,psubname,ret);
		goto out;
	}
	fprintf(stdout, "create [%s].[%s] succ\n", pkeyname,psubname);
	ret = 0;
out:
	close_reg_key(&preg);
	SETERRNO(ret);
	return ret;
}

int setregsz_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* pkeyname = NULL;
	char* psubname = NULL;
	char* kname = NULL;
	char* valstr = NULL;
	void* preg = NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if(parsestate->leftargs && parsestate->leftargs[0]) {
		pkeyname = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			psubname = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				kname = parsestate->leftargs[2];
				if (parsestate->leftargs[3]) {
					valstr = parsestate->leftargs[3];
				}
			}
		}
	}

	if (pkeyname == NULL || psubname == NULL || kname == NULL || valstr == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "need pkeyname and psubname kname valstr\n");
		goto out;
	}

	preg = create_reg_key(pkeyname,psubname,ACCESS_KEY_ALL);
	if (preg == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "create [%s].[%s] error [%d]\n", pkeyname,psubname,ret);
		goto out;
	}
	ret = set_reg_sz(preg,kname,valstr);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "set [%s]=[%s] error[%d]\n", kname,valstr,ret);
		goto out;
	}
	fprintf(stdout, "set [%s].[%s].[%s]=[%s] succ\n", pkeyname,psubname,kname,valstr);

	ret = 0;
out:
	close_reg_key(&preg);
	SETERRNO(ret);
	return ret;

}

int existregkey_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* pkeyname = NULL;
	char* psubname = NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if(parsestate->leftargs && parsestate->leftargs[0]) {
		pkeyname = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			psubname = parsestate->leftargs[1];
		}
	}

	if (pkeyname == NULL || psubname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "need pkeyname and psubname\n");
		goto out;
	}

	ret = exist_reg_key(pkeyname,psubname);
	fprintf(stdout, "[%s].[%s] %s\n", pkeyname,psubname,ret ? "exists" : "not exists");
	ret = 0;
out:
	SETERRNO(ret);
	return ret;	
}