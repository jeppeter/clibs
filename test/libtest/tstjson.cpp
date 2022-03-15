
int jsonlist_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	char* key = NULL;
	char* jsonfile = NULL;
	char* jsonstr = NULL;
	int jsonsize = 0, jsonlen = 0;
	unsigned int jsonparsed = 0;
	char* fmtstr = NULL;
	unsigned int fmtlen = 0;
	int argcnt = 0;
	int i;
	jvalue* pj = NULL, *valpj = NULL;
	jarray* curarr = NULL;
	int error;
	double valf;
	long long int valii;
	const char* vals=NULL;
	int vali;
	jobject* curobj=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);

	for (argcnt = 0; parsestate->leftargs && parsestate->leftargs[argcnt] != NULL; argcnt ++) {

	}

	if (argcnt < 1) {
		fprintf(stderr, "must list at one jsonfile\n");
		ret = -ERROR_INVALID_PARAMETER;
		goto out;
	}

	jsonfile = parsestate->leftargs[0];
	ret = read_file_whole(jsonfile, &jsonstr, &jsonsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not read [%s] error[%d]\n", jsonfile, ret);
		goto out;
	}

	jsonlen = ret;

	pj = jvalue_read(jsonstr, &jsonparsed);
	if (pj == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not parse error[%d]\n%s\n", ret, jsonstr);
		goto out;
	}

	if (argcnt > 1) {
		for (i = 1; i < argcnt; i++) {
			if (fmtstr != NULL) {
				free(fmtstr);
			}
			fmtstr = NULL;
			fmtlen = 0;
			key = parsestate->leftargs[i];
			valpj = jobject_get(pj, key);
			if (valpj != NULL) {
				ASSERT_IF(fmtstr == NULL);
				fmtstr = jvalue_write(valpj, &fmtlen);
				if (fmtstr == NULL) {
					GETERRNO(ret);
					fprintf(stderr, "can not format [%s] error[%d]\n", key, ret);
					goto out;
				}
				fprintf(stdout, "[%s] -> [%s]\n%s", jsonfile, key, fmtstr);
			} else {
				curarr = jobject_get_array(pj, key,&error);
				if (error == 0) {
					ASSERT_IF(fmtstr == NULL);
					fmtstr = jvalue_write((jvalue*)curarr, &fmtlen);
					if (fmtstr == NULL) {
						GETERRNO(ret);
						fprintf(stderr, "can not format [%s] error[%d]\n", key, ret);
						goto out;
					}
					fprintf(stdout, "[%s] -> [%s]\n%s", jsonfile, key, fmtstr);
				} else {
					vali = jobject_get_int(pj,key,&error);
					if (error == 0) {
						fprintf(stdout,"[%s] -> [%s] : %d\n", jsonfile, key, vali);
					} else {
						valf = jobject_get_real(pj,key,&error);
						if (error == 0) {
							fprintf(stdout,"[%s] -> [%s] : %f\n", jsonfile, key, valf);
						} else {
							vals = jobject_get_string(pj,key,&error);
							if (error == 0) {
								fprintf(stdout,"[%s] -> [%s] : %s\n", jsonfile, key, vals);
							} else {
								vali = jobject_get_bool(pj,key,&error);
								if (error == 0 ) {
									fprintf(stdout,"[%s] -> [%s] : %s\n", jsonfile, key, vali == 0 ? "false" : "true");
								} else {
									vali = jobject_get_null(pj,key,&error);
									if (error == 0) {
										fprintf(stdout,"[%s] -> [%s] : null\n",jsonfile,key);
									} else {
										valii = jobject_get_int64(pj,key,&error);
										if (error == 0) {
											fprintf(stdout,"[%s] -> [%s] : %lld\n",jsonfile,key,valii);
										} else {
											curobj = jobject_get_object(pj,key,&error);
											if (error == 0) {
												fprintf(stdout,"[%s] -> [%s] : object [%d]\n",jsonfile,key,curobj->type);
											} else {
												ret = -ERROR_INVALID_PARAMETER;
												fprintf(stderr,"cannot get [%s] [%s]\n", jsonfile,key);
												goto out;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		fprintf(stdout, "%s\n", jsonstr);
	}







out:
	if (fmtstr) {
		free(fmtstr);
	}
	fmtstr = NULL;
	if (pj) {
		jvalue_destroy(pj);
	}
	pj = NULL;
	SETERRNO(ret);
	return ret;
}

int getmsepoch_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	uint64_t lret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);
	REFERENCE_ARG(popt);

	lret = get_ms_from_epock();
	fprintf(stdout,"epoch ms %lld\n",lret);
	ret = 0;
	SETERRNO(ret);
	return ret;
}