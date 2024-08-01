int timetofrom_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	struct tm settm;
	char* str;
	char* nstr=NULL;
	int nsize=0;
	time_t nowt;
	int ret;
	int i;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	nowt = time(NULL);
	ret = time_to_tm(&nowt,&settm);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "time_to_tm error\n");
		goto out;
	}
	ret = tm_to_str(&settm,&nstr,&nsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "nowt to str error\n");
		goto out;
	}
	fprintf(stdout,"nowt [%s]\n",nstr);


	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		str = parsestate->leftargs[i];
		ret = tm_from_str(str,&settm);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "%s not valid\n", str);
			goto out;
		}

		ret = tm_to_time(&settm,&nowt);
		if (ret <0) {
			GETERRNO(ret);
			fprintf(stderr, "tm_to_time error\n");
			goto out;
		}

		ret = time_to_tm(&nowt,&settm);
		if (ret <0) {
			GETERRNO(ret);
			fprintf(stderr, "time_to_tm error\n");
			goto out;
		}

		ret = tm_to_str(&settm,&nstr,&nsize);
		if (ret <0) {
			GETERRNO(ret);
			fprintf(stderr, "%s not to\n", str);
			goto out;
		}
		fprintf(stdout,"str [%s] => nstr [%s]\n",str,nstr);
		tm_to_str(NULL,&nstr,&nsize);
	}

	ret = 0;
out:
	tm_to_str(NULL,&nstr,&nsize);
	SETERRNO(ret);
	return ret;
}