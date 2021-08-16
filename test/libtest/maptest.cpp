

int creatememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* mapname=NULL;
	int cnt = 0;
	int idx;
	pargs_options_t pargs = (pargs_options_t) popt;
	void* pmap=NULL;
	HANDLE exithd=NULL;
	uint64_t mapsize=0;
	int ret;
	DWORD dret;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

	init_log_level(pargs);
	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	cnt = 0;
	for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx++) {
		cnt ++;
	}
	if (cnt < 2) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr,"need mapname size\n");
		goto out;
	}

	mapname = parsestate->leftargs[0];
	idx = 1;
	GET_OPT_NUM64(mapsize,"mapsize");

	ret = map_buffer(mapname,WINLIB_MAP_FILE_WRITE|WINLIB_MAP_FILE_READ|WINLIB_MAP_FILE_EXEC|WINLIB_MAP_CREATE,mapsize,&pmap);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("map [%s] error[%d]", mapname);
		goto out;
	}

	fprintf(stdout,"create [%s] with [0x%llx] succ\n",mapname,mapsize);

	while(1) {
		dret = WaitForSingleObject(exithd,5000);
		if (dret == WAIT_OBJECT_0) {
			break;
		}
	}

	ret = 0;
out:
	unmap_buffer(&pmap);
	close_ctrlc_handle();
	exithd = NULL;
	SETERRNO(ret);
	return ret;
}


int readmemmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* mapname=NULL;
	int cnt = 0;
	int idx;
	pargs_options_t pargs = (pargs_options_t) popt;
	void* pmap=NULL;
	HANDLE exithd=NULL;
	uint64_t mapsize=0;
	int ret;
	uint64_t readoffset=0;
	int readsize=0;
	char* pbuffer=NULL;
	int readlen =0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

	init_log_level(pargs);
	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	cnt = 0;
	for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx++) {
		cnt ++;
	}
	if (cnt < 4) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr,"need mapname size readoffset readsize\n");
		goto out;
	}

	mapname = parsestate->leftargs[0];
	idx = 1;
	GET_OPT_NUM64(mapsize,"mapsize");
	GET_OPT_NUM64(readoffset,"readoffset");
	GET_OPT_INT(readsize,"readsize");

	ret = map_buffer(mapname,WINLIB_MAP_FILE_READ|WINLIB_MAP_FILE_EXEC,mapsize,&pmap);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("map [%s] error[%d]", mapname);
		goto out;
	}

	pbuffer = (char*)malloc((size_t)readsize);
	if (pbuffer == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = read_buffer(pmap,readoffset,pbuffer,readsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}
	readlen = ret;

	DEBUG_BUFFER_FMT(pbuffer,readlen,"read [%s] at [0x%llx] size[%d] ret [%d]", mapname,readoffset,readsize,readlen);
	ret = 0;
out:
	if (pbuffer) {
		free(pbuffer);
	}
	pbuffer = NULL;
	unmap_buffer(&pmap);
	close_ctrlc_handle();
	exithd = NULL;
	SETERRNO(ret);
	return ret;
}

int writememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* mapname=NULL;
	int cnt = 0;
	int idx;
	pargs_options_t pargs = (pargs_options_t) popt;
	void* pmap=NULL;
	HANDLE exithd=NULL;
	uint64_t mapsize=0;
	int ret;
	uint64_t writeoffset=0;
	int writesize=0;
	char* pwbuf=NULL;
	int writelen =0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

	init_log_level(pargs);
	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	cnt = 0;
	for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx++) {
		cnt ++;
	}
	if (cnt < 4) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr,"need mapname size writeoffset writestr\n");
		goto out;
	}

	mapname = parsestate->leftargs[0];
	idx = 1;
	GET_OPT_NUM64(mapsize,"mapsize");
	GET_OPT_NUM64(writeoffset,"writeoffset");
	pwbuf = parsestate->leftargs[3];

	ret = map_buffer(mapname,WINLIB_MAP_FILE_WRITE|WINLIB_MAP_FILE_EXEC|WINLIB_MAP_FILE_READ,mapsize,&pmap);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("map [%s] error[%d]", mapname);
		goto out;
	}
	writesize = (int)strlen(pwbuf) + 1;

	ret = write_buffer(pmap,writeoffset,pwbuf,writesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}
	writelen = ret;

	DEBUG_BUFFER_FMT(pwbuf,writelen,"write [%s] at [0x%llx] size[%d] ret [%d]", mapname,writeoffset,writesize,writelen);
	ret = 0;
out:
	unmap_buffer(&pmap);
	close_ctrlc_handle();
	exithd = NULL;
	SETERRNO(ret);
	return ret;
}
