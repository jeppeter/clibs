
#define TTY_SPEED_NOTE(fp,pdcb)                                                                   \
do{                                                                                               \
	int _sval = (int)pdcb->BaudRate;                                                              \
	switch(pdcb->BaudRate) {                                                                      \
		case CBR_110:                                                                             \
			_sval=110;                                                                            \
			break;                                                                                \
		case CBR_300:                                                                             \
			_sval=300;                                                                            \
			break;                                                                                \
		case CBR_600:                                                                             \
			_sval=600;                                                                            \
			break;                                                                                \
		case CBR_1200:                                                                            \
			_sval=1200;                                                                           \
			break;                                                                                \
		case CBR_2400:                                                                            \
			_sval=2400;                                                                           \
			break;                                                                                \
		case CBR_4800:                                                                            \
			_sval=4800;                                                                           \
			break;                                                                                \
		case CBR_9600:                                                                            \
			_sval=9600;                                                                           \
			break;                                                                                \
		case CBR_14400:                                                                           \
			_sval=14400;                                                                          \
			break;                                                                                \
		case CBR_19200:                                                                           \
			_sval=19200;                                                                          \
			break;                                                                                \
		case CBR_38400:                                                                           \
			_sval=38400;                                                                          \
			break;			                                                                      \
		case CBR_57600:                                                                           \
			_sval=57600;                                                                          \
			break;			                                                                      \
		case CBR_115200:                                                                          \
			_sval=115200;                                                                         \
			break;			                                                                      \
		case CBR_128000:                                                                          \
			_sval=128000;                                                                         \
			break;			                                                                      \
		case CBR_256000:                                                                          \
			_sval=256000;                                                                         \
			break;                                                                                \
	}                                                                                             \
	fprintf(fp,"speed [0x%lx] [%d]\n",(pdcb)->BaudRate, _sval);                                   \
}while(0)

#define TTY_VALUE_BOOL(fp,pdcb,member,desc)                                                       \
do{                                                                                               \
	if ((pdcb)->member) {                                                                         \
		fprintf(fp,"%s",desc);                                                                    \
	} else {                                                                                      \
		fprintf(fp,"-%s",desc);                                                                   \
	}                                                                                             \
}while(0)

#define TTY_SPACE(fp)                                                                             \
do{                                                                                               \
	fprintf(fp," ");                                                                              \
}while(0)

#define TTY_LINE(fp) do{fprintf(fp,"\n");}while(0)
#define TTY_ALIGN(fp) do{fprintf(fp,"        ");}while(0)

#define TTY_DTRCONTROL(fp,pdcb)                                                                   \
do{                                                                                               \
	switch((pdcb)->fDtrControl) {                                                                 \
		case DTR_CONTROL_DISABLE:                                                                 \
			fprintf(fp, "dtr disable");                                                           \
			break;                                                                                \
		case DTR_CONTROL_ENABLE:                                                                  \
			fprintf(fp, "dtr enable");                                                            \
			break;                                                                                \
		case DTR_CONTROL_HANDSHAKE:                                                               \
			fprintf(fp,"dtr handshake");                                                          \
			break;                                                                                \
		default:                                                                                  \
			fprintf(fp,"dtr[%ld]",(pdcb)->fDtrControl);                                           \
			break;                                                                                \
	}                                                                                             \
}while(0)

#define TTY_RTSCONTROL(fp,pdcb)                                                                   \
do{                                                                                               \
	switch((pdcb)->fRtsControl) {                                                                 \
		case RTS_CONTROL_DISABLE:                                                                 \
			fprintf(fp, "rts disable");                                                           \
			break;                                                                                \
		case RTS_CONTROL_ENABLE:                                                                  \
			fprintf(fp, "rts enable");                                                            \
			break;                                                                                \
		case RTS_CONTROL_HANDSHAKE:                                                               \
			fprintf(fp,"rts handshake");                                                          \
			break;                                                                                \
		case RTS_CONTROL_TOGGLE:                                                                  \
			fprintf(fp,"rts toggle");                                                             \
			break;                                                                                \
	}                                                                                             \
}while(0)

int sercfgget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	void* pserial=NULL;
	char* devname = NULL;
	int ret;
	DCB* pdcbbuf=NULL;
	int dcbsize=0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		devname = parsestate->leftargs[0];
	}
	if (devname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("need serial device name");
		goto out;
	}

	pserial = open_serial(devname);
	if (pserial == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not open_serial[%s] error[%d]", devname, ret);
		goto out;
	}

	ret = get_serial_config_direct(pserial,(void**)&pdcbbuf,&dcbsize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get serial [%s] config error[%d]", devname,ret);
		goto out;
	}

	fprintf(stdout,"[%s] config\n",devname);
	TTY_ALIGN(stdout);
	TTY_SPEED_NOTE(stdout,pdcbbuf);
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fBinary,"fbinary");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fParity,"fparity");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fOutxCtsFlow,"foutxctsflow");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fOutxDsrFlow,"foutxdsrflow");
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_DTRCONTROL(stdout,pdcbbuf);
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fDsrSensitivity,"drtsensitivity");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fTXContinueOnXoff,"txcontinueonxoff");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fOutX ,"foutx");
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fInX,"finx");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fErrorChar,"ferrorchar");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout,pdcbbuf,fNull,"fnull");
	TTY_SPACE(stdout);
	TTY_RTSCONTROL(stdout,pdcbbuf);
	TTY_LINE(stdout);



	ret = 0;
out:
	get_serial_config_direct(NULL,(void**)&pdcbbuf,&dcbsize);	
	close_serial(&pserial);
	SETERRNO(ret);
	return ret;
}


int sercfgset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(popt);
	REFERENCE_ARG(parsestate);
	return 0;
}