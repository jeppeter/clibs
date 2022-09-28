
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
	fprintf(fp,"speed [0x%lx] [%d]",(pdcb)->BaudRate, _sval);                                   \
}while(0)

#define TTY_VALUE_BOOL(fp,pdcb,member,desc)                                                       \
do{                                                                                               \
	if ((pdcb)->member) {                                                                         \
		fprintf(fp,"%s",desc);                                                                    \
	} else {                                                                                      \
		fprintf(fp,"-%s",desc);                                                                   \
	}                                                                                             \
}while(0)

#define TTY_VALUE_WORD(fp,pdcb,member,desc)                                                       \
do{                                                                                               \
	fprintf(fp,"%s[0x%x:%d]",desc,(pdcb)->member,(pdcb)->member);                                 \
}while(0)


#define TTY_VALUE_BYTE(fp,pdcb,member,desc)                                                       \
do{                                                                                               \
	fprintf(fp,"%s[0x%x:%d]",desc,(pdcb)->member,(pdcb)->member);                                 \
}while(0)


#define TTY_VALUE_CHAR(fp,pdcb,member,desc)                                                       \
do{                                                                                               \
	fprintf(fp,"%s[0x%x:%d]",desc,(pdcb)->member,(pdcb)->member);                                 \
}while(0)


#define TTY_SPACE(fp)                                                                             \
do{                                                                                               \
	fprintf(fp,"|");                                                                              \
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

#define TTY_PARITY_VALUE(fp,pdcb)                                                                 \
do{                                                                                               \
	switch((pdcb)->Parity) {                                                                      \
		case EVENPARITY:                                                                          \
			fprintf(fp,"parity even");                                                            \
			break;                                                                                \
		case ODDPARITY:                                                                           \
			fprintf(fp,"parity odd");                                                             \
			break;                                                                                \
		case NOPARITY:                                                                            \
			fprintf(fp,"parity no");                                                              \
			break;                                                                                \
		case MARKPARITY:                                                                          \
			fprintf(fp,"parity mark");                                                            \
			break;                                                                                \
		case SPACEPARITY:                                                                         \
			fprintf(fp,"parity space");                                                           \
			break;                                                                                \
		default:                                                                                  \
			fprintf(fp,"parity [%d]", (pdcb)->Parity);                                            \
			break;                                                                                \
	}                                                                                             \
}while(0)

int sercfgget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	void* pserial = NULL;
	char* devname = NULL;
	int ret;
	DCB* pdcbbuf = NULL;
	int dcbsize = 0;

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

	ret = get_serial_config_direct(pserial, (void**)&pdcbbuf, &dcbsize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get serial [%s] config error[%d]", devname, ret);
		goto out;
	}

	fprintf(stdout, "[%s] config\n", devname);
	TTY_ALIGN(stdout);
	TTY_SPEED_NOTE(stdout, pdcbbuf);
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fBinary, "binary");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fParity, "fparity");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fOutxCtsFlow, "outxctsflow");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fOutxDsrFlow, "outxdsrflow");
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_DTRCONTROL(stdout, pdcbbuf);
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fDsrSensitivity, "dsrsensitivity");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fTXContinueOnXoff, "txcontinueonxoff");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fOutX , "outx");
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fInX, "inx");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fErrorChar, "ferrorchar");
	TTY_SPACE(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fNull, "null");
	TTY_SPACE(stdout);
	TTY_RTSCONTROL(stdout, pdcbbuf);
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_BOOL(stdout, pdcbbuf, fAbortOnError, "abortonerror");
	TTY_SPACE(stdout);
	fprintf(stdout, "dummy2[%ld]", pdcbbuf->fDummy2);
	TTY_SPACE(stdout);
	TTY_VALUE_WORD(stdout, pdcbbuf, wReserved, "reserved");
	TTY_SPACE(stdout);
	TTY_VALUE_WORD(stdout, pdcbbuf, XonLim, "xonlim");
	TTY_LINE(stdout);


	TTY_ALIGN(stdout);
	TTY_VALUE_WORD(stdout, pdcbbuf, XoffLim, "xofflim");
	TTY_SPACE(stdout);
	TTY_VALUE_BYTE(stdout, pdcbbuf, ByteSize, "bytesize");
	TTY_SPACE(stdout);
	TTY_PARITY_VALUE(stdout, pdcbbuf);
	TTY_SPACE(stdout);
	TTY_VALUE_BYTE(stdout, pdcbbuf, StopBits, "stopbits");
	TTY_LINE(stdout);


	TTY_ALIGN(stdout);
	TTY_VALUE_CHAR(stdout, pdcbbuf, XonChar, "xonchar");
	TTY_SPACE(stdout);
	TTY_VALUE_CHAR(stdout, pdcbbuf, XoffChar, "xoffchar");
	TTY_SPACE(stdout);
	TTY_VALUE_CHAR(stdout, pdcbbuf, ErrorChar, "errorchar");
	TTY_SPACE(stdout);
	TTY_VALUE_CHAR(stdout, pdcbbuf, EofChar, "eofchar");
	TTY_LINE(stdout);

	TTY_ALIGN(stdout);
	TTY_VALUE_CHAR(stdout, pdcbbuf, EvtChar, "evtchar");
	TTY_SPACE(stdout);
	TTY_VALUE_WORD(stdout, pdcbbuf, wReserved1, "reserv1");
	TTY_LINE(stdout);

	ret = 0;
out:
	get_serial_config_direct(NULL, (void**)&pdcbbuf, &dcbsize);
	close_serial(&pserial);
	SETERRNO(ret);
	return ret;
}


int sercfgset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	void* pserial = NULL;
	char* devname = NULL;
	int ret;
	int idx;
	char* keyname = NULL;
	int ival;
	int iflag ;
	char* valname = NULL;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		devname = parsestate->leftargs[0];
	}

	if (devname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("need devname for sercfgset");
		goto out;
	}

	pserial = open_serial(devname);
	if (pserial == NULL) {
		GETERRNO(ret);
		ERROR_INFO("open [%s] error[%d]", devname, ret);
		goto out;
	}

	idx = 1;
	while (parsestate->leftargs && parsestate->leftargs[idx]) {
		keyname = parsestate->leftargs[idx];
		idx += 1;
		if (strcmp(keyname, "speed") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_SET_SPEED;
			idx += 1;
		} else if (strcmp(keyname, "binary") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_FBINARY_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "fparity") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_FPARITY_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "outxctsflow") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_OUTCTXFLOW_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "outxdsrflow") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_OUTDSRFLOW_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "dtr") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			valname = parsestate->leftargs[idx];
			idx += 1;
			if (strcmp(valname, "enable") == 0) {
				ival = DTR_CONTROL_ENABLE;
			} else if (strcmp(valname, "disable") == 0) {
				ival = DTR_CONTROL_DISABLE;
			} else if (strcmp(valname, "handshake") == 0) {
				ival = DTR_CONTROL_HANDSHAKE;
			} else {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] not valid for [%s]", valname, keyname);
				goto out;
			}
			iflag = SERIAL_DTRCTRL_VALUE;
		} else if (strcmp(keyname, "dsrsensitivity") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_DSRSENSITY_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "txcontinueonxoff") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_TXCONONXOFF_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "outx") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_OUTX_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "inx") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_INX_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "ferrorchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_FERRORCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "null") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_NULL_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "rts") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			valname = parsestate->leftargs[idx];
			idx += 1;
			if (strcmp(valname, "enable") == 0) {
				ival = RTS_CONTROL_ENABLE;
			} else if (strcmp(valname, "disable") == 0) {
				ival = RTS_CONTROL_DISABLE;
			} else if (strcmp(valname, "handshake") == 0) {
				ival = RTS_CONTROL_HANDSHAKE;
			} else if (strcmp(valname, "toggle") == 0) {
				ival = RTS_CONTROL_TOGGLE;
			} else {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] not valid for [%s]", valname, keyname);
				goto out;
			}
			iflag = SERIAL_RTSCTRL_VALUE;
		} else if (strcmp(keyname, "abortonerror") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_ABORTONERROR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "dummy2") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_DUMMY2_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "reserved") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_RESERVED_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "xonlim") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_XONLIMIT_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "xofflim") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_XOFFLIMIT_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "bytesize") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_BYTESIZE_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "parity") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			valname = parsestate->leftargs[idx];
			idx += 1;
			if (strcmp(valname, "no") == 0) {
				ival = NOPARITY;
			} else if (strcmp(valname, "even") == 0) {
				ival = EVENPARITY;
			} else if (strcmp(valname, "mark") == 0) {
				ival = MARKPARITY;
			} else if (strcmp(valname, "odd") == 0) {
				ival = ODDPARITY;
			} else if (strcmp(valname, "space") == 0) {
				ival = SPACEPARITY;
			} else {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] not valid for [%s]", valname, keyname);
				goto out;
			}
			iflag = SERIAL_PARITY_VALUE;
		} else if (strcmp(keyname, "stopbits") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			valname = parsestate->leftargs[idx];
			idx += 1;
			if (strcmp(valname, "1") == 0) {
				ival = ONESTOPBIT;
			} else if (strcmp(valname, "1.5") == 0) {
				ival = ONE5STOPBITS;
			} else if (strcmp(valname, "2") == 0) {
				ival = TWOSTOPBITS;
			} else {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] not valid for [%s]", valname, keyname);
				goto out;
			}
			iflag = SERIAL_STOPBITS_VALUE;
		} else if (strcmp(keyname, "xonchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_XONCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "xoffchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_XOFFCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "errorchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_ERRORCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "eofchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_EOFCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "evtchar") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_EVTCHAR_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "reserv1") == 0) {
			if (parsestate->leftargs[idx] == NULL) {
				ret = -ERROR_INVALID_PARAMETER;
				ERROR_INFO("[%s] need an arg", keyname);
				goto out;
			}
			ival = atoi(parsestate->leftargs[idx]);
			iflag = SERIAL_RESERVED1_VALUE;
			idx += 1;
		} else if (strcmp(keyname, "raw") == 0) {
			ival = 0;
			iflag = SERIAL_SET_RAW;
		} else {
			ret = -ERROR_INVALID_PARAMETER;
			ERROR_INFO("[%s] not supported", keyname);
			goto out;
		}

		ret = prepare_config_serial(pserial, iflag, (void*)&ival);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("set [%s] error[%d]", keyname, ret);
			goto out;
		}
	}

	ret = commit_config_serial(pserial);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("config [%s] error[%d]", devname, ret);
		goto out;
	}

	fprintf(stdout, "config %s succ\n", devname);
	ret = 0;
out:
	close_serial(&pserial);
	SETERRNO(ret);
	return ret;
}

int serread_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	void* pserial = NULL;
	char* devname = NULL;
	int ret;
	char* pbuf = NULL;
	int bufsize = 100;
	int timemills = 1000;
	uint64_t smills = 0, cmills;
	HANDLE waithds[2];
	DWORD waitnum = 0;
	int wtime;
	DWORD dret;


	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		devname = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			bufsize = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				timemills = atoi(parsestate->leftargs[2]);
			}
		}
	}

	if (devname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("need devname for sercfgset");
		goto out;
	}


	pbuf = (char*)malloc((size_t)bufsize);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}

	memset(pbuf, 0, (size_t)bufsize);
	pserial = open_serial(devname);
	if (pserial == NULL) {
		GETERRNO(ret);
		ERROR_INFO("open [%s] error[%d]", devname, ret);
		goto out;
	}

	ret = read_serial(pserial, pbuf, bufsize);
	if (ret > 0) {
		goto succ;
	}

	smills = get_current_ticks();
	while (1) {
		waitnum = 0;
		waithds[waitnum] = get_serial_read_handle(pserial);
		if (waithds[waitnum] != NULL) {
			waitnum ++;
		}
		cmills = get_current_ticks();
		ret = need_wait_times(smills, cmills, timemills);
		if (ret < 0) {
			ret = -ETIMEDOUT;
			ERROR_INFO("read [%s] timedout", devname);
			goto out;
		}
		wtime = ret;

		dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)wtime, FALSE);
		if (dret == WAIT_OBJECT_0) {
			ret = complete_serial_read(pserial);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("complete [%s] error[%d]", devname, ret);
				goto out;
			} else if (ret > 0) {
				goto succ;
			}
		} else {
			GETERRNO(ret);
			ERROR_INFO("wait error [%ld] [%d]", dret, ret);
			goto out;
		}
	}

succ:
	debug_buffer(stdout, pbuf, bufsize, "read [%s] size[%d]", devname, bufsize);
	DEBUG_BUFFER_FMT(pbuf,bufsize,"read [%s] size[%d]", devname, bufsize);
	ret = 0;
out:
	close_serial(&pserial);
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	bufsize = 0;
	SETERRNO(ret);
	return ret;
}

int serwrite_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	void* pserial = NULL;
	char* devname = NULL;
	char* infile = NULL;
	int ret;
	char* pbuf = NULL;
	int bufsize = 0;
	int buflen = 0;
	int timemills = 1000;
	uint64_t smills = 0, cmills;
	HANDLE waithds[2];
	DWORD waitnum = 0;
	int wtime;
	DWORD dret;
	int wbuflen = -1;
	int wlen = 0;
	int curlen;


	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		devname = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			infile = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				timemills = atoi(parsestate->leftargs[2]);
				if (parsestate->leftargs[3]) {
					wbuflen = atoi(parsestate->leftargs[3]);
				}
			}
		}
	}

	if (devname == NULL || infile == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("need devname and infile for serwrite");
		goto out;
	}

	ret = read_file_whole(infile, &pbuf, &bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("read [%s] error[%d]", infile, ret);
		goto out;
	}
	buflen = ret;
	if (wbuflen < 0) {
		wbuflen = buflen;
	}


	pserial = open_serial(devname);
	if (pserial == NULL) {
		GETERRNO(ret);
		ERROR_INFO("open [%s] error[%d]", devname, ret);
		goto out;
	}

	smills = get_current_ticks();
	while (wlen < buflen) {
		curlen = wbuflen;
		if (curlen > (buflen - wlen)) {
			curlen = buflen - wlen;
		}
		ret = write_serial(pserial, &(pbuf[wlen]), curlen);
		if (ret > 0) {
			wlen += curlen;
			continue;
		} else if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("write [%s] [0x%x:%d] error[%d]", devname, wlen, wlen, ret);
			goto out;
		}
		while (1) {
			waitnum = 0;
			waithds[waitnum] = get_serial_write_handle(pserial);
			if (waithds[waitnum] != NULL) {
				waitnum ++;
			}
			cmills = get_current_ticks();
			ret = need_wait_times(smills, cmills, timemills);
			if (ret < 0) {
				ret = -ETIMEDOUT;
				ERROR_INFO("read [%s] timedout", devname);
				goto out;
			}
			wtime = ret;

			dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)wtime, FALSE);
			if (dret == WAIT_OBJECT_0) {
				ret = complete_serial_write(pserial);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("complete [%s] error[%d]", devname, ret);
					goto out;
				} else if (ret > 0) {
					break;
				}
			} else {
				GETERRNO(ret);
				ERROR_INFO("wait error [%ld] [%d]", dret, ret);
				goto out;
			}
		}
		wlen += curlen;
	}

	fprintf(stdout, "write [%s] => [%s] succ\n", infile, devname);
	ret = 0;
out:
	close_serial(&pserial);
	read_file_whole(NULL, &pbuf, &bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}