#include <openssl/pkcs7.h>

#define NID_pkcs7_data_ex   21

int pkcs7octstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	PKCS7* p7 = NULL;
	char* str = NULL;
	int slen = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	ASN1_OCTET_STRING* octstr = NULL;
	FILE* fp = NULL;
	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}

	DEBUG_INFO(" ");

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		str = parsestate->leftargs[0];
		slen = (int) strlen(str);
	}

	DEBUG_INFO(" ");


	p7 = PKCS7_new_ex(NULL, NULL);
	if (p7 == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not new PKCS7 error[%d]\n", ret);
		goto out;
	}

	DEBUG_INFO(" ");

	ret = PKCS7_set_type(p7, NID_pkcs7_data_ex);
	if (ret == 0) {
		ret = -EINVAL;
		fprintf(stderr, "can not set NID_pkcs7_data\n");
		goto out;
	}

	DEBUG_INFO(" ");


	octstr = (ASN1_OCTET_STRING*)p7->d.data;
	if (str != NULL) {
		if (octstr == NULL) {
			ret = -EINVAL;
			fprintf(stderr, "data null\n");
			goto out;
		}

		DEBUG_INFO(" ");

		ret = ASN1_STRING_set((ASN1_STRING*) octstr, str, slen);
		if (ret == 0) {
			ret = -EINVAL;
			fprintf(stderr, "set [%s] error\n", str);
			goto out;
		}
	} else {
		if (octstr != NULL) {
			ASN1_OCTET_STRING_free(octstr);
		}
		p7->d.data = NULL;
	}


	DEBUG_INFO(" ");
	if (pargs->m_output != NULL) {
		fp = fopen(pargs->m_output, "wb");
		if (fp == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for write\n", pargs->m_output);
			goto out;
		}
	} else {
		fp = stdout;
	}

	DEBUG_INFO(" ");

	ret = i2d_PKCS7_fp(fp, p7);
	if (ret == 0) {
		ret =  -EINVAL;
		fprintf(stderr, "out [%s] error\n", pargs->m_output != NULL ? pargs->m_output : "stdout");
		goto out;
	}

	ret = 0;
out:
	if (fp != NULL && fp != stdout) {
		fclose(fp);
	}
	fp = NULL;
	PKCS7_free(p7);
	p7 = NULL;
	SETERRNO(ret);
	return ret;

}

int pkcs7dump_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	PKCS7* p7 = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	FILE* fout = NULL, *fin = NULL;

	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}

	if (pargs->m_input != NULL) {
		fin = fopen(pargs->m_input, "rb");
		if (fin == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for read\n", pargs->m_input);
			goto out;
		}
	} else {
		fin = stdin;
	}

	p7 = d2i_PKCS7_fp(fin, NULL);
	if (p7 == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not read PKCS7 from [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}



	DEBUG_INFO(" ");
	if (pargs->m_output != NULL) {
		fout = fopen(pargs->m_output, "wb");
		if (fout == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for write\n", pargs->m_output);
			goto out;
		}
	} else {
		fout = stdout;
	}

	ret = i2d_PKCS7_fp(fout, p7);
	if (ret == 0) {
		ret =  -EINVAL;
		fprintf(stderr, "out [%s] error\n", pargs->m_output != NULL ? pargs->m_output : "stdout");
		goto out;
	}

	ret = 0;
out:
	if (fin != NULL && fin != stdin) {
		fclose(fin);
	}
	fin = NULL;

	if (fout != NULL && fout != stdout) {
		fclose(fout);
	}
	fout = NULL;
	PKCS7_free(p7);
	p7 = NULL;
	SETERRNO(ret);
	return ret;
}

int asn1intenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_INTEGER* ita = NULL;
	long long ival;
	char* pendptr = NULL;
	int i;
	unsigned char* pout = NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_verbose(pargs);

	ita = ASN1_INTEGER_new();
	if (ita == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not use integer error[%d]\n", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pendptr = NULL;
		ival = strtoll(parsestate->leftargs[i], &pendptr, 10);
		ASN1_INTEGER_set_int64(ita, ival);
		outlen = i2d_ASN1_INTEGER(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "i2d error[%d]\n", ret);
			goto out;
		}
		DEBUG_BUFFER_FMT(pout, outlen, "integer format");
		OPENSSL_free(pout);
		pout = NULL;
	}

	ret = 0;
out:
	OPENSSL_free(pout);
	pout = NULL;
	ASN1_INTEGER_free(ita);
	ita = NULL;
	SETERRNO(ret);
	return ret;
}

int asn1octstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_OCTET_STRING* ita = NULL;
	ASN1_NULL* itn = NULL;
	const unsigned char* pstr = NULL;
	int llen = 0;
	int i;
	unsigned char* pout = NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_verbose(pargs);

	ita = ASN1_OCTET_STRING_new();
	if (ita == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not use integer error[%d]\n", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pstr = (const unsigned char*) parsestate->leftargs[i];
		llen = strlen(parsestate->leftargs[i]);
		ret = ASN1_OCTET_STRING_set(ita, pstr, llen);
		if (ret <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not set [%s] error[%d]\n", pstr, ret);
			goto out;
		}
		outlen = i2d_ASN1_OCTET_STRING(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "i2d error[%d]\n", ret);
			goto out;
		}
		DEBUG_BUFFER_FMT(pout, outlen, "integer format");
		OPENSSL_free(pout);
		pout = NULL;
	}

	itn = ASN1_NULL_new();
	if (itn == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not ASN1_NULL_new\n");
		goto out;
	}
	outlen = i2d_ASN1_NULL(itn, &pout);
	if (outlen <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "i2d error[%d]\n", ret);
		goto out;
	}
	DEBUG_BUFFER_FMT(pout, outlen, "null format");
	OPENSSL_free(pout);
	pout = NULL;

	ret = 0;
out:
	OPENSSL_free(pout);
	pout = NULL;
	ASN1_NULL_free(itn);
	ASN1_OCTET_STRING_free(ita);
	ita = NULL;
	SETERRNO(ret);
	return ret;
}


int asn1objenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_OBJECT* ita = NULL;
	const unsigned char* p = NULL;
	unsigned char* objsn = NULL;
	int snsize = 0;
	int snlen = 0;
	int llen = 0;
	int i;
	unsigned char* pout = NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	unsigned char* ccbuf = NULL;
	int ccsize = 0;
	int cclen = 0;

	init_log_verbose(pargs);


	snsize = 4;
	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
get_again:
		if (objsn != NULL) {
			free(objsn);
		}
		objsn = NULL;
		objsn = (unsigned char*)malloc(snsize);
		if (objsn == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not alloc [%d] objsn [%d]\n", snsize, ret);
			goto out;
		}
		memset(objsn, 0, snsize);
		ret = a2d_ASN1_OBJECT(objsn, snsize, parsestate->leftargs[i], -1);
		if (ret <= 0) {
			snsize <<= 1;
			DEBUG_INFO("ret [%d] snsize [%d]", ret, snsize);
			goto get_again;
		}
		snlen = ret;
		DEBUG_BUFFER_FMT(objsn, snlen, "to debug buffer [%s]", parsestate->leftargs[i]);
		cclen = snlen + 2;
		if (snlen < 128) {
			cclen += 0;
		} else if (snlen >= 128 && snlen < 256) {
			cclen += 1;
		} else if (snlen >= 256 && snlen < ((1 << 15) - 1)) {
			cclen += 2;
		} else {
			ret = -EINVAL;
			fprintf(stderr, "overflow snlen [%d]\n", snlen);
			goto out;
		}
		if (ccsize < cclen) {
			ccsize = cclen + 1;
			if (ccbuf != NULL) {
				OPENSSL_free(ccbuf);
			}
			ccbuf = NULL;
			ccbuf = (unsigned char*)OPENSSL_malloc(ccsize);
			if (ccbuf == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "can not alloc [%d]\n", ccsize);
				goto out;
			}
		}
		memset(ccbuf, 0, ccsize);
		llen = 0;
		ccbuf[llen] =  V_ASN1_OBJECT;
		llen ++;
		if (snlen < 128) {
			ccbuf[llen] = snlen;
			llen ++;
		} else if (snlen >= 128 && snlen < 256) {
			ccbuf[llen] = 0x81;
			llen ++;
			ccbuf[llen] = snlen;
			llen ++;
		} else if (snlen >= 256 && snlen < ((1 << 15) - 1)) {
			ccbuf[llen] = 0x82;
			llen ++;
			ccbuf[llen] = (snlen >> 8)  & 0xff;
			llen ++;
			ccbuf[llen] = (snlen & 0xff);
			llen ++;
		} else {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&(ccbuf[llen]), objsn, snlen);
		llen += snlen;

		p = (const unsigned char*) ccbuf;
		ita = d2i_ASN1_OBJECT(NULL, &p, llen);
		if (ita == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not parse buffer [%d]\n", ret);
			goto out;
		}

		outlen = i2d_ASN1_OBJECT(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "i2d error[%d]\n", ret);
			goto out;
		}

		DEBUG_BUFFER_FMT(pout, outlen, "object format");
		OPENSSL_free(pout);
		pout = NULL;
		ASN1_OBJECT_free(ita);
		ita = NULL;
	}


	ret = 0;
out:
	OPENSSL_free(pout);
	pout = NULL;
	ASN1_OBJECT_free(ita);
	ita = NULL;
	if (objsn != NULL) {
		free(objsn);
	}
	objsn = NULL;
	OPENSSL_free(ccbuf);
	ccbuf = NULL;
	ccsize = 0;
	cclen = 0;

	SETERRNO(ret);
	return ret;
}

int asn1enumerateenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_ENUMERATED* ita = NULL;
	long long ival;
	char* pendptr = NULL;
	int i;
	unsigned char* pout = NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_verbose(pargs);

	ita = ASN1_ENUMERATED_new();
	if (ita == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not use enumerated error[%d]\n", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pendptr = NULL;
		ival = strtoll(parsestate->leftargs[i], &pendptr, 10);
		ASN1_ENUMERATED_set_int64(ita, ival);
		outlen = i2d_ASN1_ENUMERATED(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "i2d error[%d]\n", ret);
			goto out;
		}
		DEBUG_BUFFER_FMT(pout, outlen, "integer format");
		OPENSSL_free(pout);
		pout = NULL;
	}

	ret = 0;
out:
	OPENSSL_free(pout);
	pout = NULL;
	ASN1_ENUMERATED_free(ita);
	ita = NULL;
	SETERRNO(ret);
	return ret;
}