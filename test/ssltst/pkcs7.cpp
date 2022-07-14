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

int asn1strenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_STRING* ita = NULL;
	int i;
	unsigned char* pout = NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_verbose(pargs);

	ita = ASN1_STRING_new();
	if (ita == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not use string error[%d]\n", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		ret = ASN1_STRING_set(ita, parsestate->leftargs[i], -1);
		if (ret <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "set [%s] error[%d]\n", parsestate->leftargs[i], ret);
			goto out;
		}
		outlen = i2d_ASN1_UTF8STRING(ita, &pout);
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
	ASN1_STRING_free(ita);
	ita = NULL;
	SETERRNO(ret);
	return ret;
}




typedef struct {
	ASN1_INTEGER *simpint;
	ASN1_UTF8STRING *simpstr;
	ASN1_OBJECT *simpobj;
	int32_t embint;
	ASN1_UTF8STRING *optstr;
	ASN1_OBJECT *optobj;
	ASN1_INTEGER* optint;
	int32_t optembint;
	ASN1_UTF8STRING* impstr;
	ASN1_OBJECT* impobj;
	ASN1_INTEGER* impint;
	int32_t impembint;
	ASN1_UTF8STRING* impoptstr;
	ASN1_OBJECT* impoptobj;
	ASN1_INTEGER* impoptint;
	ASN1_UTF8STRING* expstr;
	ASN1_OBJECT* expobj;
	ASN1_INTEGER* expint;
	int32_t expembint;
	ASN1_UTF8STRING* expoptstr;
	ASN1_OBJECT* expoptobj;
	ASN1_INTEGER* expoptint;
	int32_t expoptembint;
	ASN1_UTF8STRING* seqstr;
	ASN1_OBJECT* seqobj;
	ASN1_INTEGER* seqint;
	ASN1_UTF8STRING* seqoptstr;
	ASN1_OBJECT* seqoptobj;
	ASN1_INTEGER* seqoptint;
	STACK_OF(ASN1_UTF8STRING)* setstr;
	STACK_OF(ASN1_OBJECT)* setobj;
	STACK_OF(ASN1_INTEGER)* setint;
	STACK_OF(ASN1_UTF8STRING)* setoptstr;
	STACK_OF(ASN1_OBJECT)* setoptobj;
	STACK_OF(ASN1_INTEGER)* setoptint;
	STACK_OF(ASN1_UTF8STRING)* impsetstr;
	STACK_OF(ASN1_OBJECT)* impsetobj;
	STACK_OF(ASN1_INTEGER)* impsetint;
	STACK_OF(ASN1_UTF8STRING)* expsetstr;
	STACK_OF(ASN1_OBJECT)* expsetobj;
	STACK_OF(ASN1_INTEGER)* expsetint;
	STACK_OF(ASN1_UTF8STRING)* impsetoptstr;
	STACK_OF(ASN1_OBJECT)* impsetoptobj;
	STACK_OF(ASN1_INTEGER)* impsetoptint;
	STACK_OF(ASN1_UTF8STRING)* expsetoptstr;
	STACK_OF(ASN1_OBJECT)* expsetoptobj;
	STACK_OF(ASN1_INTEGER)* expsetoptint;
	STACK_OF(ASN1_UTF8STRING)* impseqstr;
	STACK_OF(ASN1_OBJECT)* impseqobj;
	STACK_OF(ASN1_INTEGER)* impseqint;
	STACK_OF(ASN1_UTF8STRING)* impseqoptstr;
	STACK_OF(ASN1_OBJECT)* impseqoptobj;
	STACK_OF(ASN1_INTEGER)* impseqoptint;
	STACK_OF(ASN1_UTF8STRING)* expseqstr;
	STACK_OF(ASN1_OBJECT)* expseqobj;
	STACK_OF(ASN1_INTEGER)* expseqint;
	STACK_OF(ASN1_UTF8STRING)* expseqoptstr;
	STACK_OF(ASN1_OBJECT)* expseqoptobj;
	STACK_OF(ASN1_INTEGER)* expseqoptint;
	ASN1_UTF8STRING* ndefexpstr;
	ASN1_OBJECT* ndefexpobj;
	ASN1_INTEGER* ndefexpint;
	ASN1_UTF8STRING* ndefexpoptstr;
	ASN1_OBJECT* ndefexpoptobj;
	ASN1_INTEGER* ndefexpoptint;
} ASN1_SEQ_DATA;


DECLARE_ASN1_FUNCTIONS(ASN1_SEQ_DATA)

ASN1_SEQUENCE(ASN1_SEQ_DATA) = {
	ASN1_SIMPLE(ASN1_SEQ_DATA, simpint, ASN1_INTEGER),
	ASN1_SIMPLE(ASN1_SEQ_DATA, simpstr, ASN1_UTF8STRING),
	ASN1_SIMPLE(ASN1_SEQ_DATA, simpobj, ASN1_OBJECT),
	ASN1_EMBED(ASN1_SEQ_DATA, embint, ZINT32),
	ASN1_OPT(ASN1_SEQ_DATA, optstr, ASN1_UTF8STRING),
	ASN1_OPT(ASN1_SEQ_DATA, optobj, ASN1_OBJECT),
	ASN1_OPT(ASN1_SEQ_DATA, optint, ASN1_INTEGER),
	ASN1_OPT_EMBED(ASN1_SEQ_DATA, optint, ZINT32),
	ASN1_IMP(ASN1_SEQ_DATA, impstr, ASN1_UTF8STRING, 1),
	ASN1_IMP(ASN1_SEQ_DATA, impobj, ASN1_OBJECT, 2),
	ASN1_IMP(ASN1_SEQ_DATA, impint, ASN1_INTEGER, 3),
	ASN1_IMP_EMBED(ASN1_SEQ_DATA, impembint, ZINT32, 4),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptstr, ASN1_UTF8STRING, 5),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptobj, ASN1_OBJECT, 6),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptint, ASN1_INTEGER, 7),
	ASN1_EXP(ASN1_SEQ_DATA, expstr, ASN1_UTF8STRING, 8),
	ASN1_EXP(ASN1_SEQ_DATA, expobj, ASN1_OBJECT, 9),
	ASN1_EXP(ASN1_SEQ_DATA, expint, ASN1_OBJECT, 10),
	ASN1_EXP_EMBED(ASN1_SEQ_DATA, expembint, ZINT32, 11),
	ASN1_EXP_OPT(ASN1_SEQ_DATA, expoptstr, ASN1_UTF8STRING, 12),
	ASN1_EXP_OPT(ASN1_SEQ_DATA, expoptobj, ASN1_OBJECT, 13),
	ASN1_EXP_OPT(ASN1_SEQ_DATA, expoptint, ASN1_INTEGER, 14),
	ASN1_EXP_OPT_EMBED(ASN1_SEQ_DATA, expoptembint, ZINT32, 15),
	ASN1_SEQUENCE_OF(ASN1_SEQ_DATA, seqstr, ASN1_UTF8STRING),
	ASN1_SEQUENCE_OF(ASN1_SEQ_DATA, seqobj, ASN1_OBJECT),
	ASN1_SEQUENCE_OF(ASN1_SEQ_DATA, seqint, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, seqoptstr, ASN1_UTF8STRING),
	ASN1_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, seqoptobj, ASN1_OBJECT),
	ASN1_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, seqoptint, ASN1_INTEGER),
	ASN1_SET_OF(ASN1_SEQ_DATA, setstr, ASN1_UTF8STRING),
	ASN1_SET_OF(ASN1_SEQ_DATA, setobj, ASN1_OBJECT),
	ASN1_SET_OF(ASN1_SEQ_DATA, setint, ASN1_INTEGER),
	ASN1_SET_OF_OPT(ASN1_SEQ_DATA, setoptstr, ASN1_UTF8STRING),
	ASN1_SET_OF_OPT(ASN1_SEQ_DATA, setoptobj, ASN1_OBJECT),
	ASN1_SET_OF_OPT(ASN1_SEQ_DATA, setoptint, ASN1_INTEGER),
	ASN1_IMP_SET_OF(ASN1_SEQ_DATA, impsetstr, ASN1_UTF8STRING, 1),
	ASN1_IMP_SET_OF(ASN1_SEQ_DATA, impsetobj, ASN1_OBJECT, 2),
	ASN1_IMP_SET_OF(ASN1_SEQ_DATA, impsetint, ASN1_INTEGER, 3),
	ASN1_EXP_SET_OF(ASN1_SEQ_DATA, expsetstr, ASN1_UTF8STRING, 4),
	ASN1_EXP_SET_OF(ASN1_SEQ_DATA, expsetobj, ASN1_OBJECT, 5),
	ASN1_EXP_SET_OF(ASN1_SEQ_DATA, expsetint, ASN1_INTEGER, 6),
	ASN1_IMP_SET_OF_OPT(ASN1_SEQ_DATA, impsetoptstr, ASN1_UTF8STRING, 7),
	ASN1_IMP_SET_OF_OPT(ASN1_SEQ_DATA, impsetoptobj, ASN1_OBJECT, 8),
	ASN1_IMP_SET_OF_OPT(ASN1_SEQ_DATA, impsetoptint, ASN1_INTEGER, 9),
	ASN1_EXP_SET_OF_OPT(ASN1_SEQ_DATA, expsetoptstr, ASN1_UTF8STRING, 10),
	ASN1_EXP_SET_OF_OPT(ASN1_SEQ_DATA, expsetoptobj, ASN1_OBJECT, 11),
	ASN1_EXP_SET_OF_OPT(ASN1_SEQ_DATA, expsetoptint, ASN1_INTEGER, 12),
	ASN1_IMP_SEQUENCE_OF(ASN1_SEQ_DATA, impseqstr, ASN1_UTF8STRING, 13),
	ASN1_IMP_SEQUENCE_OF(ASN1_SEQ_DATA, impseqobj, ASN1_OBJECT, 14),
	ASN1_IMP_SEQUENCE_OF(ASN1_SEQ_DATA, impseqint, ASN1_INTEGER, 15),
	ASN1_IMP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, impseqoptstr, ASN1_UTF8STRING, 1),
	ASN1_IMP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, impseqoptobj, ASN1_OBJECT, 2),
	ASN1_IMP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, impseqoptint, ASN1_INTEGER, 3),
	ASN1_EXP_SEQUENCE_OF(ASN1_SEQ_DATA, expseqstr, ASN1_UTF8STRING, 4),
	ASN1_EXP_SEQUENCE_OF(ASN1_SEQ_DATA, expseqobj, ASN1_OBJECT, 5),
	ASN1_EXP_SEQUENCE_OF(ASN1_SEQ_DATA, expseqint, ASN1_INTEGER, 6),
	ASN1_EXP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, expseqoptstr, ASN1_UTF8STRING, 7),
	ASN1_EXP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, expseqoptobj, ASN1_OBJECT, 8),
	ASN1_EXP_SEQUENCE_OF_OPT(ASN1_SEQ_DATA, expseqoptint, ASN1_INTEGER, 9),
	ASN1_NDEF_EXP(ASN1_SEQ_DATA, ndefexpstr, ASN1_UTF8STRING, 10),
	ASN1_NDEF_EXP(ASN1_SEQ_DATA, ndefexpobj, ASN1_OBJECT, 11),
	ASN1_NDEF_EXP(ASN1_SEQ_DATA, ndefexpint, ASN1_INTEGER, 12),
	ASN1_NDEF_EXP_OPT(ASN1_SEQ_DATA, ndefexpoptstr, ASN1_UTF8STRING, 13),
	ASN1_NDEF_EXP_OPT(ASN1_SEQ_DATA, ndefexpoptobj, ASN1_OBJECT, 14),
	ASN1_NDEF_EXP_OPT(ASN1_SEQ_DATA, ndefexpoptint, ASN1_INTEGER, 15)
} ASN1_SEQUENCE_END(ASN1_SEQ_DATA)


IMPLEMENT_ASN1_FUNCTIONS(ASN1_SEQ_DATA)


int set_asn1_object(ASN1_OBJECT** ppobj, const char* key, jvalue* pj)
{
	int ret;
	const char* pstrobj;
	int error;
	unsigned char* objsn = NULL;
	int snsize = 0;
	int snlen = 0;
	unsigned char* ccbuf = NULL;
	int ccsize = 0;
	int cclen = 0;
	int llen;
	const unsigned char* p;
	ASN1_OBJECT* pobj = NULL;

	error = 0;
	pstrobj = jobject_get_string(pj, key, &error);
	if (pstrobj == NULL) {
		return 0;
	}

	snsize = 4;
get_again:
	if (objsn != NULL) {
		OPENSSL_free(objsn);
	}
	objsn = NULL;
	objsn = (unsigned char*)OPENSSL_malloc(snsize);
	if (objsn == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "alloc [%d] error[%d]\n", snsize, ret);
		goto fail;
	}

	ret = a2d_ASN1_OBJECT(objsn, snsize, pstrobj, -1);
	if (ret <= 0 || ret >= snsize) {
		snsize <<= 1;
		goto get_again;
	}
	snlen = ret;

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
		goto fail;
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
			goto fail;
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
		goto fail;
	}

	memcpy(&(ccbuf[llen]), objsn, snlen);
	llen += snlen;



	p = (const unsigned char*) ccbuf;
	pobj = d2i_ASN1_OBJECT(ppobj, &p, llen);
	if (pobj == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not parse buffer [%d]\n", ret);
		goto fail;
	}

	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	llen = 0;
	OPENSSL_free(objsn);
	snsize = 0;
	snlen = 0;
	return 1;
fail:
	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	llen = 0;
	OPENSSL_free(objsn);
	snsize = 0;
	snlen = 0;
	SETERRNO(ret);
	return ret;
}

int set_asn1_integer(ASN1_INTEGER** ppint, const char* key, const jvalue* pj)
{
	long long int ival;
	int error;
	int ret;
	ASN1_INTEGER* pint = NULL;

	error = 0;
	ival = jobject_get_int64(pj, key, &error);
	if (error != 0) {
		return 0;
	}

	pint = *ppint;
	if (pint == NULL) {
		pint = ASN1_INTEGER_new();
		if (pint == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not alloc [%s] integer error[%d]\n", key, ret);
			goto fail;
		}
		*ppint = pint;
	}

	ret = ASN1_INTEGER_set_int64(pint, ival);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not set [%s] ival [%lld] error[%d]\n", key, ival, ret);
		goto fail;
	}
	return 1;
fail:

	SETERRNO(ret);
	return ret;
}

int set_asn1_utfstr(ASN1_UTF8STRING** ppobjstr, const char* key, const jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	ASN1_UTF8STRING* pobjstr = NULL;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		return 0;
	}

	pobjstr = *ppobjstr;
	if (pobjstr == NULL) {
		pobjstr = ASN1_STRING_new();
		if (pobjstr == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "alloc [%s] error[%d]\n", key, ret);
			goto fail;
		}
		*ppobjstr = pobjstr;
	}

	ret = ASN1_STRING_set(pobjstr, pstr, -1);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "set [%s] error[%d]\n", key, ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}


int set_asn1_object_array(STACK_OF(ASN1_OBJECT)** ppobjarr, const char* key, jvalue* pj)
{
	int ret;
	int error;
	unsigned char* objsn = NULL;
	int snsize = 0;
	int snlen = 0;
	unsigned char* ccbuf = NULL;
	int ccsize = 0;
	int cclen = 0;
	int llen;
	const unsigned char* p;
	STACK_OF(ASN1_OBJECT)* pobjarr = NULL;
	ASN1_OBJECT* pobj = NULL;
	jvalue* arrobj = NULL;
	jstring* curobj = NULL;
	unsigned int arrsize = 0;
	int cnt = 0;
	unsigned int i;


	error = 0;
	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		return 0;
	}

	snsize = 4;
	arrsize = jarray_size(arrobj);

	for (i = 0; i < arrsize; i++) {
		error = 0;
		curobj = (jstring*)jarray_get(arrobj, i, &error);
		if (curobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "get [%s].[%d] error[%d]\n", key, i, ret);
			goto fail;
		}
		if (curobj->type != JSTRING) {
			ret = -EINVAL;
			fprintf(stderr, "[%s].[%d] not JSTRING\n", key, i);
			goto fail;
		}

		ASSERT_IF(pobj == NULL);
get_again:
		if (objsn != NULL) {
			OPENSSL_free(objsn);
		}
		objsn = NULL;
		objsn = (unsigned char*)OPENSSL_malloc(snsize);
		if (objsn == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "alloc [%d] error[%d]\n", snsize, ret);
			goto fail;
		}

		ret = a2d_ASN1_OBJECT(objsn, snsize, curobj->value, -1);
		if (ret <= 0 || ret >= snsize) {
			snsize <<= 1;
			goto get_again;
		}
		snlen = ret;

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
			goto fail;
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
				goto fail;
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
			goto fail;
		}

		memcpy(&(ccbuf[llen]), objsn, snlen);
		llen += snlen;



		p = (const unsigned char*) ccbuf;
		pobj = d2i_ASN1_OBJECT(NULL, &p, llen);
		if (pobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not parse buffer [%d]\n", ret);
			goto fail;
		}

		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_OBJECT_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "alloc [%s] STACK_OF(ASN1_OBJECT) error[%d]\n", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_OBJECT_push(pobjarr,pobj);
		if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] push error[%d]\n", key,i, ret);
			goto fail;
		}
		pobj = NULL;
		cnt ++;
	}

	ASN1_OBJECT_free(pobj);
	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	llen = 0;
	OPENSSL_free(objsn);
	snsize = 0;
	snlen = 0;
	return cnt;
fail:
	ASN1_OBJECT_free(pobj);
	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	llen = 0;
	OPENSSL_free(objsn);
	snsize = 0;
	snlen = 0;
	SETERRNO(ret);
	return ret;
}

int set_asn1_integer_array(STACK_OF(ASN1_INTEGER)** ppobjarr, const char* key, jvalue* pj)
{	
	int ret;
	int error;
	STACK_OF(ASN1_INTEGER)* pobjarr = NULL;
	ASN1_INTEGER* pobj = NULL;
	jvalue* arrobj = NULL;
	jvalue* curobj = NULL;
	jint* curint=NULL;
	jint64* curint64=NULL;
	unsigned int arrsize = 0;
	int cnt = 0;
	unsigned int i;

	error = 0;
	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		return 0;
	}

	arrsize = jarray_size(arrobj);

	for (i = 0; i < arrsize; i++) {
		error = 0;
		curint = NULL;
		curint64 = NULL;
		curobj = jarray_get(arrobj, i, &error);
		if (curobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "get [%s].[%d] error[%d]\n", key, i, ret);
			goto fail;
		}

		if (curobj->type == JINT) {
			curint = (jint*) curobj;
		} else if (curobj->type == JINT64) {
			curint64 = (jint64*) curobj;
		} else {
			ret = -EINVAL;
			fprintf(stderr, "[%s].[%d] not JSTRING\n", key, i);
			goto fail;
		}

		ASSERT_IF(pobj == NULL);
		pobj = ASN1_INTEGER_new();
		if (pobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] alloc error[%d]\n", key, i,ret);
			goto fail;
		}

		if (curint) {
			ret = ASN1_INTEGER_set_int64(pobj,(int64_t)curint->value);
		} else {
			ret = ASN1_INTEGER_set_int64(pobj,(int64_t)curint64->value);
		}
		if (ret <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] set int64 error[%d]\n", key,i, ret);
			goto fail;
		}

		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_INTEGER_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "alloc [%s] STACK_OF(ASN1_INTEGER) error[%d]\n", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_INTEGER_push(pobjarr,pobj);
		if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] push error[%d]\n", key,i, ret);
			goto fail;
		}
		pobj = NULL;
		cnt ++;
	}

	ASN1_INTEGER_free(pobj);
	return cnt;
fail:
	ASN1_INTEGER_free(pobj);
	SETERRNO(ret);
	return ret;
}


int set_asn1_string_array(STACK_OF(ASN1_UTF8STRING)** ppobjarr, const char* key, jvalue* pj)
{	
	int ret;
	int error;
	STACK_OF(ASN1_UTF8STRING)* pobjarr = NULL;
	ASN1_STRING* pobj = NULL;
	jvalue* arrobj = NULL;
	jstring* curobj = NULL;
	unsigned int arrsize = 0;
	int cnt = 0;
	unsigned int i;

	error = 0;
	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		return 0;
	}

	arrsize = jarray_size(arrobj);

	for (i = 0; i < arrsize; i++) {
		error = 0;
		curobj = (jstring*)jarray_get(arrobj, i, &error);
		if (curobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "get [%s].[%d] error[%d]\n", key, i, ret);
			goto fail;
		}

		if (curobj->type != JSTRING) {
			ret = -EINVAL;
			fprintf(stderr, "[%s].[%d] error[%d]\n",key, i, ret);
			goto fail;
		}

		ASSERT_IF(pobj == NULL);
		pobj = ASN1_STRING_new();
		if (pobj == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] alloc error[%d]\n", key, i,ret);
			goto fail;
		}

		ret = ASN1_STRING_set(pobj,curobj->value,-1);
		if (ret <= 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] set error[%d]\n", key, i, ret);
			goto fail;
		}


		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_UTF8STRING_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "alloc [%s] STACK_OF(ASN1_STRING) error[%d]\n", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_UTF8STRING_push(pobjarr,pobj);
		if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s].[%d] push error[%d]\n", key,i, ret);
			goto fail;
		}
		pobj = NULL;
		cnt ++;
	}

	ASN1_STRING_free(pobj);
	return cnt;
fail:
	ASN1_STRING_free(pobj);
	SETERRNO(ret);
	return ret;
}


int set_asn1_int32(int32_t* pint32, const char* key, const jvalue *pj)
{
	int val;
	int error=0;

	val = jobject_get_int(pj,key,&error);
	if (error != 0) {
		return 0;
	}
	*pint32 = val;
	return 1;
}

int asn1seqenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_SEQ_DATA* pdata = NULL;
	jvalue* pj = NULL;
	char* pjson = NULL;
	int jsonsize = 0;
	int jsonlen = 0;
	unsigned int jlen = 0;
	pargs_options_t pargs = (pargs_options_t)popt;
	int ret;
	unsigned char* pout=NULL;
	int outlen;

	init_log_verbose(pargs);

	pdata = ASN1_SEQ_DATA_new();
	if (pdata == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "alloc ASN1_SEQ_DATA error[%d]\n", ret);
		goto out;
	}

	if (pargs->m_input == NULL) {
		ret = read_stdin_whole(0,&pjson,&jsonsize);
	} else {
		ret = read_file_whole(pargs->m_input,&pjson,&jsonsize);
	}
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}
	jsonlen = ret;
	pjson[jsonlen] = 0x0;

	jlen = jsonlen + 1;
	pj = jvalue_read(pjson,&jlen);
	if (pj == NULL) {
		ret = -EINVAL;
		fprintf(stderr,"parse [%s] error\n", pargs->m_input ? pargs->m_input : "stdin");
		goto out;
	}

	ret = set_asn1_integer(&(pdata->simpint),"simpint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object(&(pdata->simpobj),"simpobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->simpstr),"simpstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_int32(&(pdata->embint),"embint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->optstr),"optstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object(&(pdata->optobj),"optobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->optint),"optint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_int32(&(pdata->optembint),"optembint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->impstr),"impstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->impobj),"impobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->impint),"impint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_int32(&(pdata->impembint),"impembint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_utfstr(&(pdata->impoptstr),"impoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->impoptobj),"impoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->impoptint),"impoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->expstr),"expstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->expobj),"expobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->expint),"expint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_int32(&(pdata->expembint),"expembint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->expoptstr),"expoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->expoptobj),"expoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->expoptint),"expoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_int32(&(pdata->expoptembint),"expoptembint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_utfstr(&(pdata->seqstr),"seqstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->seqobj),"seqobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->seqint),"seqint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->seqoptstr),"seqoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->seqoptobj),"seqoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->seqoptint),"seqoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->setstr),"setstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->setobj),"setobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->setint),"setint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_string_array(&(pdata->setoptstr),"setoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->setoptobj),"setoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->setoptint),"setoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_string_array(&(pdata->impsetstr),"impsetstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->impsetobj),"impsetobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->impsetint),"impsetint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->expsetstr),"expsetstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->expsetobj),"expsetobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->expsetint),"expsetint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->impsetoptstr),"impsetoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->impsetoptobj),"impsetoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->impsetoptint),"impsetoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->expsetoptstr),"expsetoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->expsetoptobj),"expsetoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->expsetoptint),"expsetoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->impseqstr),"impseqstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->impseqobj),"impseqobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->impseqint),"impseqint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->impseqoptstr),"impseqoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->impseqoptobj),"impseqoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->impseqoptint),"impseqoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->expseqstr),"expseqstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->expseqobj),"expseqobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->expseqint),"expseqint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_string_array(&(pdata->expseqoptstr),"expseqoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_object_array(&(pdata->expseqoptobj),"expseqoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer_array(&(pdata->expseqoptint),"expseqoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->ndefexpstr),"ndefexpstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->ndefexpobj),"ndefexpobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->ndefexpint),"ndefexpint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_utfstr(&(pdata->ndefexpoptstr),"ndefexpoptstr",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = set_asn1_object(&(pdata->ndefexpoptobj),"ndefexpoptobj",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = set_asn1_integer(&(pdata->ndefexpoptint),"ndefexpoptint",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = i2d_ASN1_SEQ_DATA(pdata, &pout);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "seq data error[%d]\n", ret);
		goto out;
	}
	outlen = ret;

	DEBUG_BUFFER_FMT(pout, outlen, "seq data");

	ret = 0;
out:
	OPENSSL_free(pout);
	outlen = 0;
	ASN1_SEQ_DATA_free(pdata);
	if (pargs->m_input) {
		read_file_whole(NULL,&pjson,&jsonsize);
	} else {
		read_stdin_whole(1,&pjson,&jsonsize);
	}
	jsonlen = 0;
	SETERRNO(ret);
	return ret;
}

