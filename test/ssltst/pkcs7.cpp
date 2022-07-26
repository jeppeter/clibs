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
		ERROR_INFO( "can not new PKCS7 error[%d]", ret);
		goto out;
	}

	DEBUG_INFO(" ");

	ret = PKCS7_set_type(p7, NID_pkcs7_data_ex);
	if (ret == 0) {
		ret = -EINVAL;
		ERROR_INFO( "can not set NID_pkcs7_data");
		goto out;
	}

	DEBUG_INFO(" ");


	octstr = (ASN1_OCTET_STRING*)p7->d.data;
	if (str != NULL) {
		if (octstr == NULL) {
			ret = -EINVAL;
			ERROR_INFO( "data null");
			goto out;
		}

		DEBUG_INFO(" ");

		ret = ASN1_STRING_set((ASN1_STRING*) octstr, str, slen);
		if (ret == 0) {
			ret = -EINVAL;
			ERROR_INFO( "set [%s] error", str);
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
			ERROR_INFO( "can not open [%s] for write", pargs->m_output);
			goto out;
		}
	} else {
		fp = stdout;
	}

	DEBUG_INFO(" ");

	ret = i2d_PKCS7_fp(fp, p7);
	if (ret == 0) {
		ret =  -EINVAL;
		ERROR_INFO( "out [%s] error", pargs->m_output != NULL ? pargs->m_output : "stdout");
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
			ERROR_INFO( "can not open [%s] for read", pargs->m_input);
			goto out;
		}
	} else {
		fin = stdin;
	}

	p7 = d2i_PKCS7_fp(fin, NULL);
	if (p7 == NULL) {
		GETERRNO(ret);
		ERROR_INFO( "can not read PKCS7 from [%s] error[%d]", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}



	DEBUG_INFO(" ");
	if (pargs->m_output != NULL) {
		fout = fopen(pargs->m_output, "wb");
		if (fout == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "can not open [%s] for write", pargs->m_output);
			goto out;
		}
	} else {
		fout = stdout;
	}

	ret = i2d_PKCS7_fp(fout, p7);
	if (ret == 0) {
		ret =  -EINVAL;
		ERROR_INFO( "out [%s] error", pargs->m_output != NULL ? pargs->m_output : "stdout");
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
		ERROR_INFO( "can not use integer error[%d]", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pendptr = NULL;
		ival = strtoll(parsestate->leftargs[i], &pendptr, 10);
		ASN1_INTEGER_set_int64(ita, ival);
		outlen = i2d_ASN1_INTEGER(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "i2d error[%d]", ret);
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
		ERROR_INFO( "can not use integer error[%d]", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pstr = (const unsigned char*) parsestate->leftargs[i];
		llen = strlen(parsestate->leftargs[i]);
		ret = ASN1_OCTET_STRING_set(ita, pstr, llen);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "can not set [%s] error[%d]", pstr, ret);
			goto out;
		}
		outlen = i2d_ASN1_OCTET_STRING(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "i2d error[%d]", ret);
			goto out;
		}
		DEBUG_BUFFER_FMT(pout, outlen, "integer format");
		OPENSSL_free(pout);
		pout = NULL;
	}

	itn = ASN1_NULL_new();
	if (itn == NULL) {
		GETERRNO(ret);
		ERROR_INFO( "can not ASN1_NULL_new");
		goto out;
	}
	outlen = i2d_ASN1_NULL(itn, &pout);
	if (outlen <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "i2d error[%d]", ret);
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
			ERROR_INFO( "can not alloc [%d] objsn [%d]", snsize, ret);
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
			ERROR_INFO( "overflow snlen [%d]", snlen);
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
				ERROR_INFO( "can not alloc [%d]", ccsize);
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
			ERROR_INFO( "can not parse buffer [%d]", ret);
			goto out;
		}

		outlen = i2d_ASN1_OBJECT(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "i2d error[%d]", ret);
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
		ERROR_INFO( "can not use enumerated error[%d]", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		pendptr = NULL;
		ival = strtoll(parsestate->leftargs[i], &pendptr, 10);
		ASN1_ENUMERATED_set_int64(ita, ival);
		outlen = i2d_ASN1_ENUMERATED(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "i2d error[%d]", ret);
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
		ERROR_INFO("can not use string error[%d]", ret);
		goto out;
	}

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		ret = ASN1_STRING_set(ita, parsestate->leftargs[i], -1);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "set [%s] error[%d]", parsestate->leftargs[i], ret);
			goto out;
		}
		outlen = i2d_ASN1_UTF8STRING(ita, &pout);
		if (outlen <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "i2d error[%d]", ret);
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
	ASN1_UTF8STRING embstr;
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
	STACK_OF(ASN1_UTF8STRING)* seqstr;
	STACK_OF(ASN1_OBJECT)* seqobj;
	STACK_OF(ASN1_INTEGER)* seqint;
	STACK_OF(ASN1_UTF8STRING)* seqoptstr;
	STACK_OF(ASN1_OBJECT)* seqoptobj;
	STACK_OF(ASN1_INTEGER)* seqoptint;
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
	ASN1_EMBED(ASN1_SEQ_DATA,embstr, ASN1_UTF8STRING),
	ASN1_OPT(ASN1_SEQ_DATA, optstr, ASN1_UTF8STRING),
	ASN1_OPT(ASN1_SEQ_DATA, optobj, ASN1_OBJECT),
	ASN1_OPT(ASN1_SEQ_DATA, optint, ASN1_INTEGER),
	ASN1_OPT_EMBED(ASN1_SEQ_DATA, optembint, ZINT32),
	ASN1_IMP(ASN1_SEQ_DATA, impstr, ASN1_UTF8STRING, 1),
	ASN1_IMP(ASN1_SEQ_DATA, impobj, ASN1_OBJECT, 2),
	ASN1_IMP(ASN1_SEQ_DATA, impint, ASN1_INTEGER, 3),
	ASN1_IMP_EMBED(ASN1_SEQ_DATA, impembint, ZINT32, 4),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptstr, ASN1_UTF8STRING, 5),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptobj, ASN1_OBJECT, 6),
	ASN1_IMP_OPT(ASN1_SEQ_DATA, impoptint, ASN1_INTEGER, 7),
	ASN1_EXP(ASN1_SEQ_DATA, expstr, ASN1_UTF8STRING, 8),
	ASN1_EXP(ASN1_SEQ_DATA, expobj, ASN1_OBJECT, 9),
	ASN1_EXP(ASN1_SEQ_DATA, expint, ASN1_INTEGER, 10),
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
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	DEBUG_INFO("set [%s] object", key);

	snsize = 4;
get_again:
	if (objsn != NULL) {
		OPENSSL_free(objsn);
	}
	objsn = NULL;
	objsn = (unsigned char*)OPENSSL_malloc(snsize);
	if (objsn == NULL) {
		GETERRNO(ret);
		ERROR_INFO( "alloc [%d] error[%d]", snsize, ret);
		goto fail;
	}

	ret = a2d_ASN1_OBJECT(objsn, snsize, pstrobj, -1);
	if (ret <= 0 || ret >= snsize) {
		snsize <<= 1;
		DEBUG_INFO("a2d [%s] error[%d]", pstrobj, ret);
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
		ERROR_INFO( "overflow snlen [%d]", snlen);
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
			ERROR_INFO( "can not alloc [%d]", ccsize);
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
		ERROR_INFO( "can not parse buffer [%d]", ret);
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

		error = 0;
		ival = (long long int) jobject_get_int(pj, key, &error);
		if (error != 0) {
			DEBUG_INFO("no [%s] set", key);
			return 0;
		}
	}

	pint = *ppint;
	if (pint == NULL) {
		pint = ASN1_INTEGER_new();
		if (pint == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "can not alloc [%s] integer error[%d]", key, ret);
			goto fail;
		}
		*ppint = pint;
	}

	ret = ASN1_INTEGER_set_int64(pint, ival);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "can not set [%s] ival [%lld] error[%d]", key, ival, ret);
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
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	pobjstr = *ppobjstr;
	if (pobjstr == NULL) {
		pobjstr = ASN1_STRING_new();
		if (pobjstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppobjstr = pobjstr;
	}

	ret = ASN1_STRING_set(pobjstr, pstr, -1);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "set [%s] error[%d]", key, ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int set_asn1_embstr(ASN1_UTF8STRING* pobjstr, const char* key, const jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}


	ret = ASN1_STRING_set(pobjstr, pstr, -1);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "set [%s] error[%d]", key, ret);
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
			ERROR_INFO( "get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		if (curobj->type != JSTRING) {
			ret = -EINVAL;
			ERROR_INFO( "[%s].[%d] not JSTRING", key, i);
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
			ERROR_INFO( "alloc [%d] error[%d]", snsize, ret);
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
			ERROR_INFO( "overflow snlen [%d]", snlen);
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
				ERROR_INFO( "can not alloc [%d]", ccsize);
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
			ERROR_INFO( "can not parse buffer [%d]", ret);
			goto fail;
		}

		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_OBJECT_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				ERROR_INFO( "alloc [%s] STACK_OF(ASN1_OBJECT) error[%d]", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_OBJECT_push(pobjarr, pobj);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] push error[%d]", key, i, ret);
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
	jint* curint = NULL;
	jint64* curint64 = NULL;
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
			ERROR_INFO( "get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		if (curobj->type == JINT) {
			curint = (jint*) curobj;
		} else if (curobj->type == JINT64) {
			curint64 = (jint64*) curobj;
		} else {
			ret = -EINVAL;
			ERROR_INFO( "[%s].[%d] not JSTRING", key, i);
			goto fail;
		}

		ASSERT_IF(pobj == NULL);
		pobj = ASN1_INTEGER_new();
		if (pobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] alloc error[%d]", key, i, ret);
			goto fail;
		}

		if (curint) {
			ret = ASN1_INTEGER_set_int64(pobj, (int64_t)curint->value);
		} else {
			ret = ASN1_INTEGER_set_int64(pobj, (int64_t)curint64->value);
		}
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] set int64 error[%d]", key, i, ret);
			goto fail;
		}

		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_INTEGER_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				ERROR_INFO( "alloc [%s] STACK_OF(ASN1_INTEGER) error[%d]", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_INTEGER_push(pobjarr, pobj);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] push error[%d]", key, i, ret);
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
			ERROR_INFO( "get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		if (curobj->type != JSTRING) {
			ret = -EINVAL;
			ERROR_INFO( "[%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(pobj == NULL);
		pobj = ASN1_STRING_new();
		if (pobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] alloc error[%d]", key, i, ret);
			goto fail;
		}

		ret = ASN1_STRING_set(pobj, curobj->value, -1);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] set error[%d]", key, i, ret);
			goto fail;
		}


		if (pobjarr == NULL) {
			pobjarr = sk_ASN1_UTF8STRING_new_null();
			if (pobjarr == NULL) {
				GETERRNO(ret);
				ERROR_INFO( "alloc [%s] STACK_OF(ASN1_STRING) error[%d]", key, ret);
				goto fail;
			}
			*ppobjarr = pobjarr;
		}

		ret = sk_ASN1_UTF8STRING_push(pobjarr, pobj);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO( "[%s].[%d] push error[%d]", key, i, ret);
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
	int error = 0;

	val = jobject_get_int(pj, key, &error);
	if (error != 0) {
		return 0;
	}
	*pint32 = val;
	return 1;
}

#define SET_SEQ_INT_VALUE(member)                                                                 \
do{                                                                                               \
	ret = set_asn1_integer(&(pdata->member),#member,pj);                                          \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define SET_SEQ_OBJECT_VALUE(member)                                                              \
do{                                                                                               \
	ret = set_asn1_object(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define SET_SEQ_STR_VALUE(member)                                                                 \
do{                                                                                               \
	ret = set_asn1_utfstr(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define SET_SEQ_INT32_VALUE(member)                                                               \
do{                                                                                               \
	ret = set_asn1_int32(&(pdata->member),#member,pj);                                            \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define SET_SEQ_STR_EMBED(member)                                                                 \
do{                                                                                               \
	ret = set_asn1_embstr(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define SET_SEQ_INT_ARRAY(member)                                                                 \
do{                                                                                               \
	ret = set_asn1_integer_array(&(pdata->member),#member,pj);                                    \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define SET_SEQ_OBJECT_ARRAY(member)                                                              \
do{                                                                                               \
	ret = set_asn1_object_array(&(pdata->member),#member,pj);                                     \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define SET_SEQ_STR_ARRAY(member)                                                                 \
do{                                                                                               \
	ret = set_asn1_string_array(&(pdata->member),#member,pj);                                     \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


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
	unsigned char* pout = NULL;
	int outlen;

	init_log_verbose(pargs);

	pdata = ASN1_SEQ_DATA_new();
	if (pdata == NULL) {
		GETERRNO(ret);
		ERROR_INFO( "alloc ASN1_SEQ_DATA error[%d]", ret);
		goto out;
	}

	if (pargs->m_input == NULL) {
		ret = read_stdin_whole(0, &pjson, &jsonsize);
	} else {
		ret = read_file_whole(pargs->m_input, &pjson, &jsonsize);
	}
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO( "read [%s] error[%d]", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}
	jsonlen = ret;
	pjson[jsonlen] = 0x0;

	jlen = jsonlen + 1;
	pj = jvalue_read(pjson, &jlen);
	if (pj == NULL) {
		ret = -EINVAL;
		ERROR_INFO("parse [%s] error", pargs->m_input ? pargs->m_input : "stdin");
		goto out;
	}

	SET_SEQ_INT_VALUE(simpint);
	SET_SEQ_OBJECT_VALUE(simpobj);
	SET_SEQ_STR_VALUE(simpstr);
	SET_SEQ_INT32_VALUE(embint);
	SET_SEQ_STR_EMBED(embstr);
	SET_SEQ_STR_VALUE(optstr);
	SET_SEQ_OBJECT_VALUE(optobj);
	SET_SEQ_INT_VALUE(optint);
	SET_SEQ_INT32_VALUE(optembint);
	SET_SEQ_STR_VALUE(impstr);
	SET_SEQ_OBJECT_VALUE(impobj);
	SET_SEQ_INT_VALUE(impint);
	SET_SEQ_INT32_VALUE(impembint);
	SET_SEQ_STR_VALUE(impoptstr);
	SET_SEQ_OBJECT_VALUE(impoptobj);
	SET_SEQ_INT_VALUE(impoptint);
	SET_SEQ_STR_VALUE(expstr);
	SET_SEQ_OBJECT_VALUE(expobj);
	SET_SEQ_INT_VALUE(expint);
	SET_SEQ_INT32_VALUE(expembint);
	SET_SEQ_STR_VALUE(expoptstr);
	SET_SEQ_OBJECT_VALUE(expoptobj);
	SET_SEQ_INT_VALUE(expoptint);
	SET_SEQ_INT32_VALUE(expoptembint);
	SET_SEQ_STR_ARRAY(seqstr);
	SET_SEQ_OBJECT_ARRAY(seqobj);
	SET_SEQ_INT_ARRAY(seqint);
	SET_SEQ_STR_ARRAY(seqoptstr);
	SET_SEQ_OBJECT_ARRAY(seqoptobj);
	SET_SEQ_INT_ARRAY(seqoptint);
	SET_SEQ_STR_ARRAY(setstr);
	SET_SEQ_OBJECT_ARRAY(setobj);
	SET_SEQ_INT_ARRAY(setint);
	SET_SEQ_STR_ARRAY(setoptstr);
	SET_SEQ_OBJECT_ARRAY(setoptobj);
	SET_SEQ_INT_ARRAY(setoptint);
	SET_SEQ_STR_ARRAY(impsetstr);
	SET_SEQ_OBJECT_ARRAY(impsetobj);
	SET_SEQ_INT_ARRAY(impsetint);
	SET_SEQ_STR_ARRAY(expsetstr);
	SET_SEQ_OBJECT_ARRAY(expsetobj);
	SET_SEQ_INT_ARRAY(expsetint);
	SET_SEQ_STR_ARRAY(impsetoptstr);
	SET_SEQ_OBJECT_ARRAY(impsetoptobj);
	SET_SEQ_INT_ARRAY(impsetoptint);
	SET_SEQ_STR_ARRAY(expsetoptstr);
	SET_SEQ_OBJECT_ARRAY(expsetoptobj);
	SET_SEQ_INT_ARRAY(expsetoptint);
	SET_SEQ_STR_ARRAY(impseqstr);
	SET_SEQ_OBJECT_ARRAY(impseqobj);
	SET_SEQ_INT_ARRAY(impseqint);
	SET_SEQ_STR_ARRAY(impseqoptstr);
	SET_SEQ_OBJECT_ARRAY(impseqoptobj);
	SET_SEQ_INT_ARRAY(impseqoptint);
	SET_SEQ_STR_ARRAY(expseqstr);
	SET_SEQ_OBJECT_ARRAY(expseqobj);
	SET_SEQ_INT_ARRAY(expseqint);
	SET_SEQ_STR_ARRAY(expseqoptstr);
	SET_SEQ_OBJECT_ARRAY(expseqoptobj);
	SET_SEQ_INT_ARRAY(expseqoptint);
	SET_SEQ_STR_VALUE(ndefexpstr);
	SET_SEQ_OBJECT_VALUE(ndefexpobj);
	SET_SEQ_INT_VALUE(ndefexpint);
	SET_SEQ_STR_VALUE(ndefexpoptstr);
	SET_SEQ_OBJECT_VALUE(ndefexpoptobj);
	SET_SEQ_INT_VALUE(ndefexpoptint);

	ret = i2d_ASN1_SEQ_DATA(pdata, &pout);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "seq data error[%d]", ret);
		goto out;
	}
	outlen = ret;

	DEBUG_BUFFER_FMT(pout, outlen, "seq data");
	if (pargs->m_output != NULL) {
		ret = write_file_whole(pargs->m_output, (char*)pout, outlen);
	} else {
		ret =  write_out_whole(STDOUT_FILE_FLAG, (char*)pout, outlen);
	}
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not write [%s] error[%d]", pargs->m_output ? pargs->m_output : "stdout", ret);
		goto out;
	}

	ret = 0;
out:
	if (pj) {
		jvalue_destroy(pj);
	}
	pj = NULL;

	OPENSSL_free(pout);
	outlen = 0;
	ASN1_SEQ_DATA_free(pdata);
	if (pargs->m_input) {
		read_file_whole(NULL, &pjson, &jsonsize);
	} else {
		read_stdin_whole(1, &pjson, &jsonsize);
	}
	jsonlen = 0;
	SETERRNO(ret);
	return ret;
}

int get_asn1_integer(ASN1_INTEGER** ppint, const char* key, jvalue* pj)
{
	ASN1_INTEGER* pint;
	int64_t pr;
	int ret;
	if (ppint == NULL || *ppint == NULL) {
		DEBUG_INFO("no [%s]", key);
		return 0;
	}

	pint = *ppint;
	pr = 0;
	ret = ASN1_INTEGER_get_int64(&pr, pint);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not get [%s] int", key);
		goto fail;
	} else if (ret == 0) {
		ret = jobject_put_int64(pj, key, 0);
	} else {
		ret = jobject_put_int64(pj, key, pr);
	}

	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not put [%s] in json", key);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int get_asn1_object(ASN1_OBJECT** ppobj, const char* key, jvalue* pj)
{
	int ret;
	char* ccbuf = NULL;
	int cclen = 0;
	int ccsize = 0;
	ASN1_OBJECT* pobj;
	int setted = 0;

	if (ppobj == NULL || *ppobj == NULL) {
		DEBUG_INFO("no [%s] object", key);
		return 0;
	}
	ccsize = 4;
	pobj = *ppobj;
get_again:
	OPENSSL_free(ccbuf);
	ccbuf = (char*) OPENSSL_malloc(ccsize);
	if (ccbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not alloc [%d] buffer [%d]", ccsize, ret);
		goto fail;
	}
	memset(ccbuf , 0 , ccsize);

	ret = i2t_ASN1_OBJECT(ccbuf, ccsize, pobj);
	if (ret < 0) {
		ccsize <<= 1;
		goto get_again;
	} else if (ret == 0) {
		goto out;
	}
	cclen = ret;
	if (cclen >= ccsize) {
		ccsize <<= 1;
		goto get_again;
	}
	/*put end of char*/
	ccbuf[cclen] = 0x0;

	ret = jobject_put_string(pj, key, ccbuf);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not put [%s] value [%s] error[%d]", key, ccbuf, ret);
		goto fail;
	}
	setted = 1;
out:
	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	return setted;
fail:
	OPENSSL_free(ccbuf);
	ccsize = 0;
	cclen = 0;
	SETERRNO(ret);
	return ret;
}

int get_asn1_utfstr(ASN1_UTF8STRING** ppstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_UTF8STRING* pstr;
	if (ppstr == NULL || *ppstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pstr = *ppstr;


	pout = (const char*)ASN1_STRING_get0_data(pstr);
	if (pout != NULL) {
		ret = jobject_put_string(pj, key, pout);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("can not put [%s] [%s] error[%d]", key, pout, ret);
			goto fail;
		}
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int get_asn1_embstr(ASN1_UTF8STRING* pstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;


	pout = (const char*)ASN1_STRING_get0_data(pstr);
	if (pout != NULL) {
		ret = jobject_put_string(pj, key, pout);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("can not put [%s] [%s] error[%d]", key, pout, ret);
			goto fail;
		}
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}


int get_asn1_string_array(STACK_OF(ASN1_UTF8STRING)** ppstrarr, const char* key, jvalue* pj)
{
	jvalue* parr = NULL;
	STACK_OF(ASN1_UTF8STRING)* pstrarr = NULL;
	ASN1_UTF8STRING* pcurstr = NULL;
	int cnt = 0;
	int ret;
	const char* pout = NULL;
	int i;
	if (ppstrarr == NULL || *ppstrarr == NULL) {
		DEBUG_INFO("no [%s] array", key);
		return 0;
	}

	pstrarr = *ppstrarr;
	if (parr == NULL) {
		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] error[%d]", key, ret);
			goto fail;
		}
	}


	for (i = 0; i < sk_ASN1_UTF8STRING_num(pstrarr); i++) {
		pcurstr = sk_ASN1_UTF8STRING_value(pstrarr, i);
		if (pcurstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		pout = (const char*)ASN1_STRING_get0_data(pcurstr);
		if (pout != NULL) {
			ret = jarray_put_string(parr, pout);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("can not set [%s][%d] [%s] error[%d]", key, i, pout, ret);
				goto fail;
			}
			cnt ++;
		}

	}

	if (parr != NULL) {
		ret = jobject_put_array(pj, key, parr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] array error[%d]", key, ret);
			goto fail;
		}
		/*we have inserted ,so make it ok*/
		parr = NULL;
	}

	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	return cnt;
fail:
	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}

int get_asn1_object_array(STACK_OF(ASN1_OBJECT)** ppobjarr, const char* key, jvalue* pj)
{
	jvalue* parr = NULL;
	STACK_OF(ASN1_OBJECT)* pobjarr = NULL;
	ASN1_OBJECT* pcurobj = NULL;
	int cnt = 0;
	int ret;
	char* pout = NULL;
	int outsize = 0;
	int outlen = 0;
	int i;
	if (ppobjarr == NULL || *ppobjarr == NULL) {
		DEBUG_INFO("no [%s] array", key);
		return 0;
	}

	pobjarr = *ppobjarr;

	if (parr == NULL) {
		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] error[%d]", key, ret);
			goto fail;
		}
	}

	outsize = 4;
	for (i = 0; i < sk_ASN1_OBJECT_num(pobjarr); i++) {
		pcurobj = sk_ASN1_OBJECT_value(pobjarr, i);
		if (pcurobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
get_again:
		OPENSSL_free(pout);
		pout = (char*)OPENSSL_malloc(outsize);
		if (pout == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc [%s] [%d] error[%d]", key, outsize, ret);
			goto fail;
		}

		ret = i2t_ASN1_OBJECT(pout, outsize, pcurobj);
		if (ret < 0) {
			outsize <<= 1;
			goto get_again;
		} else if (ret > 0) {
			outlen = ret;
			if (outlen >= outsize) {
				outsize <<= 1;
				goto get_again;
			}
			pout[outlen] = 0x0;


			ret = jarray_put_string(parr, pout);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put string [%s] [%s] error[%d]", key, pout, ret);
				goto fail;
			}
			cnt ++;
		} else {
			WARN_INFO("[%s].[%d] not valid", key,i);
		}
	}

	if (parr != NULL) {
		ret = jobject_put_array(pj, key, parr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] array error[%d]", key, ret);
			goto fail;
		}
		/*put so not free again*/
		parr = NULL;
	}

	OPENSSL_free(pout);
	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	return cnt;
fail:
	OPENSSL_free(pout);
	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}


int get_asn1_integer_array(STACK_OF(ASN1_INTEGER)** ppintarr, const char* key, jvalue* pj)
{
	jvalue* parr = NULL;
	STACK_OF(ASN1_INTEGER)* pintarr = NULL;
	ASN1_INTEGER* pcurint = NULL;
	int cnt = 0;
	int ret;
	int64_t pr;
	int i;
	if (ppintarr == NULL || *ppintarr == NULL) {
		DEBUG_INFO("no [%s] array", key);
		return 0;
	}

	pintarr = *ppintarr;
	if (parr == NULL) {
		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] error[%d]", key, ret);
			goto fail;
		}
	}

	for (i = 0; i < sk_ASN1_INTEGER_num(pintarr); i++) {
		pcurint = sk_ASN1_INTEGER_value(pintarr, i);
		if (pcurint == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ret = ASN1_INTEGER_get_int64(&pr, pcurint);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("can not get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}


		ret = jarray_put_int64(parr, pr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put string [%s] [%lld] error[%d]", key, pr, ret);
			goto fail;
		}
		cnt ++;
	}

	if (parr != NULL) {
		ret = jobject_put_array(pj, key, parr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] array error[%d]", key, ret);
			goto fail;
		}
		/*put for no free*/
		parr= NULL;
	}

	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	return cnt;
fail:
	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}

int get_asn1_int32(int32_t* pint32, const char* key, jvalue* pj)
{
	int ret;
	if (pint32 == NULL) {
		return 0;
	}
	ret = jobject_put_int(pj, key, *pint32);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("put [%s] error[%d]", key, ret);
		goto fail;
	}
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

#define GET_SEQ_INT_VALUE(member)                                                                 \
do{                                                                                               \
	ret = get_asn1_integer(&(pdata->member),#member,pj);                                          \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define GET_SEQ_STR_VALUE(member)                                                                 \
do{                                                                                               \
	ret = get_asn1_utfstr(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define GET_SEQ_OBJECT_VALUE(member)                                                              \
do{                                                                                               \
	ret = get_asn1_object(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define GET_SEQ_INT32_VALUE(member)                                                               \
do{                                                                                               \
	ret = get_asn1_int32(&(pdata->member),#member,pj);                                            \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define GET_SEQ_STR_EMBED(member)                                                                 \
do{                                                                                               \
	ret = get_asn1_embstr(&(pdata->member),#member,pj);                                           \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define GET_SEQ_INT_ARRAY(member)                                                                 \
do{                                                                                               \
	ret = get_asn1_integer_array(&(pdata->member),#member,pj);                                    \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

#define GET_SEQ_STR_ARRAY(member)                                                                 \
do{                                                                                               \
	ret = get_asn1_string_array(&(pdata->member),#member,pj);                                     \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)


#define GET_SEQ_OBJECT_ARRAY(member)                                                              \
do{                                                                                               \
	ret = get_asn1_object_array(&(pdata->member),#member,pj);                                     \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
}while(0)

int asn1seqdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_SEQ_DATA* pdata = NULL;
	char* pout = NULL;
	int outlen = 0;
	int outsize = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	const unsigned char* p;
	int ret;
	jvalue* pj = NULL;
	char* jsonstr = NULL;
	unsigned int jlen = 0;

	init_log_verbose(pargs);
	if (pargs->m_input) {
		ret = read_file_whole(pargs->m_input, &pout, &outsize);
	} else {
		ret = read_stdin_whole(0, &pout, &outsize);
	}
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not read [%s] error[%d]", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}
	outlen = ret;

	p = (const unsigned char*) pout;
	pdata = d2i_ASN1_SEQ_DATA(NULL, &p, outlen);
	if (pdata == NULL) {
		GETERRNO(ret);
		ERROR_INFO("parse data error[%d]", ret);
		goto out;
	}

	jlen = 2;
	pj = jvalue_read("{}", &jlen);
	if (pj == NULL) {
		GETERRNO(ret);
		ERROR_INFO("read jvalue error[%d]", ret);
		goto out;
	}

	GET_SEQ_INT_VALUE(simpint);
	GET_SEQ_STR_VALUE(simpstr);
	GET_SEQ_OBJECT_VALUE(simpobj);
	GET_SEQ_INT32_VALUE(embint);
	GET_SEQ_STR_EMBED(embstr);
	GET_SEQ_INT_VALUE(optint);
	GET_SEQ_STR_VALUE(optstr);
	GET_SEQ_OBJECT_VALUE(optobj);
	GET_SEQ_INT_VALUE(impint);
	GET_SEQ_STR_VALUE(impstr);
	GET_SEQ_OBJECT_VALUE(impobj);
	GET_SEQ_INT32_VALUE(impembint);
	GET_SEQ_INT_VALUE(impoptint);
	GET_SEQ_STR_VALUE(impoptstr);
	GET_SEQ_OBJECT_VALUE(impoptobj);
	GET_SEQ_INT_VALUE(expint);
	GET_SEQ_STR_VALUE(expstr);
	GET_SEQ_OBJECT_VALUE(expobj);
	GET_SEQ_INT32_VALUE(expembint);
	GET_SEQ_INT_VALUE(expoptint);
	GET_SEQ_STR_VALUE(expoptstr);
	GET_SEQ_OBJECT_VALUE(expoptobj);
	GET_SEQ_INT32_VALUE(expoptembint);
	GET_SEQ_INT_ARRAY(seqint);
	GET_SEQ_STR_ARRAY(seqstr);
	GET_SEQ_OBJECT_ARRAY(seqobj);
	GET_SEQ_INT_ARRAY(seqoptint);
	GET_SEQ_STR_ARRAY(seqoptstr);
	GET_SEQ_OBJECT_ARRAY(seqoptobj);
	GET_SEQ_STR_ARRAY(setstr);
	GET_SEQ_OBJECT_ARRAY(setobj);
	GET_SEQ_INT_ARRAY(setint);
	GET_SEQ_STR_ARRAY(setoptstr);
	GET_SEQ_OBJECT_ARRAY(setoptobj);
	GET_SEQ_INT_ARRAY(setoptint);
	GET_SEQ_STR_ARRAY(impsetstr);
	GET_SEQ_OBJECT_ARRAY(impsetobj);
	GET_SEQ_INT_ARRAY(impsetint);
	GET_SEQ_STR_ARRAY(expsetstr);
	GET_SEQ_OBJECT_ARRAY(expsetobj);
	GET_SEQ_INT_ARRAY(expsetint);
	GET_SEQ_STR_ARRAY(impsetoptstr);
	GET_SEQ_OBJECT_ARRAY(impsetoptobj);
	GET_SEQ_INT_ARRAY(impsetoptint);
	GET_SEQ_STR_ARRAY(expsetoptstr);
	GET_SEQ_OBJECT_ARRAY(expsetoptobj);
	GET_SEQ_INT_ARRAY(expsetoptint);
	GET_SEQ_STR_ARRAY(impsetstr);
	GET_SEQ_OBJECT_ARRAY(impseqobj);
	GET_SEQ_INT_ARRAY(impseqint);
	GET_SEQ_STR_ARRAY(impseqoptstr);
	GET_SEQ_OBJECT_ARRAY(impseqoptobj);
	GET_SEQ_INT_ARRAY(impseqoptint);
	GET_SEQ_STR_ARRAY(expseqstr);
	GET_SEQ_OBJECT_ARRAY(expseqobj);
	GET_SEQ_INT_ARRAY(expseqint);
	GET_SEQ_STR_ARRAY(expseqoptstr);
	GET_SEQ_OBJECT_ARRAY(expseqoptobj);
	GET_SEQ_INT_ARRAY(expseqoptint);
	GET_SEQ_INT_VALUE(ndefexpint);
	GET_SEQ_STR_VALUE(ndefexpstr);
	GET_SEQ_OBJECT_VALUE(ndefexpobj);
	GET_SEQ_INT_VALUE(ndefexpoptint);
	GET_SEQ_STR_VALUE(ndefexpoptstr);
	GET_SEQ_OBJECT_VALUE(ndefexpoptobj);

	jsonstr = jvalue_write_pretty(pj, &jlen);
	if (jsonstr == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not format json error[%d]", ret);
		goto out;
	}

	if (pargs->m_output) {
		ret = write_file_whole(pargs->m_output, jsonstr, jlen);
	} else {
		ret = write_out_whole(STDOUT_FILE_FLAG, jsonstr, jlen);
	}
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("write [%s] error [%d]", pargs->m_output ? pargs->m_output : "stdout", ret);
		goto out;
	}

	ret = 0;
out:
	if (jsonstr) {
		free(jsonstr);
	}
	jsonstr = NULL;
	jlen = 0;
	if (pargs->m_input) {
		read_file_whole(NULL, &pout, &outsize);
	} else {
		read_stdin_whole(1, &pout, &outsize);
	}
	outlen = 0;
	ASN1_SEQ_DATA_free(pdata);
	SETERRNO(ret);
	return ret;
}

#define SEARCH_DIGIT(p)                                                                           \
do{                                                                                               \
	while(*p != 0x0 && ( *p < '0' || *p > '9')) {                                                 \
		p ++;                                                                                     \
	}                                                                                             \
	if (*p < '0' || *p > '9') {                                                                   \
		ret = -EINVAL;                                                                            \
		goto fail;                                                                                \
	}                                                                                             \
}while(0)

#define SKIP_DIGIT(p)                                                                             \
do{                                                                                               \
	while(*p >= '0' && *p <= '9') {                                                               \
		p ++;                                                                                     \
	}                                                                                             \
}while(0)

int get_time_str(const char* timestr, time_t* ptm)
{
	struct tm stm = {0};
	char* pcur= (char*)timestr;
	int ret = 0;

	/*first search year*/
	SEARCH_DIGIT(pcur);
	stm.tm_year = atoi(pcur) - 1900;
	SKIP_DIGIT(pcur);

	SEARCH_DIGIT(pcur);
	stm.tm_mon = atoi(pcur) - 1;
	SKIP_DIGIT(pcur);

	SEARCH_DIGIT(pcur);
	stm.tm_mday = atoi(pcur);
	SKIP_DIGIT(pcur);

	SEARCH_DIGIT(pcur);
	stm.tm_hour = atoi(pcur);
	SKIP_DIGIT(pcur);

	SEARCH_DIGIT(pcur);
	stm.tm_min = atoi(pcur);
	SKIP_DIGIT(pcur);

	SEARCH_DIGIT(pcur);
	stm.tm_sec = atoi(pcur);
	SKIP_DIGIT(pcur);

	*ptm = mktime(&stm);
	if (*ptm == -1) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int asn1timeenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_TIME* ptime=NULL;
	ASN1_TIME* prettime = NULL;
	unsigned char* pout=NULL;
	int outlen = 0;
	int ret;
	pargs_options_t pargs = (pargs_options_t)popt;
	int i;
	const char* timestr = NULL;
	time_t settm;
	init_log_verbose(pargs);

	ptime = ASN1_TIME_new();
	if (ptime == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not new ASN1_TIME [%d]",ret);
		goto out;
	}

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		timestr = parsestate->leftargs[i];
		ret = get_time_str(timestr,&settm);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("get time [%s] error[%d]", timestr, ret);
			goto out;
		}
		DEBUG_INFO("[%s] to [0x%lx:%ld]", timestr, settm,settm);

		prettime = ASN1_TIME_set(ptime, settm);
		if (prettime == NULL) {
			GETERRNO(ret);
			ERROR_INFO("set [%s] time error[%d]", timestr, ret);
			goto out;
		}
		OPENSSL_free(pout);
		pout = NULL;
		ret = i2d_ASN1_TIME(ptime,&pout);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("can not format ASN1_TIME for [%s] error[%d]", timestr,ret);
			goto out;
		}
		outlen = ret;
		DEBUG_BUFFER_FMT(pout, outlen, "out[%s] time", timestr);
	}


	ret = 0;
out:
	OPENSSL_free(pout);
	ASN1_TIME_free(ptime);
	SETERRNO(ret);
	return ret;
}