
int set_asn1_bmpstr(ASN1_BMPSTRING **ppbmpstr, const char* key, jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_BMPSTRING* pbmpstr = NULL;
	char* inbuf=NULL;
	size_t inlen=0;
	char*outbuf=NULL;
	char* pout=NULL;
	size_t outlen=0;
	size_t outsize=0;
	iconv_t cd = (iconv_t)-1;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	pbmpstr = *ppbmpstr;
	if (pbmpstr == NULL) {
		pbmpstr = ASN1_BMPSTRING_new();
		if (pbmpstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppbmpstr = pbmpstr;
	}
	rlen = strlen(pstr);

	/*from UTF-8 to UTF-16BE*/
	cd = iconv_open("UTF-16BE","UTF-8");
	if (cd == (iconv_t) -1) {
		GETERRNO(ret);
		ERROR_INFO("iconv_open error[%d]",ret);
		goto fail;
	}

	outsize = (rlen << 1) + 2;
	outbuf = (char*)malloc(outsize);
	if (outbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(outbuf,0,outsize);
	inbuf = (char*)pstr;
	inlen = (size_t)rlen;
	outlen = outsize;
	pout = outbuf;
	ret = iconv(cd,&inbuf,&inlen,&pout,&outlen);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	ret = ASN1_OCTET_STRING_set(pbmpstr, (unsigned char*)outbuf, (outsize - outlen));
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO( "set [%s] error[%d]", key, ret);
		goto fail;
	}

	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;

	if (cd != (iconv_t)-1) {
		iconv_close(cd);
	}
	cd = (iconv_t)-1;


	return 1;
fail:
	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;
	if (cd != (iconv_t)-1) {
		iconv_close(cd);
	}
	cd = (iconv_t)-1;
	SETERRNO(ret);
	return ret;
}

int set_asn1_string(ASN1_STRING **ppstr, const char* key, jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_STRING* pasn1str = NULL;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	pasn1str = *ppstr;
	if (pasn1str == NULL) {
		pasn1str = ASN1_STRING_new();
		if (pasn1str == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppstr = pasn1str;
	}
	rlen = strlen(pstr);
	ret = ASN1_STRING_set(pasn1str, (unsigned char*)pstr, rlen);
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


int set_asn1_ia5str(ASN1_IA5STRING **ppia5, const char* key, jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_IA5STRING* pia5str = NULL;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	pia5str = *ppia5;
	if (pia5str == NULL) {
		pia5str = ASN1_IA5STRING_new();
		if (pia5str == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppia5 = pia5str;
	}
	rlen = strlen(pstr);
	ret = ASN1_OCTET_STRING_set(pia5str, (unsigned char*)pstr, rlen);
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

int set_asn1_octstr(ASN1_OCTET_STRING** ppoct, const char* key, jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_OCTET_STRING* poctstr = NULL;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	poctstr = *ppoct;
	if (poctstr == NULL) {
		poctstr = ASN1_OCTET_STRING_new();
		if (poctstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppoct = poctstr;
	}
	rlen = strlen(pstr);
	ret = ASN1_OCTET_STRING_set(poctstr, (unsigned char*)pstr, rlen);
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

int set_asn1_octdata(ASN1_OCTET_STRING** ppoct, const char* key, jvalue* pj)
{
	int error;
	int ret;
	ASN1_OCTET_STRING* poctstr = NULL;
	jvalue* arrobj = NULL;
	unsigned char* pbuf = NULL;
	jvalue* curobj = NULL;
	int arrsize = 0;
	int i;
	jint* curint=NULL;
	jint64* curint64=NULL;


	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		return 0;
	}

	poctstr = ASN1_OCTET_STRING_new();
	if (poctstr == NULL) {
		GETERRNO(ret);
		ERROR_INFO("ASN1_OCTET_STRING_new error[%d]", ret);
		goto fail;
	}

	arrsize = (int)jarray_size(arrobj);

	pbuf = (unsigned char*)malloc(arrsize);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pbuf,0,arrsize);

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
			pbuf[i] = (unsigned char)curint->value;
		} else if (curobj->type == JINT64) {
			curint64 = (jint64*) curobj;
			pbuf[i] = (unsigned char) curint64->value;
		} else {
			ret = -EINVAL;
			ERROR_INFO( "[%s].[%d] not JSTRING", key, i);
			goto fail;
		}
	}

	if (arrsize > 0) {
		ASN1_STRING_set0((ASN1_STRING*)poctstr,pbuf,arrsize);
		/*we replaced*/
		pbuf = NULL;
	}
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;

	if (*ppoct) {
		ASN1_OCTET_STRING_free(*ppoct);
		*ppoct = NULL;
	}
	*ppoct = poctstr;
	poctstr = NULL;

	return (int) arrsize;
fail:
	if (poctstr) {
		ASN1_OCTET_STRING_free(poctstr);
	}
	poctstr = NULL;
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	SETERRNO(ret);
	return ret;
}


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
	const char* sval = NULL;
	int error;
	int ret;
	ASN1_INTEGER* pint = NULL, *pretint = NULL;
	BIGNUM* bn = NULL;


	error = 0;
	ival = jobject_get_int64(pj, key, &error);
	if (error != 0) {
		error = 0;
		ival = (long long int) jobject_get_int(pj, key, &error);
		if (error != 0) {
			error = 0;
			sval = jobject_get_string(pj, key, &error);
			if (sval == NULL || error != 0) {
				DEBUG_INFO("no [%s] set", key);
				return 0;
			}
			ret = BN_hex2bn(&bn, sval);
			if (ret == 0) {
				GETERRNO(ret);
				ERROR_INFO("hex2bn [%s] error[%d]", sval, ret);
				goto fail;
			}
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

	if (bn != NULL) {
		pretint = BN_to_ASN1_INTEGER(bn, pint);
		if (pretint == NULL) {
			GETERRNO(ret);
			ERROR_INFO("bn set error[%d]", ret);
			goto fail;
		}
	} else {
		ret = ASN1_INTEGER_set_int64(pint, ival);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO( "can not set [%s] ival [%lld] error[%d]", key, ival, ret);
			goto fail;
		}
	}

	if (bn) {
		BN_free(bn);
	}
	bn = NULL;

	return 1;
fail:
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;
	SETERRNO(ret);
	return ret;
}

int set_asn1_bitstr(ASN1_BIT_STRING** ppbitstr, const char* key, const jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_BIT_STRING* pbitstr = NULL;

	error = 0;
	pstr = jobject_get_string(pj, key, &error);
	if (pstr == NULL) {
		DEBUG_INFO("no [%s] set", key);
		return 0;
	}

	pbitstr = *ppbitstr;
	if (pbitstr == NULL) {
		pbitstr = ASN1_BIT_STRING_new();
		if (pbitstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO( "alloc [%s] error[%d]", key, ret);
			goto fail;
		}
		*ppbitstr = pbitstr;
	}
	rlen = strlen(pstr);
	ret = ASN1_BIT_STRING_set(pbitstr, (unsigned char*)pstr, rlen);
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

int set_asn1_bitdata(ASN1_BIT_STRING** ppbitstr, const char* key, const jvalue* pj)
{
	int error;
	int ret;
	ASN1_BIT_STRING* pbitstr = NULL;
	jvalue* arrobj = NULL;
	unsigned char* pbuf = NULL;
	jvalue* curobj = NULL;
	int arrsize = 0;
	int i;
	jint* curint=NULL;
	jint64* curint64=NULL;


	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		return 0;
	}

	pbitstr = ASN1_BIT_STRING_new();
	if (pbitstr == NULL) {
		GETERRNO(ret);
		ERROR_INFO("ASN1_OCTET_STRING_new error[%d]", ret);
		goto fail;
	}

	arrsize = (int)jarray_size(arrobj);

	pbuf = (unsigned char*)malloc(arrsize);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pbuf,0,arrsize);

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
			pbuf[i] = (unsigned char)curint->value;
		} else if (curobj->type == JINT64) {
			curint64 = (jint64*) curobj;
			pbuf[i] = (unsigned char) curint64->value;
		} else {
			ret = -EINVAL;
			ERROR_INFO( "[%s].[%d] not JSTRING", key, i);
			goto fail;
		}
	}

	if (arrsize > 0) {
		ASN1_STRING_set0((ASN1_STRING*)pbitstr,pbuf,arrsize);
		/*we replaced*/
		pbuf = NULL;
	}
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;

	if (*ppbitstr) {
		ASN1_BIT_STRING_free(*ppbitstr);
		*ppbitstr = NULL;
	}
	*ppbitstr = pbitstr;
	pbitstr = NULL;

	return (int) arrsize;
fail:
	if (pbitstr) {
		ASN1_BIT_STRING_free(pbitstr);
	}
	pbitstr = NULL;
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
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
	jstring* curs = NULL;
	ASN1_INTEGER*pretint = NULL;
	unsigned int arrsize = 0;
	int cnt = 0;
	unsigned int i;
	BIGNUM* bn = NULL;

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
		curs = NULL;
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
		} else if (curobj->type == JSTRING) {
			curs = (jstring*) curobj;
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
		} else if (curint64 ) {
			ret = ASN1_INTEGER_set_int64(pobj, (int64_t)curint64->value);
		} else  {
			ASSERT_IF(bn == NULL);
			ret = BN_hex2bn(&bn, curs->value);
			if (ret == 0) {
				GETERRNO(ret);
				ERROR_INFO("bn [%s] error[%d]", curs->value, ret);
				goto fail;
			}
			pretint = BN_to_ASN1_INTEGER(bn, pobj);
			if (pretint == NULL) {
				GETERRNO(ret);
				ERROR_INFO("set integer [%s] error[%d]", curs->value, ret);
				goto fail;
			}
			BN_free(bn);
			bn = NULL;
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

	ASSERT_IF(bn == NULL);
	ASN1_INTEGER_free(pobj);
	return cnt;
fail:
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;
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
	long long int val64;
	int error = 0;

	val = jobject_get_int(pj, key, &error);
	if (error != 0) {
		error = 0;
		val64 = jobject_get_int64(pj,key,&error);
		if (error != 0) {
			return 0;	
		}
		*pint32 = (int32_t)val64;
		return 1;
		
	}
	*pint32 = val;
	return 1;
}

int set_asn1_any(ASN1_TYPE** ppany , const char* key, const jvalue* pj)
{
	jvalue* ptype = NULL;
	jvalue* parr = NULL;
	jint* jval = NULL;
	const char* stype = NULL;
	unsigned int i;
	unsigned int size;
	int itype;
	ASN1_TYPE* pat = NULL;
	ASN1_OBJECT* pnobj = NULL;
	jvalue* curval = NULL;
	unsigned char* pbuf = NULL;
	void* bptr = NULL;
	int bval;
	int ret;
	int error;
	uint64_t num;
	ASN1_STRING* pstr = NULL;
	char* pendptr = NULL;

	if (ppany == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	DEBUG_INFO(" ");
	ptype = jobject_get(pj, key);
	if (ptype == NULL) {
		DEBUG_INFO("no [%s] for json", key);
		return 0;
	}

	if (ptype->type != JOBJECT) {
		ret = -EINVAL;
		ERROR_INFO("[%s] not valid object", key);
		goto fail;
	}

	stype = jobject_get_string(ptype, "type", &error);
	if (stype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("[%s] no type has", key);
		goto fail;
	}

	if (*ppany == NULL) {
		*ppany = ASN1_TYPE_new();
		if (*ppany == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc [%s] error[%d]", key, ret);
			goto fail;
		}
	}
	pat = *ppany;

	if (strcmp(stype, "bool") == 0) {
		itype = V_ASN1_BOOLEAN;
try_bool:
		bval = jobject_get_bool(ptype, "value", &error);
		if (error != 0) {
			ret = -EINVAL;
			goto fail;
		}
		bptr = NULL;
		if (bval) {
			bptr = ptype;
		}
		ret = ASN1_TYPE_set1(pat, itype, bptr);
	} else if (strcmp(stype, "null") == 0) {
		itype = V_ASN1_NULL;
try_null:
		ret = ASN1_TYPE_set1(pat, itype, NULL);
	} else {
		/*now to copy the value*/
		ret = parse_number((char*)stype, &num, &pendptr);
		if (ret < 0) {
			ret = -EINVAL;
			ERROR_INFO("[%s] not valid for type ", stype);
			goto fail;
		}
		itype = (int)num;
		if (itype == V_ASN1_NULL) {
			goto try_null;
		}

		if (itype == V_ASN1_BOOLEAN) {
			goto try_bool;
		}

		parr = jobject_get(ptype, "data");
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("can not get [%s].[data]", key);
			goto fail;
		}

		pstr = ASN1_STRING_new();
		if (pstr == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		if (parr->type != JARRAY) {
			ret = -EINVAL;
			ERROR_INFO("[%s].[data] not array", key);
			goto fail;
		}

		size = jarray_size(parr);
		if (size > 0) {
			pbuf = (unsigned char*)malloc(size);
			if (pbuf == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			memset(pbuf, 0, size);
			for (i = 0; i < size; i++) {
				ASSERT_IF(curval == NULL);
				error = 0;
				curval = jarray_get(parr, i, &error);
				if (curval == NULL || error != 0) {
					ret = -EINVAL;
					ERROR_INFO("[%s].[data].[%d] get error[%d]", key, i, error);
					goto fail;
				}

				if (curval->type != JINT) {
					ret = -EINVAL;
					ERROR_INFO("[%s].[data].[%d] not int", key, i);
					goto fail;
				}
				jval = (jint*) curval;
				if (jval->value > 255) {
					ret = -EINVAL;
					ERROR_INFO("[%s].[data].[%d] not valid value [%d]", key, i, jval->value);
					goto fail;
				}
				pbuf[i] = (unsigned char)jval->value;
				jval = NULL;
				curval = NULL;
			}
			DEBUG_BUFFER_FMT(pbuf, size, "set buffer");
			ret = ASN1_STRING_set(pstr, pbuf, size);
			if (ret <= 0) {
				GETERRNO(ret);
				ERROR_INFO("set [%s] string error[%d]", key, ret);
				goto fail;
			}
		}

		ret = ASN1_TYPE_set1(pat, itype, pstr);
	}
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("set [%s] type error[%d]", key, ret);
		goto fail;
	}

	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	if (pstr) {
		ASN1_STRING_free(pstr);
	}
	pstr = NULL;
	if (pnobj) {
		ASN1_OBJECT_free(pnobj);
	}
	pnobj = NULL;

	return 1;
fail:
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	if (pstr) {
		ASN1_STRING_free(pstr);
	}
	pstr = NULL;
	if (pnobj) {
		ASN1_OBJECT_free(pnobj);
	}
	pnobj = NULL;

	SETERRNO(ret);
	return ret;
}

int set_asn1_seq(ASN1_STRING** ppstr , const char* key, const jvalue* pj)
{
	jvalue* parr = NULL;
	jvalue* curval = NULL;
	jint* jval = NULL;
	int ret;
	unsigned char* pbuf = NULL;
	unsigned int size = 0;
	unsigned int i;
	int error;
	ASN1_STRING* pstr = NULL;


	if (ppstr == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	error = 0;
	parr = (jvalue*)jobject_get_array(pj, key, &error);
	if (parr == NULL) {
		DEBUG_INFO("no [%s] for json", key);
		return 0;
	}

	DEBUG_INFO(" ");
	if (parr->type != JARRAY) {
		ret = -EINVAL;
		ERROR_INFO("[%s] not valid object", key);
		goto fail;
	}


	if (*ppstr == NULL) {
		*ppstr = ASN1_STRING_new();
		if (*ppstr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc [%s] error[%d]", key, ret);
			goto fail;
		}
	}
	pstr = *ppstr;


	size = jarray_size(parr);
	if (size > 0) {
		pbuf = (unsigned char*)malloc(size);
		if (pbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pbuf, 0, size);
		for (i = 0; i < size; i++) {
			ASSERT_IF(curval == NULL);
			error = 0;
			curval = jarray_get(parr, i, &error);
			if (curval == NULL || error != 0) {
				ret = -EINVAL;
				ERROR_INFO("[%s].[data].[%d] get error[%d]", key, i, error);
				goto fail;
			}

			if (curval->type != JINT) {
				ret = -EINVAL;
				ERROR_INFO("[%s].[data].[%d] not int", key, i);
				goto fail;
			}
			jval = (jint*) curval;
			if (jval->value > 255) {
				ret = -EINVAL;
				ERROR_INFO("[%s].[data].[%d] not valid value [%d]", key, i, jval->value);
				goto fail;
			}
			pbuf[i] = (unsigned char)jval->value;
			jval = NULL;
			curval = NULL;
		}
		DEBUG_BUFFER_FMT(pbuf, size, "set buffer");
		ret = ASN1_STRING_set(pstr, pbuf, size);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("set [%s] string error[%d]", key, ret);
			goto fail;
		}
	}

	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	return 1;
fail:
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int set_asn1_utctime(ASN1_UTCTIME** pputc, const char* key, jvalue* pj)
{
	const char* putcstr = NULL;
	int error;
	int ret;

	error = 0;
	putcstr = jobject_get_string(pj, key, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("[%s] get string error[%d]", key, ret);
		goto fail;
	}
	if (putcstr == NULL) {
		DEBUG_INFO("no [%s] utctime", key);
		return 0;
	}

	if (pputc == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	if (*pputc == NULL) {
		*pputc = ASN1_UTCTIME_new();
		if (*pputc == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] error[%d]", key, ret);
			goto fail;
		}
	}

	ret = ASN1_UTCTIME_set_string(*pputc, putcstr);
	if (ret == 0) {
		GETERRNO(ret);
		ERROR_INFO("set [%s] [%s] error[%d]", key, putcstr, ret);
		goto fail;
	}
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int get_asn1_integer(ASN1_INTEGER** ppint, const char* key, jvalue* pj)
{
	ASN1_INTEGER* pint;
	int ret;
	BIGNUM* bn = NULL;
	char* buf = NULL;
	if (ppint == NULL || *ppint == NULL) {
		DEBUG_INFO("no [%s]", key);
		return 0;
	}

	pint = *ppint;

	bn = ASN1_INTEGER_to_BN(pint, NULL);
	if (bn == NULL) {
		GETERRNO(ret);
		ERROR_INFO("get [%s] error[%d]", key, ret);
		goto fail;
	}

	buf = BN_bn2hex(bn);
	if (buf == NULL) {
		GETERRNO(ret);
		ERROR_INFO("bn2hex [%s] error[%d]", key, ret);
		goto fail;
	}

	ret = jobject_put_string(pj, key, buf);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not put [%s] in json", key);
		goto fail;
	}

	if (buf) {
		free(buf);
	}
	buf = NULL;
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;

	return 1;
fail:
	if (buf) {
		free(buf);
	}
	buf = NULL;
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;

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

int get_asn1_bitstr(ASN1_BIT_STRING** ppbitstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_UTF8STRING* pbitstr;
	if (ppbitstr == NULL || *ppbitstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pbitstr = *ppbitstr;


	pout = (const char*)ASN1_STRING_get0_data(pbitstr);
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

int get_asn1_bitdata(ASN1_BIT_STRING** ppbitstr, const char* key, jvalue* pj)
{
	int ret;
	ASN1_BIT_STRING* pbitstr;
	ASN1_STRING* pstr;
	jvalue* arrobj = NULL;
	jvalue* replpj = NULL;
	unsigned char* pbuf=NULL;
	int bufsize=0;
	int i;
	jint* curval = NULL;
	int error=0;
	if (ppbitstr == NULL || *ppbitstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pbitstr = *ppbitstr;

	pstr = (ASN1_STRING*)pbitstr;
	pbuf = (unsigned char*)ASN1_STRING_get0_data(pstr);
	bufsize = ASN1_STRING_length(pstr);
	arrobj = jarray_create();
	if (arrobj == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	if (bufsize > 0) {
		for(i=0;i<bufsize;i++) {
			ASSERT_IF(curval == NULL);
			curval = (jint*)jint_create(pbuf[i]);
			if (curval == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = jarray_put(arrobj,(jvalue*)curval);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put [%s].[%d] error[%d]",key,i,ret);
				goto fail;
			}

			curval = NULL;
		}
	}

	error = 0;
	replpj = jobject_put(pj,key,arrobj,&error);
	if (error != 0) {
		GETERRNO(ret);
		goto fail;
	}
	arrobj = NULL;
	if (replpj) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;

	return bufsize;
fail:
	if (replpj) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	if (curval) {
		jvalue_destroy((jvalue*)curval);
	}
	curval = NULL;
	if (arrobj) {
		jvalue_destroy(arrobj);
	}
	arrobj = NULL;
	SETERRNO(ret);
	return ret;	
}

int get_asn1_bmpstr(ASN1_BMPSTRING** ppbmpstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pcc = NULL;
	int setted = 0;
	ASN1_BMPSTRING* pbmpstr = NULL;
	iconv_t cd=(iconv_t)-1;
	char* outbuf=NULL,*pout=NULL;
	char* pin=NULL;
	size_t outsize=0;
	size_t outlen=0;
	size_t insize=0;
	size_t inlen=0;
	unsigned short* pwc=NULL;

	if (ppbmpstr == NULL || *ppbmpstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pbmpstr = *ppbmpstr;


	pcc = (const char*)ASN1_STRING_get0_data(pbmpstr);
	if (pcc != NULL) {
		cd = iconv_open("UTF-8","UTF-16BE");
		if (cd == (iconv_t)-1) {
			GETERRNO(ret);
			goto fail;
		}
		pwc = (unsigned short*)pcc;
		insize =0;
		while (pwc[insize] != 0) {
			insize += 1;
		}
		outsize = insize + 1;
		insize *= 2;
		inlen = insize;
		outbuf = (char*)malloc(outsize);
		if (outbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(outbuf,0,outsize);
		pin = (char*)pcc;
		inlen = insize;
		pout = outbuf;
		outlen = outsize;

		ret = iconv(cd,&pin,&inlen,&pout,&outlen);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}


		ret = jobject_put_string(pj, key, outbuf);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("can not put [%s] [%s] error[%d]", key, pout, ret);
			goto fail;
		}
		setted = 1;
	}

	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;

	if (cd != (iconv_t)-1) {
		iconv_close(cd);
	}
	cd = (iconv_t)-1;

	return setted;
fail:
	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;

	if (cd != (iconv_t)-1) {
		iconv_close(cd);
	}
	cd = (iconv_t)-1;
	SETERRNO(ret);
	return ret;
}


int get_asn1_ia5str(ASN1_IA5STRING** ppia5, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_IA5STRING* pia5str = NULL;
	if (ppia5 == NULL || *ppia5 == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pia5str = *ppia5;


	pout = (const char*)ASN1_STRING_get0_data(pia5str);
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


int get_asn1_string(ASN1_STRING** ppstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_STRING* pasn1str = NULL;
	if (ppstr == NULL || *ppstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pasn1str = *ppstr;


	pout = (const char*)ASN1_STRING_get0_data(pasn1str);
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


int get_asn1_octstr(ASN1_OCTET_STRING** ppoctstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_UTF8STRING* poctstr;
	if (ppoctstr == NULL || *ppoctstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	poctstr = *ppoctstr;


	pout = (const char*)ASN1_STRING_get0_data(poctstr);
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

int get_asn1_octdata(ASN1_OCTET_STRING** ppoctstr, const char* key, jvalue* pj)
{
	int ret;
	ASN1_UTF8STRING* poctstr;
	ASN1_STRING* pstr;
	jvalue* arrobj = NULL;
	jvalue* replpj = NULL;
	unsigned char* pbuf=NULL;
	int bufsize=0;
	int i;
	jint* curval = NULL;
	int error=0;
	if (ppoctstr == NULL || *ppoctstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	poctstr = *ppoctstr;

	pstr = (ASN1_STRING*)poctstr;
	pbuf = (unsigned char*)ASN1_STRING_get0_data(pstr);
	bufsize = ASN1_STRING_length(pstr);
	arrobj = jarray_create();
	if (arrobj == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	if (bufsize > 0) {
		for(i=0;i<bufsize;i++) {
			ASSERT_IF(curval == NULL);
			curval = (jint*)jint_create(pbuf[i]);
			if (curval == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = jarray_put(arrobj,(jvalue*)curval);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put [%s].[%d] error[%d]",key,i,ret);
				goto fail;
			}

			curval = NULL;
		}
	}

	error = 0;
	replpj = jobject_put(pj,key,arrobj,&error);
	if (error != 0) {
		GETERRNO(ret);
		goto fail;
	}
	arrobj = NULL;
	if (replpj) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;

	return bufsize;
fail:
	if (replpj) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	if (curval) {
		jvalue_destroy((jvalue*)curval);
	}
	curval = NULL;
	if (arrobj) {
		jvalue_destroy(arrobj);
	}
	arrobj = NULL;
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
			WARN_INFO("[%s].[%d] not valid", key, i);
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
	int i;
	BIGNUM* bn = NULL;
	char* buf = NULL;
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

		ASSERT_IF(bn == NULL);
		bn = ASN1_INTEGER_to_BN(pcurint, NULL);
		if (bn == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] bn error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(buf == NULL);
		buf = BN_bn2hex(bn);
		if (buf == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] buffer error[%d]", key, i, ret);
			goto fail;
		}



		ret = jarray_put_string(parr, buf);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put string [%s] [%s] error[%d]", key, buf, ret);
			goto fail;
		}
		cnt ++;
		BN_free(bn);
		free(buf);
		bn = NULL;
		buf = NULL;
	}

	if (parr != NULL) {
		ret = jobject_put_array(pj, key, parr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] array error[%d]", key, ret);
			goto fail;
		}
		/*put for no free*/
		parr = NULL;
	}

	if (parr != NULL) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	return cnt;
fail:
	if (buf) {
		free(buf);
	}
	buf = NULL;
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;

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

int get_asn1_any(ASN1_TYPE** ppany, const char* key, jvalue* pj)
{
	jvalue *parr = NULL;
	jvalue * curval = NULL;
	jvalue *retpj = NULL;
	jvalue *pinsert = NULL;
	ASN1_TYPE* at;
	int bval;
	ASN1_OBJECT* pnobj = NULL;
	int i;
	int ret;
	unsigned char *pbuf = NULL;
	int buflen = 0;
	int error;
	int typ;
	ASN1_INTEGER* pinteger = NULL;
	ASN1_STRING* pstr = NULL;
	char* typestr = NULL;
	int typesize = 0;
	long lval;
	if (ppany == NULL || *ppany == NULL) {
		DEBUG_INFO("no [%s] any", key);
		return 0;
	}
	at = *ppany;
	typ = ASN1_TYPE_get(at);
	pinsert = jobject_create();
	if (pinsert == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] insert error[%d]", key, ret);
		goto fail;
	}
	if (typ == V_ASN1_OBJECT) {
		ret = jobject_put_string(pinsert, "type", "object");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] type object error[%d]", key, ret);
			goto fail;
		}
		pnobj = at->value.object;
		if (pnobj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no object for [%s]", key);
			goto fail;
		}
		ret = get_asn1_object(&pnobj, "value", pinsert);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret == 0) {
			ret =  -EINVAL;
			ERROR_INFO("no [%s] value for object", key);
			goto fail;
		}

	} else if (typ == V_ASN1_NULL) {
		ret = jobject_put_string(pinsert, "type", "null");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] type null error[%d]", key, ret);
			goto fail;
		}
	} else if (typ == V_ASN1_BOOLEAN) {
		ret = jobject_put_string(pinsert, "type", "bool");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] type null error[%d]", key, ret);
			goto fail;
		}
		bval = at->value.boolean;
		ret = jobject_put_bool(pinsert, "value", bval);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] value bool error[%d]", key, ret);
			goto fail;
		}
	} else if (typ == V_ASN1_INTEGER || typ == V_ASN1_ENUMERATED) {
		pinteger = at->value.integer;
		lval = ASN1_INTEGER_get(pinteger);
		pbuf = (unsigned char*)&lval;
		buflen = sizeof(lval);
		goto put_data;
	} else if (typ == V_ASN1_BIT_STRING || typ == V_ASN1_OCTET_STRING || typ == V_ASN1_UTF8STRING || typ == V_ASN1_SEQUENCE || typ == V_ASN1_SET || typ == V_ASN1_NUMERICSTRING || typ == V_ASN1_PRINTABLESTRING || typ == V_ASN1_T61STRING || typ == V_ASN1_T61STRING || typ == V_ASN1_TELETEXSTRING || typ == V_ASN1_VIDEOTEXSTRING || typ == V_ASN1_IA5STRING || typ == V_ASN1_UTCTIME || typ == V_ASN1_GENERALIZEDTIME || typ == V_ASN1_GRAPHICSTRING || typ == V_ASN1_ISO64STRING || typ == V_ASN1_VISIBLESTRING || typ == V_ASN1_GENERALSTRING || typ == V_ASN1_UNIVERSALSTRING) {
		pstr = at->value.set;
		pbuf = (unsigned char*)ASN1_STRING_get0_data(pstr);
		buflen = ASN1_STRING_length(pstr);
		goto put_data;
	} else {
		pstr = at->value.set;
		pbuf = (unsigned char*)ASN1_STRING_get0_data(pstr);
		buflen = ASN1_STRING_length(pstr);
put_data:
		ret = snprintf_safe(&typestr, &typesize, "0x%x", typ);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = jobject_put_string(pinsert, "type", typestr);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}

		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create array error[%d]", ret);
			goto fail;
		}

		for (i = 0; i < buflen; i++) {
			ASSERT_IF(curval == NULL);
			curval = jint_create(pbuf[i]);
			if (curval == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = jarray_put(parr, curval);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put [%d] [0x%02x] error[%d]", i, pbuf[i], ret);
				goto fail;
			}
			/*all is insert*/
			curval = NULL;
		}

		error = 0;
		retpj = jobject_put(pinsert, "data", parr, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("insert data error[%d]", error);
			goto fail;
		}
		parr = NULL;
		if (retpj != NULL) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	error = 0;
	retpj = jobject_put(pj, key, pinsert, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("put value error[%d]", error);
		goto fail;
	}
	pinsert = NULL;
	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	snprintf_safe(&typestr, &typesize, NULL);

	return 1;
fail:
	snprintf_safe(&typestr, &typesize, NULL);
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (curval) {
		jvalue_destroy(curval);
	}
	curval = NULL;
	if (parr) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	if (pinsert) {
		jvalue_destroy(pinsert);
	}
	pinsert = NULL;
	SETERRNO(ret);
	return ret;
}

int get_asn1_seq(ASN1_STRING** ppstr, const char* key, jvalue* pj)
{
	jvalue *parr = NULL;
	jvalue * curval = NULL;
	ASN1_STRING* pstr = NULL;
	unsigned char* pbuf=NULL;
	unsigned int buflen;
	unsigned int i;
	int ret;
	if (ppstr == NULL || *ppstr == NULL) {
		DEBUG_INFO("no [%s] any", key);
		return 0;
	}
	pstr = *ppstr;
	parr = jarray_create();
	if (parr == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] insert error[%d]", key, ret);
		goto fail;
	}
	pbuf = (unsigned char*)ASN1_STRING_get0_data(pstr);
	buflen = ASN1_STRING_length(pstr);

	for (i = 0; i < buflen; i++) {
		ASSERT_IF(curval == NULL);
		curval = jint_create(pbuf[i]);
		if (curval == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		ret = jarray_put(parr, curval);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%d] [0x%02x] error[%d]", i, pbuf[i], ret);
			goto fail;
		}
		/*all is insert*/
		curval = NULL;
	}

	ret = jobject_put_array(pj, key, parr);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("insert %s error[%d]",key, ret);
		goto fail;
	}
	parr = NULL;
	return 1;
fail:
	if (curval) {
		jvalue_destroy(curval);
	}
	curval = NULL;
	if (parr) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}

int get_asn1_utctime(ASN1_UTCTIME** pputc, const char* key, jvalue* pj)
{
	const char* pstr  = NULL;
	int ret;
	int setted = 0;
	if (pputc == NULL || *pputc == NULL) {
		DEBUG_INFO("no [%s] setted", key);
		return 0;
	}

	pstr = (const char*)ASN1_STRING_get0_data((ASN1_STRING*)*pputc);
	if (pstr != NULL) {
		ret = jobject_put_string(pj, key, pstr);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] [%s] error[%d]", key, pstr, ret);
			goto fail;
		}
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}


#define EXPAND_ENCODE_HANDLER(typev)                                                              \
do{                                                                                               \
	typev* pstr = NULL;                                                                           \
	int ret;                                                                                      \
	jvalue *pj = NULL;                                                                            \
	char* jsonfile = NULL;                                                                        \
	char* jbuf = NULL;                                                                            \
	int jsize = 0, jlen = 0;                                                                      \
	unsigned int jsonlen;                                                                         \
	uint8_t* pp = NULL;                                                                           \
	uint8_t* pin = NULL;                                                                          \
	int plen = 0;                                                                                 \
	pargs_options_t pargs = (pargs_options_t) popt;                                               \
                                                                                                  \
	init_log_verbose(pargs);                                                                      \
	pstr = typev##_new();                                                                         \
	if (pstr == NULL) {                                                                           \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	if (parsestate->leftargs && parsestate->leftargs[0] != NULL) {                                \
		jsonfile = parsestate->leftargs[0];                                                       \
	}                                                                                             \
    DEBUG_INFO(" ");                                                                              \
	if (jsonfile == NULL) {                                                                       \
		ret = -EINVAL;                                                                            \
		ERROR_INFO("no jsonfile specified");                                                      \
		goto out;                                                                                 \
	}                                                                                             \
    DEBUG_INFO(" ");                                                                              \
	ret = read_file_whole(jsonfile, &jbuf, &jsize);                                               \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
    DEBUG_INFO(" ");                                                                              \
    jlen = ret;                                                                                   \
	jbuf[jlen] = 0x0;                                                                             \
	jsonlen = jlen + 1;                                                                           \
    DEBUG_INFO(" ");                                                                              \
	pj = jvalue_read(jbuf, &jsonlen);                                                             \
	if (pj == NULL) {                                                                             \
		GETERRNO(ret);                                                                            \
		ERROR_INFO("parse [%s] error[%d]", jsonfile, ret);                                        \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	ret = encode_##typev(pj, pstr);                                                                \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	ret = i2d_##typev(pstr, NULL);                                                                \
	if (ret <= 0) {                                                                               \
		GETERRNO(ret);                                                                            \
		ERROR_INFO("can not i2d %s [%d]",#typev, ret);                                            \
		goto out;                                                                                 \
	}                                                                                             \
	plen = ret;                                                                                   \
                                                                                                  \
	pp = (uint8_t*)malloc(plen);                                                                  \
	if (pp == NULL) {                                                                             \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	pin = pp;                                                                                     \
	ret = i2d_##typev(pstr, &pin);                                                                \
	if (ret <= 0) {                                                                               \
		GETERRNO(ret);                                                                            \
		const char* errfile=NULL,*errfunc=NULL,*errdata=NULL;                                     \
		int errline=0,errflags=0;                                                                 \
		ERR_peek_error_all(&errfile,&errline,&errfunc,&errdata,&errflags);                        \
		ERROR_INFO("can not i2d %s [%d] [%s:%d] errflags 0x%x:%d",#typev, ret,                    \
			errfile,errline,errflags,errflags);                                                   \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	if (pargs->m_output != NULL) {                                                                \
		ret = write_file_whole(pargs->m_output, (char*)pp, plen);                                 \
		if (ret < 0) {                                                                            \
			GETERRNO(ret);                                                                        \
			ERROR_INFO("write [%s] failed", pargs->m_output);                                     \
			goto out;                                                                             \
		}                                                                                         \
	} else {                                                                                      \
		dump_buffer_out(stdout, pp, plen, "%s",#typev);                                           \
	}                                                                                             \
                                                                                                  \
	ret = 0;                                                                                      \
out:                                                                                              \
	if (pp != NULL) {                                                                             \
		OPENSSL_free(pp);                                                                         \
	}                                                                                             \
	pp = NULL;                                                                                    \
                                                                                                  \
	if (pstr != NULL) {                                                                           \
		typev##_free(pstr);                                                                       \
	}                                                                                             \
	pstr = NULL;                                                                                  \
	if (pj) {                                                                                     \
		jvalue_destroy(pj);                                                                       \
	}                                                                                             \
	pj = NULL;                                                                                    \
	read_file_whole(NULL, &jbuf, &jsize);                                                         \
	jlen = 0;                                                                                     \
	SETERRNO(ret);                                                                                \
	return ret;                                                                                   \
}while(0)

#define  EXPAND_DECODE_HANDLER(typev)                                                             \
do{                                                                                               \
	typev* pstr = NULL;                                                                           \
	int ret;                                                                                      \
	jvalue *pj = NULL;                                                                            \
	char* binfile = NULL;                                                                         \
	char* pbin = NULL;                                                                            \
	int blen = 0, bsize = 0;                                                                      \
	char* jbuf = NULL;                                                                            \
	int jlen = 0;                                                                                 \
	unsigned int jsonlen;                                                                         \
	const unsigned char* pin = NULL;                                                              \
	int i;                                                                                        \
	pargs_options_t pargs = (pargs_options_t) popt;                                               \
                                                                                                  \
	init_log_verbose(pargs);                                                                      \
                                                                                                  \
	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {                           \
		binfile = parsestate->leftargs[i];                                                        \
		ret = read_file_whole(binfile, &pbin, &bsize);                                            \
		if (ret < 0) {                                                                            \
			GETERRNO(ret);                                                                        \
			ERROR_INFO("read [%s] error[%d]", binfile, ret);                                      \
			goto out;                                                                             \
		}                                                                                         \
		blen = ret;                                                                               \
		if (pstr != NULL) {                                                                       \
			typev##_free(pstr);                                                                   \
		}                                                                                         \
		pstr =  NULL;                                                                             \
                                                                                                  \
		pin = (const unsigned char*)pbin;                                                         \
		pstr = d2i_##typev(NULL, &pin, blen);                                                     \
		if (pstr == NULL) {                                                                       \
			GETERRNO(ret);                                                                        \
			const char* errfile=NULL,*errfunc=NULL,*errdata=NULL;                                 \
			int errline=0,errflags=0;                                                             \
			ERR_peek_error_all(&errfile,&errline,&errfunc,&errdata,&errflags);                    \
			ERROR_BUFFER_FMT(pbin,blen,"[%s] not valid [%s:%d] %s [%d:0x%x][%d]",binfile,         \
				errfile,errline,#typev,errflags,errflags,ret);                                    \
			goto out;                                                                             \
		}                                                                                         \
                                                                                                  \
		if (pj != NULL) {                                                                         \
			jvalue_destroy(pj);                                                                   \
		}                                                                                         \
		pj = NULL;                                                                                \
                                                                                                  \
		pj = jobject_create();                                                                    \
		if (pj == NULL) {                                                                         \
			GETERRNO(ret);                                                                        \
			goto out;                                                                             \
		}                                                                                         \
                                                                                                  \
		ret = decode_##typev(pstr, pj);                                                           \
		if (ret < 0) {                                                                            \
			GETERRNO(ret);                                                                        \
			goto out;                                                                             \
		}                                                                                         \
                                                                                                  \
		if (jbuf != NULL) {                                                                       \
			free(jbuf);                                                                           \
		}                                                                                         \
		jbuf = NULL;                                                                              \
                                                                                                  \
		jsonlen = 0;                                                                              \
		jbuf = jvalue_write_pretty(pj, &jsonlen);                                                 \
		if (jbuf == NULL) {                                                                       \
			GETERRNO(ret);                                                                        \
			goto out;                                                                             \
		}                                                                                         \
		if (pargs->m_output) {                                                                    \
			ret = write_file_whole(pargs->m_output, jbuf, jlen);                                  \
			if (ret < 0) {                                                                        \
				GETERRNO(ret);                                                                    \
				goto out;                                                                         \
			}                                                                                     \
		} else {                                                                                  \
			fprintf(stdout, "%s\n", jbuf);                                                        \
		}                                                                                         \
	}                                                                                             \
	ret = 0;                                                                                      \
out:                                                                                              \
	if (pstr != NULL) {                                                                           \
		typev##_free(pstr);                                                                       \
	}                                                                                             \
	pstr = NULL;                                                                                  \
	if (pj) {                                                                                     \
		jvalue_destroy(pj);                                                                       \
	}                                                                                             \
	pj = NULL;                                                                                    \
	if (jbuf != NULL) {                                                                           \
		free(jbuf);                                                                               \
	}                                                                                             \
	jbuf = NULL;                                                                                  \
	jlen = 0;                                                                                     \
	read_file_whole(NULL, &pbin, &bsize);                                                         \
	blen = 0;                                                                                     \
	SETERRNO(ret);                                                                                \
	return ret;                                                                                   \
}while(0)
