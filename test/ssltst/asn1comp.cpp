
int set_asn1_bmpstr(ASN1_BMPSTRING **ppbmpstr,const char* key, jvalue* pj)
{
	const char* pstr = NULL;
	int error;
	int ret;
	int rlen;
	ASN1_BMPSTRING* pbmpstr = NULL;

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
	ret = ASN1_OCTET_STRING_set(pbmpstr, (unsigned char*)pstr, rlen);
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


int set_asn1_ia5str(ASN1_IA5STRING **ppia5,const char* key, jvalue* pj)
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

int get_asn1_bmpstr(ASN1_BMPSTRING** ppbmpstr, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_BMPSTRING* pbmpstr=NULL;
	if (ppbmpstr == NULL || *ppbmpstr == NULL) {
		DEBUG_INFO("no [%s] get", key);
		return 0;
	}

	pbmpstr = *ppbmpstr;


	pout = (const char*)ASN1_STRING_get0_data(pbmpstr);
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


int get_asn1_ia5str(ASN1_IA5STRING** ppia5, const char* key, jvalue* pj)
{
	int ret;
	const char* pout = NULL;
	int setted = 0;
	ASN1_IA5STRING* pia5str=NULL;
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