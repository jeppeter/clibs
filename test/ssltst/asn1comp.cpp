
int set_asn1_bmpstr(ASN1_BMPSTRING **ppbmpstr, const char* key, jvalue* pj)
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
	ASN1_OBJECT* pnobj=NULL;
	jvalue* curval = NULL;
	unsigned char* pbuf = NULL;
	void* bptr=NULL;
	int bval;
	int ret;
	int error;
	uint64_t num;
	ASN1_STRING* pstr = NULL;
	char* pendptr=NULL;

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
		ret = ASN1_TYPE_set1(pat,itype,NULL);
	} else if (strcmp(stype, "object") == 0) {
		itype = V_ASN1_OBJECT;
	try_object:
		ret = set_asn1_object(&pnobj,"value",ptype);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret == 0) {
			ret = -EINVAL;
			ERROR_INFO("[%s].[value] get error",key);
			goto fail;
		}

		ret=  ASN1_TYPE_set1(pat,itype,pnobj);
	} else {
		/*now to copy the value*/
		ret = parse_number((char*)stype, &num, &pendptr);
		if (ret < 0) {
			ret = -EINVAL;
			ERROR_INFO("[%s] not valid for type ", stype);
			goto fail;
		}
		itype = (int)num;
		if (itype == V_ASN1_OBJECT) {
			goto try_object;
		}
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
	ASN1_BMPSTRING* pbmpstr = NULL;
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
	jvalue *pinsert=NULL;
	ASN1_TYPE* at;
	int bval;
	ASN1_OBJECT* pnobj=NULL;
	int i;
	int ret;
	unsigned char *pbuf=NULL;
	int buflen=0;
	int setted = 0;
	int error;
	int typ;
	ASN1_INTEGER* pinteger=NULL;
	ASN1_STRING* pstr=NULL;
	char* typestr = NULL;
	int typesize=0;
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
		ERROR_INFO("create [%s] insert error[%d]", key,ret);
		goto fail;
	}
	if (typ == V_ASN1_OBJECT) {
		ret = jobject_put_string(pinsert,"type","object");
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
		ret = get_asn1_object(&pnobj,"value",pinsert);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret == 0) {
			ret=  -EINVAL;
			ERROR_INFO("no [%s] value for object",key);
			goto fail;
		}

	} else if (typ == V_ASN1_NULL) {
		ret = jobject_put_string(pinsert,"type","null");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] type null error[%d]", key, ret);
			goto fail;
		}
	} else if (typ == V_ASN1_BOOLEAN) {
		ret = jobject_put_string(pinsert,"type","bool");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] type null error[%d]", key, ret);
			goto fail;
		}
		bval = at->value.boolean;
		ret = jobject_put_bool(pinsert,"value",bval);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s] value bool error[%d]", key,ret);
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
		ret = snprintf_safe(&typestr,&typesize,"0x%x", typ);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = jobject_put_string(pinsert,"type",typestr);
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

		for(i=0;i<buflen;i++) {
			ASSERT_IF(curval == NULL);
			curval = jint_create(pbuf[i]);
			if (curval == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = jarray_put(parr,curval);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put [%d] [0x%02x] error[%d]", i,pbuf[i],ret);
				goto fail;
			}
			/*all is insert*/
			curval = NULL;
		}

		error = 0;
		retpj = jobject_put(pinsert,"data",parr,&error);
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
	retpj = jobject_put(pj,"value",pinsert,&error);
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

	snprintf_safe(&typestr,&typesize,NULL);

	return setted;
fail:	
	snprintf_safe(&typestr,&typesize,NULL);
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
