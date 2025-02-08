


struct x509_cert_aux_exp_st {
    STACK_OF(ASN1_OBJECT) *trust; /* trusted uses */
    STACK_OF(ASN1_OBJECT) *reject; /* rejected uses */
    ASN1_UTF8STRING *alias;     /* "friendly name" */
    ASN1_OCTET_STRING *keyid;   /* key id of private key */
    STACK_OF(X509_ALGOR) *other; /* other unspecified info */
};

typedef struct x509_cert_aux_exp_st X509_CERT_AUX_EXP;

STACK_OF(X509_ALGOR)* sk_X509_ALGRO_new_null();

ASN1_SEQUENCE(X509_CERT_AUX_EXP) = {
        ASN1_SEQUENCE_OF_OPT(X509_CERT_AUX_EXP, trust, ASN1_OBJECT),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX_EXP, reject, ASN1_OBJECT, 0),
        ASN1_OPT(X509_CERT_AUX_EXP, alias, ASN1_UTF8STRING),
        ASN1_OPT(X509_CERT_AUX_EXP, keyid, ASN1_OCTET_STRING),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX_EXP, other, X509_ALGOR, 1)
} ASN1_SEQUENCE_END(X509_CERT_AUX_EXP)

IMPLEMENT_ASN1_FUNCTIONS(X509_CERT_AUX_EXP)


int encode_X509_ALGOR(jvalue* pj,X509_ALGOR*pobj)
{
	int ret;
	ret = set_asn1_object(&(pobj->algorithm),"algorithm",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_any(&(pobj->parameter),"parameter",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}


int decode_X509_ALGOR(X509_ALGOR*pobj, jvalue* pj)
{
	int ret;
	ret = get_asn1_object(&(pobj->algorithm),"algorithm",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_any(&(pobj->parameter),"parameter",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_X509_CERT_AUX_EXP(jvalue* pj,X509_CERT_AUX_EXP* pobj)
{
	jvalue* chldarr =NULL;
	jvalue* chldpj=NULL;
	int ret;
	int err;
	unsigned int arrsize,i;
	int setted = 0;
	ASN1_OBJECT* casn1obj=NULL;
	jvalue* dummypj=NULL;
	X509_ALGOR* calgor=NULL;
	chldarr = (jvalue*)jobject_get_array(pj,"trust",&err);
	if (chldarr != NULL) {
		arrsize = jarray_size(chldarr);
		if (pobj->trust == NULL) {
			pobj->trust = sk_ASN1_OBJECT_new_null();
			if (pobj->trust == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		dummypj = jobject_create();
		if (dummypj == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		for(i=0;i<arrsize;i++) {
			jvalue* cpj=NULL;
			jstring* pjstr =NULL;
			ASSERT_IF(casn1obj == NULL);
			cpj = jarray_get(chldarr,i,&err);
			if (cpj == NULL || cpj->type != JSTRING) {
				GETERRNO(ret);
				ERROR_INFO("get [%d] error",i);
				goto fail;
			}
			pjstr = (jstring*)cpj;
	
			ret = jobject_put_string(dummypj,"dummy",pjstr->value);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put dummy object error");
				goto fail;
			}

			ret = set_asn1_object(&casn1obj,"dummy",dummypj);
			if (ret <= 0) {
				GETERRNO(ret);
				goto fail;
			}

			sk_ASN1_OBJECT_push(pobj->trust,casn1obj);
			casn1obj = NULL;
		}
		setted += 1;
	}

	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;

	chldarr = (jvalue*)jobject_get_array(pj,"reject",&ret);
	if (chldarr != NULL) {
		arrsize = jarray_size(chldarr);
		if (pobj->reject == NULL) {
			pobj->reject = sk_ASN1_OBJECT_new_null();
			if (pobj->reject == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		dummypj = jobject_create();
		if (dummypj == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		for(i=0;i<arrsize;i++) {
			jvalue* cpj=NULL;
			jstring* pjstr =NULL;
			ASSERT_IF(casn1obj == NULL);
			cpj = jarray_get(chldarr,i,&err);
			if (cpj == NULL || cpj->type != JSTRING) {
				GETERRNO(ret);
				ERROR_INFO("get [%d] error",i);
				goto fail;
			}
			pjstr = (jstring*)cpj;
	
			ret = jobject_put_string(dummypj,"dummy",pjstr->value);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put dummy object error");
				goto fail;
			}

			ret = set_asn1_object(&casn1obj,"dummy",dummypj);
			if (ret <= 0) {
				GETERRNO(ret);
				goto fail;
			}

			sk_ASN1_OBJECT_push(pobj->reject,casn1obj);
			casn1obj = NULL;
		}
		setted += 1;
	}

	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;


	ret = set_asn1_utfstr(&pobj->alias,"alias",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_octdata(&pobj->keyid,"keyid",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;		
	}

	chldarr = (jvalue*)jobject_get_array(pj,"other",&err);
	if (chldarr != NULL) {
		arrsize = jarray_size(chldarr);
		if (pobj->other == NULL) {
			pobj->other = sk_X509_ALGOR_new_null();
			if (pobj->other == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}
		for(i=0;i<arrsize;i++) {

			ASSERT_IF(calgor == NULL);
			chldpj = jarray_get(chldarr,i,&err);
			if (chldpj == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not get [%d]",i);
				goto fail;
			}

			ASSERT_IF(calgor == NULL);
			calgor = X509_ALGOR_new();
			if (calgor == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = encode_X509_ALGOR(chldpj,calgor);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			sk_X509_ALGOR_push(pobj->other,calgor);
			calgor = NULL;

		}
		setted += 1;
	}


	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;

	return setted;
fail:
	if (calgor) {
		X509_ALGOR_free(calgor);
	}
	calgor = NULL;

	if (casn1obj) {
		ASN1_OBJECT_free(casn1obj);
	}
	casn1obj = NULL;

	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;

	SETERRNO(ret);
	return ret;
}

int x509auxenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(X509_CERT_AUX_EXP);
}

int decode_X509_CERT_AUX_EXP(X509_CERT_AUX_EXP* pobj, jvalue* pj)
{
	int ret;
	int err;
	jvalue* chldarr =NULL;
	jvalue* chldpj = NULL;
	unsigned int i,arrsize;
	jvalue* dummypj=NULL;
	int setted = 0;
	const char* ostr;
	if (pobj->trust) {
		chldarr = jarray_create();
		if (chldarr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		arrsize = sk_ASN1_OBJECT_num(pobj->trust);
		for(i=0;i<arrsize;i++) {
			ASN1_OBJECT* curobj = sk_ASN1_OBJECT_value(pobj->trust,i);
			if (curobj == NULL) {
				GETERRNO(ret);
				ERROR_INFO("get trust [%d] error",i);
				goto fail;
			}

			if (dummypj) {
				jvalue_destroy(dummypj);
			}
			dummypj = NULL;

			dummypj = jobject_create();
			if (dummypj == NULL) {
				GETERRNO(ret);
				goto fail;
			}


			ret = get_asn1_object(&curobj,"dummy",dummypj);
			if (ret <= 0) {
				GETERRNO(ret);
				goto fail;
			}

			ostr = jobject_get_string(dummypj,"dummy",&err);
			if (ostr == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not get string");
				goto fail;
			}

			ret = jarray_put_string(chldarr,ostr);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put string error");
				goto fail;
			}
		}

		ret = jobject_put_array(pj,"trust",chldarr);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldarr = NULL;
		setted += 1;
	}

	if (pobj->reject) {
		chldarr = jarray_create();
		if (chldarr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		arrsize = sk_ASN1_OBJECT_num(pobj->reject);
		for(i=0;i<arrsize;i++) {
			ASN1_OBJECT* curobj = sk_ASN1_OBJECT_value(pobj->reject,i);
			if (curobj == NULL) {
				GETERRNO(ret);
				ERROR_INFO("get reject [%d] error",i);
				goto fail;
			}

			if (dummypj) {
				jvalue_destroy(dummypj);
			}
			dummypj = NULL;

			dummypj = jobject_create();
			if (dummypj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = get_asn1_object(&curobj,"dummy",dummypj);
			if (ret <= 0) {
				GETERRNO(ret);
				goto fail;
			}

			ostr = jobject_get_string(dummypj,"dummy",&err);
			if (ostr == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not get string");
				goto fail;
			}

			ret = jarray_put_string(chldarr,ostr);
			if (ret != 0) {
				GETERRNO(ret);
				ERROR_INFO("put string error");
				goto fail;
			}
		}

		ret = jobject_put_array(pj,"reject",chldarr);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldarr = NULL;
		setted += 1;
	}


	ret = get_asn1_utfstr(&pobj->alias,"alias",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_octdata(&pobj->keyid,"keyid",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->other) {
		chldarr = jarray_create();
		if (chldarr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		arrsize = sk_X509_ALGOR_num(pobj->other);
		for(i=0;i<arrsize;i++) {
			X509_ALGOR* curobj = sk_X509_ALGOR_value(pobj->other,i);
			if (curobj == NULL) {
				GETERRNO(ret);
				ERROR_INFO("get reject [%d] error",i);
				goto fail;
			}

			ASSERT_IF(chldpj == NULL);
			chldpj = jobject_create();
			if (chldpj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = decode_X509_ALGOR(curobj,chldpj);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			ret = jarray_put_object(chldarr,chldpj);
			if (ret != 0) {
				GETERRNO(ret);
				goto fail;
			}
			chldpj = NULL;

		}

		ret = jobject_put_array(pj,"other",chldarr);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldarr = NULL;
		setted += 1;
	}

	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;
	return setted;
fail:
	if (dummypj) {
		jvalue_destroy(dummypj);
	}
	dummypj = NULL;
	if (chldarr) {
		jarray_destroy((jarray*)chldarr);
	}
	chldarr = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int x509auxdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(X509_CERT_AUX_EXP);
}
