
/* some structures needed for the asn1 encoding */
typedef struct x9_62_pentanomial_st {
	int32_t k1;
	int32_t k2;
	int32_t k3;
} X9_62_PENTANOMIAL;

typedef struct x9_62_characteristic_two_st {
	int32_t m;
	ASN1_OBJECT *type;
	union {
		char *ptr;
		/* NID_X9_62_onBasis */
		ASN1_NULL *onBasis;
		/* NID_X9_62_tpBasis */
		ASN1_INTEGER *tpBasis;
		/* NID_X9_62_ppBasis */
		X9_62_PENTANOMIAL *ppBasis;
		/* anything else */
		ASN1_TYPE *other;
	} p;
} X9_62_CHARACTERISTIC_TWO;

typedef struct x9_62_fieldid_st {
	ASN1_OBJECT *fieldType;
	union {
		char *ptr;
		/* NID_X9_62_prime_field */
		ASN1_INTEGER *prime;
		/* NID_X9_62_characteristic_two_field */
		X9_62_CHARACTERISTIC_TWO *char_two;
		/* anything else */
		ASN1_TYPE *other;
	} p;
} X9_62_FIELDID;

typedef struct x9_62_curve_st {
	ASN1_OCTET_STRING *a;
	ASN1_OCTET_STRING *b;
	ASN1_BIT_STRING *seed;
} X9_62_CURVE;

struct ec_parameters_st {
	int32_t version;
	X9_62_FIELDID *fieldID;
	X9_62_CURVE *curve;
	ASN1_OCTET_STRING *base;
	ASN1_INTEGER *order;
	ASN1_INTEGER *cofactor;
} /* ECPARAMETERS */ ;

typedef enum {
	ECPKPARAMETERS_TYPE_NAMED = 0,
	ECPKPARAMETERS_TYPE_EXPLICIT,
	ECPKPARAMETERS_TYPE_IMPLICIT
} ecpk_parameters_type_t;

struct ecpk_parameters_st {
	int type;
	union {
		ASN1_OBJECT *named_curve;
		ECPARAMETERS *parameters;
		ASN1_NULL *implicitlyCA;
	} value;
} /* ECPKPARAMETERS */ ;

/* SEC1 ECPrivateKey */
typedef struct ec_privatekey_st {
	int32_t version;
	ASN1_OCTET_STRING *privateKey;
	ECPKPARAMETERS *parameters;
	ASN1_BIT_STRING *publicKey;
} EC_PRIVATEKEY;

/* the OpenSSL ASN.1 definitions */
ASN1_SEQUENCE(X9_62_PENTANOMIAL) = {
	ASN1_EMBED(X9_62_PENTANOMIAL, k1, INT32),
	ASN1_EMBED(X9_62_PENTANOMIAL, k2, INT32),
	ASN1_EMBED(X9_62_PENTANOMIAL, k3, INT32)
} static_ASN1_SEQUENCE_END(X9_62_PENTANOMIAL)

DECLARE_ASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)

ASN1_ADB_TEMPLATE(char_two_def) = ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.other, ASN1_ANY);

ASN1_ADB(X9_62_CHARACTERISTIC_TWO) = {
	ADB_ENTRY(NID_X9_62_onBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.onBasis, ASN1_NULL)),
	ADB_ENTRY(NID_X9_62_tpBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.tpBasis, ASN1_INTEGER)),
	ADB_ENTRY(NID_X9_62_ppBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.ppBasis, X9_62_PENTANOMIAL))
} ASN1_ADB_END(X9_62_CHARACTERISTIC_TWO, 0, type, 0, &char_two_def_tt, NULL);

ASN1_SEQUENCE(X9_62_CHARACTERISTIC_TWO) = {
	ASN1_EMBED(X9_62_CHARACTERISTIC_TWO, m, INT32),
	ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, type, ASN1_OBJECT),
	ASN1_ADB_OBJECT(X9_62_CHARACTERISTIC_TWO)
} static_ASN1_SEQUENCE_END(X9_62_CHARACTERISTIC_TWO)

DECLARE_ASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)

ASN1_ADB_TEMPLATE(fieldID_def) = ASN1_SIMPLE(X9_62_FIELDID, p.other, ASN1_ANY);

ASN1_ADB(X9_62_FIELDID) = {
	ADB_ENTRY(NID_X9_62_prime_field, ASN1_SIMPLE(X9_62_FIELDID, p.prime, ASN1_INTEGER)),
	ADB_ENTRY(NID_X9_62_characteristic_two_field, ASN1_SIMPLE(X9_62_FIELDID, p.char_two, X9_62_CHARACTERISTIC_TWO))
} ASN1_ADB_END(X9_62_FIELDID, 0, fieldType, 0, &fieldID_def_tt, NULL);

ASN1_SEQUENCE(X9_62_FIELDID) = {
	ASN1_SIMPLE(X9_62_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_ADB_OBJECT(X9_62_FIELDID)
} static_ASN1_SEQUENCE_END(X9_62_FIELDID)

ASN1_SEQUENCE(X9_62_CURVE) = {
	ASN1_SIMPLE(X9_62_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(X9_62_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(X9_62_CURVE, seed, ASN1_BIT_STRING)
} static_ASN1_SEQUENCE_END(X9_62_CURVE)

ASN1_SEQUENCE(ECPARAMETERS) = {
	ASN1_EMBED(ECPARAMETERS, version, INT32),
	ASN1_SIMPLE(ECPARAMETERS, fieldID, X9_62_FIELDID),
	ASN1_SIMPLE(ECPARAMETERS, curve, X9_62_CURVE),
	ASN1_SIMPLE(ECPARAMETERS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECPARAMETERS, order, ASN1_INTEGER),
	ASN1_OPT(ECPARAMETERS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ECPARAMETERS)

DECLARE_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)

ASN1_CHOICE(ECPKPARAMETERS) = {
	ASN1_SIMPLE(ECPKPARAMETERS, value.named_curve, ASN1_OBJECT),
	ASN1_SIMPLE(ECPKPARAMETERS, value.parameters, ECPARAMETERS),
	ASN1_SIMPLE(ECPKPARAMETERS, value.implicitlyCA, ASN1_NULL)
} ASN1_CHOICE_END(ECPKPARAMETERS)

DECLARE_ASN1_FUNCTIONS(ECPKPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(ECPKPARAMETERS, ECPKPARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS(ECPKPARAMETERS)

ASN1_SEQUENCE(EC_PRIVATEKEY) = {
	ASN1_EMBED(EC_PRIVATEKEY, version, INT32),
	ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
	ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
	ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
} static_ASN1_SEQUENCE_END(EC_PRIVATEKEY)

DECLARE_ASN1_FUNCTIONS(EC_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(EC_PRIVATEKEY, EC_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS(EC_PRIVATEKEY)

int encode_X9_62_PENTANOMIAL(jvalue* pj, X9_62_PENTANOMIAL* pobj)
{
	int ret;
	int setted = 0;

	ret = set_asn1_int32(&(pobj->k1),"k1",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set k1 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_int32(&(pobj->k2),"k2",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set k2 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}


	ret = set_asn1_int32(&(pobj->k3),"k3",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set k3 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_X9_62_PENTANOMIAL(X9_62_PENTANOMIAL* pobj, jvalue* pj)
{
	int ret;
	int setted = 0;

	ret = get_asn1_int32(&(pobj->k1),"k1",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get k1 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_int32(&(pobj->k2),"k2",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get k2 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}


	ret = get_asn1_int32(&(pobj->k3),"k3",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get k3 error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

#define  X962_ONBASIS_OBJ               "1.2.840.10045.1.2.3.1"
#define  X962_ONBASIS_STR               ""

#define  X962_TPBASIS_OBJ               "1.2.840.10045.1.2.3.2"
#define  X962_TPBASIS_STR               ""

#define  X962_PPBASIS_OBJ               "1.2.840.10045.1.2.3.3"
#define  X962_PPBASIS_STR               ""

int encode_X9_62_CHARACTERISTIC_TWO(jvalue* pj, X9_62_CHARACTERISTIC_TWO* pobj)
{
	int ret;
	const char* otype=NULL;
	int error;
	jvalue* chldpj = NULL;

	ret = set_asn1_int32(&(pobj->m),"m",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set m error[%d]", ret);
		goto fail;
	}

	ret = set_asn1_object(&(pobj->type),"type",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("set type error[%d]", ret);
		goto fail;
	}

	otype = jobject_get_string(pj,"type",&error);
	if (otype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("no type");
		goto fail;
	}

	if (strcmp(otype,X962_ONBASIS_OBJ) == 0) {
		if (pobj->p.onBasis != NULL) {
			ret = -EINVAL;
			ERROR_INFO("onBasis already");
			goto fail;
		}
		pobj->p.onBasis = ASN1_NULL_new();
		if (pobj->p.onBasis == NULL) {
			GETERRNO(ret);
			ERROR_INFO("ASN1_NULL_new error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype,X962_TPBASIS_OBJ) == 0) {
		if (pobj->p.tpBasis != NULL) {
			ret = -EINVAL;
			ERROR_INFO("tpBasis already");
			goto fail;
		}
		ret = set_asn1_integer(&(pobj->p.tpBasis),"tpbasis",pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("set tpbasis error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype,X962_PPBASIS_OBJ) == 0) {
		chldpj = jobject_get(pj,"ppbasis");
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("no ppbasis");
			goto fail;
		}
		if (pobj->p.ppBasis != NULL) {
			ret = -EINVAL;
			ERROR_INFO("ppbasis already");
			goto fail;
		}
		pobj->p.ppBasis = X9_62_PENTANOMIAL_new();
		if (pobj->p.ppBasis == NULL) {
			GETERRNO(ret);
			ERROR_INFO("X9_62_PENTANOMIAL_new error[%d]", ret);
			goto fail;
		}
		ret = encode_X9_62_PENTANOMIAL(chldpj,pobj->p.ppBasis);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		if(pobj->p.other != NULL) {
			ret = -EINVAL;
			ERROR_INFO("other already");
			goto fail;
		}
		ret = set_asn1_any(&(pobj->p.other),"other",pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("other error[%d]", ret);
			goto fail;
		}
	}


	return 1;
fail:
	SETERRNO(ret);
	return ret;
}


int decode_X9_62_CHARACTERISTIC_TWO(X9_62_CHARACTERISTIC_TWO* pobj, jvalue* pj)
{
	int ret;
	int error;
	jvalue* chldpj = NULL, *replpj= NULL;
	const char* otype = NULL;

	ret = get_asn1_int32(&(pobj->m),"m",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("get m error[%d]", ret);
		goto fail;
	}

	ret = get_asn1_object(&(pobj->type),"type",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("get type error[%d]", ret);
		goto fail;
	}

	otype = jobject_get_string(pj,"type",&error);
	if (otype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("no type get");
		goto fail;
	}

	DEBUG_INFO("otype [%s]", otype);
	if (strcmp(otype,X962_ONBASIS_OBJ) == 0 || 
		strcmp(otype,X962_ONBASIS_STR) == 0) {
		ret = jobject_put_null(pj,"onbasis");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put onbasis error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype, X962_TPBASIS_OBJ) == 0 ||
		strcmp(otype, X962_TPBASIS_STR) == 0) {
		ret = get_asn1_integer(&(pobj->p.tpBasis),"tpbasis",pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("put tpbasis error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype, X962_PPBASIS_OBJ) == 0 || 
		strcmp(otype, X962_PPBASIS_STR) == 0) {
		ASSERT_IF(chldpj == NULL);
		ASSERT_IF(replpj == NULL);
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("ppbasis object create error[%d]", ret);
			goto fail;
		}
		if (pobj->p.ppBasis == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no ppBasis");
			goto fail;
		}
		ret = decode_X9_62_PENTANOMIAL(pobj->p.ppBasis,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		replpj = jobject_put(pj,"ppbasis",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put ppbasis error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj != NULL) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
	} else {
		ret = get_asn1_any(&(pobj->p.other),"other",pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("put other error[%d]", ret);
			goto fail;
		}
	}

	return 1;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (replpj != NULL) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	SETERRNO(ret);
	return ret;
}

#define X962_PRIME_FIELD_OBJ               "1.2.840.10045.1.1"
#define X962_PRIME_FIELD_STR               "prime-field"

#define X962_CHAR_TWO_FIELD_OBJ            "1.2.840.10045.1.2"
#define X962_CHAR_TWO_FIELD_STR            "char-two-field"


int encode_X9_62_FIELDID(jvalue* pj, X9_62_FIELDID* pobj)
{
	int ret;
	const char* otype=NULL;
	jvalue* chldpj = NULL;
	int error;

	ret = set_asn1_object(&(pobj->fieldType),"fieldtype",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("set fieldtype error[%d]", ret);
		goto fail;
	}

	otype = jobject_get_string(pj,"fieldtype",&error);
	if (otype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("fieldtype error[%d]", ret);
		goto fail;
	}

	if (strcmp(otype,X962_PRIME_FIELD_OBJ) == 0) {
		ret = set_asn1_integer(&(pobj->p.prime),"prime",pj);
		if (ret <= 0 ) {
			GETERRNO(ret);
			ERROR_INFO("set prime error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype,X962_CHAR_TWO_FIELD_OBJ) == 0) {
		chldpj= jobject_get(pj,"tow_field");
		if (chldpj != NULL) {
			if (pobj->p.char_two != NULL) {
				ret = -EINVAL;
				ERROR_INFO("char_tow already set");
				goto fail;
			}
			pobj->p.char_two = X9_62_CHARACTERISTIC_TWO_new();
			if (pobj->p.char_two == NULL) {
				GETERRNO(ret);
				ERROR_INFO("X9_62_CHARACTERISTIC_TWO_new error[%d]" ,ret);
				goto fail;
			}

			ret = encode_X9_62_CHARACTERISTIC_TWO(chldpj,pobj->p.char_two);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		} else {
			ret = -EINVAL;
			ERROR_INFO("no tow_field");
			goto fail;
		}
	} else {
		ret = set_asn1_any(&(pobj->p.other),"other",pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("set other error[%d]", ret);
			goto fail;
		}
	}



	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_X9_62_FIELDID(X9_62_FIELDID* pobj, jvalue* pj)
{
	int ret;
	int error;
	const char* otype = NULL;
	jvalue* chldpj = NULL;
	jvalue* replpj = NULL;

	ret = get_asn1_object(&(pobj->fieldType),"fieldtype",pj);
	if (ret <=0 ) {
		GETERRNO(ret);
		ERROR_INFO("get fieldtype error[%d]", ret);
		goto fail;
	}

	error = 0;
	otype = jobject_get_string(pj,"fieldtype",&error);
	if (otype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("get fieldtype error[%d]", ret);
		goto fail;
	}

	DEBUG_INFO("otype [%s]", otype);
	if (strcmp(otype,X962_PRIME_FIELD_OBJ) == 0) {
		if (pobj->p.prime == NULL) {
			ret = -EINVAL;
			ERROR_INFO("[%s] for prime null", otype);
			goto fail;
		}
		ret = get_asn1_integer(&(pobj->p.prime),"prime",pj);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("get prime error[%d]", ret);
			goto fail;
		}
	} else if (strcmp(otype,X962_CHAR_TWO_FIELD_OBJ) == 0) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("char_two object create error[%d]", ret);
			goto fail;
		}
		if (pobj->p.char_two == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no char_two");
			goto fail;
		}
		ret = decode_X9_62_CHARACTERISTIC_TWO(pobj->p.char_two,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		replpj = jobject_put(pj,"char_two",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put char_two error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj != NULL) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
	} else {
		if (pobj->p.other == NULL) {
			ret = -EINVAL;
			ERROR_INFO("[%s] for other null", otype);
			goto fail;
		}
		ret = get_asn1_any(&(pobj->p.other),"other",pj);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("get other error[%d]", ret);
			goto fail;
		}
	}

	return 1;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (replpj != NULL) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_X9_62_CURVE(jvalue* pj, X9_62_CURVE* pobj)
{
	int ret;
	int setted = 0;

	ret = set_asn1_octdata(&(pobj->a),"a",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set a error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_octdata(&(pobj->b),"b",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set b error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_bitdata(&(pobj->seed),"seed",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set seed error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_X9_62_CURVE(X9_62_CURVE* pobj, jvalue* pj)
{
	int ret;
	int setted = 0;

	ret = get_asn1_octdata(&(pobj->a),"a",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get a error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_octdata(&(pobj->b),"b",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get b error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_bitdata(&(pobj->seed),"seed",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get seed error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}


	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_ECPARAMETERS(jvalue* pj, ECPARAMETERS* pobj)
{
	int ret;
	int setted = 0;
	jvalue* chldpj = NULL;

	ret = set_asn1_int32(&(pobj->version), "version", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	chldpj = jobject_get(pj, "fieldid");
	if (chldpj != NULL) {
		if (pobj->fieldID == NULL) {
			pobj->fieldID = (X9_62_FIELDID*)malloc(sizeof(*(pobj->fieldID)));
			if (pobj->fieldID == NULL) {
				GETERRNO(ret);
				ERROR_INFO("X9_62_FIELDID_new error[%d]", ret);
				goto fail;
			}
			memset(pobj->fieldID, 0, sizeof(*pobj->fieldID));
		}
		ret = encode_X9_62_FIELDID(chldpj, pobj->fieldID);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		setted = 1;
	}

	chldpj = jobject_get(pj, "curve");
	if (chldpj != NULL) {
		if (pobj->curve == NULL) {
			pobj->curve = (X9_62_CURVE*) malloc(sizeof(X9_62_CURVE));
			if (pobj->curve == NULL) {
				GETERRNO(ret);
				ERROR_INFO("X9_62_CURVE_new error[%d]", ret);
				goto fail;
			}
			memset(pobj->curve, 0, sizeof(X9_62_CURVE));
		}
		ret = encode_X9_62_CURVE(chldpj, pobj->curve);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		setted = 1;
	}

	ret = set_asn1_octdata(&(pobj->base), "base", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set base error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_integer(&(pobj->order), "order", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set order error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_integer(&(pobj->cofactor), "cofactor", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set cofactor error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;

fail:
	SETERRNO(ret);
	return ret;
}

int decode_ECPARAMETERS(ECPARAMETERS* pobj, jvalue* pj)
{
	int ret;
	int error;
	jvalue* chldpj = NULL;
	jvalue* replpj = NULL;
	int setted = 0;

	ret = get_asn1_int32(&(pobj->version), "version", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	if (pobj->fieldID != NULL) {
		ASSERT_IF(chldpj == NULL);
		ASSERT_IF(replpj == NULL);
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("fieldid object create error[%d]", ret);
			goto fail;
		}

		ret = decode_X9_62_FIELDID(pobj->fieldID, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		replpj = jobject_put(pj, "fieldid", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put fieldid error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj != NULL) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
		setted = 1;
	}

	if (pobj->curve != NULL) {
		ASSERT_IF(chldpj == NULL);
		ASSERT_IF(replpj == NULL);
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("curve object create error[%d]", ret);
			goto fail;
		}

		ret = decode_X9_62_CURVE(pobj->curve, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		replpj = jobject_put(pj, "curve", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put curve error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj != NULL) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
		setted = 1;
	}

	ret = get_asn1_octdata(&(pobj->base), "base", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get base error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_integer(&(pobj->order), "order", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get order error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_integer(&(pobj->cofactor), "cofactor", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get cofactor error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (replpj != NULL) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	SETERRNO(ret);
	return ret;
}


int encode_ECPKPARAMETERS(jvalue* pj, ECPKPARAMETERS* pobj)
{
	int type = -1;
	int ret;
	jvalue* chldpj = NULL;
	int error;


	ret = set_asn1_object(&(pobj->value.named_curve), "named_curve", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set named_curve error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		type = ECPKPARAMETERS_TYPE_NAMED;
	}

	if (type < 0) {
		chldpj = jobject_get(pj, "parameters");
		if (chldpj != NULL) {
			if (pobj->value.parameters != NULL) {
				ret = -EINVAL;
				ERROR_INFO("already set parameters");
				goto fail;
			}
			pobj->value.parameters = ECPARAMETERS_new();
			if (pobj->value.parameters == NULL) {
				GETERRNO(ret);
				ERROR_INFO("ECPARAMETERS_new error[%d]", ret);
				goto fail;
			}

			ret = encode_ECPARAMETERS(chldpj, pobj->value.parameters);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = ECPKPARAMETERS_TYPE_EXPLICIT;
		}
	}

	if (type < 0) {
		error = 0;
		jobject_get_null(pj, "implicitlyca", &error);
		if (error == 0) {
			if (pobj->value.implicitlyCA != NULL) {
				GETERRNO(ret);
				ERROR_INFO("implicitlyCA already set");
				goto fail;
			}
			pobj->value.implicitlyCA = ASN1_NULL_new();
			if (pobj->value.implicitlyCA == NULL) {
				GETERRNO(ret);
				ERROR_INFO("ASN1_NULL_new error[%d]", ret);
				goto fail;
			}
			type = ECPKPARAMETERS_TYPE_IMPLICIT;
		}
	}

	if (type < 0) {
		ret = -EINVAL;
		ERROR_INFO("no type set");
		goto fail;
	}

	pobj->type = type;
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_ECPKPARAMETERS(ECPKPARAMETERS* pobj, jvalue* pj)
{
	int ret;
	jvalue* chldpj = NULL;
	jvalue* replpj = NULL;
	int error;
	if (pobj->type == ECPKPARAMETERS_TYPE_NAMED) {
		ret = get_asn1_object(&(pobj->value.named_curve), "named_curve", pj);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("set named_curve error[%d]", ret);
			goto fail;
		}
	} else if (pobj->type == ECPKPARAMETERS_TYPE_EXPLICIT) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("parameters object create error[%d]", ret);
			goto fail;
		}
		if (pobj->value.parameters == NULL) {
			ret = -EINVAL;
			ERROR_INFO("parameters null");
			goto fail;
		}
		ret = decode_ECPARAMETERS(pobj->value.parameters, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		replpj = jobject_put(pj, "parameters", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("set parameters error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
	} else if (pobj->type == ECPKPARAMETERS_TYPE_IMPLICIT) {
		ret = jobject_put_null(pj, "implicitlyca");
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("set implicitlyca error[%d]" , ret);
			goto fail;
		}
	} else {
		ret = -EINVAL;
		ERROR_INFO("not valid type [%d]" , pobj->type);
		goto fail;
	}

	return 1;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (replpj != NULL) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	SETERRNO(ret);
	return ret;
}


int encode_EC_PRIVATEKEY(jvalue* pj, EC_PRIVATEKEY* pobj)
{
	int ret;
	jvalue* chldpj = NULL;
	int setted = 0;

	ret = set_asn1_int32(&(pobj->version), "version", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_octdata(&(pobj->privateKey), "privatekey", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set privatekey error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	chldpj = jobject_get(pj, "parameters");
	if (chldpj != NULL) {
		if (pobj->parameters == NULL) {
			pobj->parameters = ECPKPARAMETERS_new();
			if (pobj->parameters == NULL) {
				GETERRNO(ret);
				ERROR_INFO("ECPKPARAMETERS_new error[%d]" , ret);
				goto fail;
			}
		}

		ret = encode_ECPKPARAMETERS(chldpj, pobj->parameters);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		setted = 1;
	}

	ret = set_asn1_bitdata(&(pobj->publicKey), "publickey", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set publickey error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_EC_PRIVATEKEY(EC_PRIVATEKEY* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* replpj = NULL;
	int setted = 0;
	int error;

	ret = get_asn1_int32(&(pobj->version), "version", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_octdata(&(pobj->privateKey), "privatekey", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get privatekey error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	if (pobj->parameters != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("parameters object create error[%d]", ret);
			goto fail;
		}

		ret = decode_ECPKPARAMETERS(pobj->parameters, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		replpj = jobject_put(pj, "parameters", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put parameters error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (replpj != NULL) {
			jvalue_destroy(replpj);
		}
		replpj = NULL;
		setted = 1;
	}

	ret =  get_asn1_bitdata(&(pobj->publicKey), "publickey", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get publickey error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	return setted;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (replpj != NULL) {
		jvalue_destroy(replpj);
	}
	replpj = NULL;
	SETERRNO(ret);
	return ret;
}


int ecprivkeyenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(EC_PRIVATEKEY);
}
int ecprivkeydec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(EC_PRIVATEKEY);
}

int ecpkparamsenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(ECPKPARAMETERS);
}
int ecpkparamsdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(ECPKPARAMETERS);
}
