
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


int encode_EC_PRIVATEKEY(jvalue* pj, EC_PRIVATEKEY* pobj)
{
	int ret;
	jvalue* chldpj = NULL;
	int setted = 0;

	ret = set_asn1_int32(&(pobj->version),"version",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = set_asn1_octdata(&(pobj->privateKey),"privatekey",pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set privatekey error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	chldpj = jobject_get(pj,"parameters");
	if (chldpj != NULL) {
		if (pobj->parameters == NULL) {
			pobj->parameters = ECPKPARAMETERS_new();
			if (pobj->parameters == NULL) {
				GETERRNO(ret);
				ERROR_INFO("ECPKPARAMETERS_new error[%d]" , ret);
				goto fail;
			}
		}

		ret = encode_ECPKPARAMETERS(chldpj,pobj->parameters);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		setted = 1;
	}

	ret = set_asn1_bitdata(&(pobj->publicKey),"publickey",pj);
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

	ret = get_asn1_int32(&(pobj->version),"version", pj);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("get version error[%d]", ret);
		goto fail;
	} else if (ret > 0) {
		setted = 1;
	}

	ret = get_asn1_octdata(&(pobj->privateKey),"privatekey",pj);
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
		replpj = jobject_put(pj,"parameters",chldpj, &error);
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

	ret=  get_asn1_bitdata(&(pobj->publicKey),"publickey", pj);
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

