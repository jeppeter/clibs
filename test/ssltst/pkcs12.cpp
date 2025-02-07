
/* a sequence of these are used */
struct x509_attribute_exp_st {
    ASN1_OBJECT *object;
    STACK_OF(ASN1_TYPE) *set;
};

typedef  struct x509_attribute_exp_st X509_ATTRIBUTE_EXP;


ASN1_SEQUENCE(X509_ATTRIBUTE_EXP) = {
        ASN1_SIMPLE(X509_ATTRIBUTE_EXP, object, ASN1_OBJECT),
        ASN1_SET_OF(X509_ATTRIBUTE_EXP, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE_EXP)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE_EXP)
//IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE_EXP)
DEFINE_STACK_OF(X509_ATTRIBUTE_EXP)



struct X509_sig_exp_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};
typedef struct X509_sig_exp_st X509_SIG_EXP;


ASN1_SEQUENCE(X509_SIG_EXP) = {
        ASN1_SIMPLE(X509_SIG_EXP, algor, X509_ALGOR),
        ASN1_SIMPLE(X509_SIG_EXP, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_SIG_EXP)

IMPLEMENT_ASN1_FUNCTIONS(X509_SIG_EXP)

struct pkcs8_priv_key_info_exp_st {
    ASN1_INTEGER *version;
    X509_ALGOR *pkeyalg;
    ASN1_OCTET_STRING *pkey;
    STACK_OF(X509_ATTRIBUTE_EXP) *attributes;
};

typedef struct pkcs8_priv_key_info_exp_st PKCS8_PRIV_KEY_INFO_EXP;

/* Minor tweak to operation: zero private key data */
static int pkey_exp_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    /* Since the structure must still be valid use ASN1_OP_FREE_PRE */
    if (operation == ASN1_OP_FREE_PRE) {
        PKCS8_PRIV_KEY_INFO_EXP *key = (PKCS8_PRIV_KEY_INFO_EXP *)*pval;
        if (key->pkey)
            OPENSSL_cleanse(key->pkey->data, key->pkey->length);
    }
    return 1;
}


ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO_EXP, pkey_exp_cb) = {
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO_EXP, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO_EXP, pkeyalg, X509_ALGOR),
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO_EXP, pkey, ASN1_OCTET_STRING),
        ASN1_IMP_SET_OF_OPT(PKCS8_PRIV_KEY_INFO_EXP, attributes, X509_ATTRIBUTE_EXP, 0)
} ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO_EXP, PKCS8_PRIV_KEY_INFO_EXP)

IMPLEMENT_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO_EXP)



struct pkcs12_bag_exp_st {
    ASN1_OBJECT *type;
    union {
        ASN1_OCTET_STRING *x509cert;
        ASN1_OCTET_STRING *x509crl;
        ASN1_OCTET_STRING *octet;
        ASN1_IA5STRING *sdsicert;
        ASN1_TYPE *other;       /* Secret or other bag */
    } value;
};

typedef struct pkcs12_bag_exp_st PKCS12_BAGS_EXP;


ASN1_ADB_TEMPLATE(bag_default_exp) = ASN1_EXP(PKCS12_BAGS_EXP, value.other, ASN1_ANY, 0);

ASN1_ADB(PKCS12_BAGS_EXP) = {
        ADB_ENTRY(NID_x509Certificate, ASN1_EXP(PKCS12_BAGS_EXP, value.x509cert, ASN1_OCTET_STRING, 0)),
        ADB_ENTRY(NID_x509Crl, ASN1_EXP(PKCS12_BAGS_EXP, value.x509crl, ASN1_OCTET_STRING, 0)),
        ADB_ENTRY(NID_sdsiCertificate, ASN1_EXP(PKCS12_BAGS_EXP, value.sdsicert, ASN1_IA5STRING, 0)),
} ASN1_ADB_END(PKCS12_BAGS_EXP, 0, type, 0, &bag_default_exp_tt, NULL);

ASN1_SEQUENCE(PKCS12_BAGS_EXP) = {
        ASN1_SIMPLE(PKCS12_BAGS_EXP, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(PKCS12_BAGS_EXP),
} ASN1_SEQUENCE_END(PKCS12_BAGS_EXP)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12_BAGS_EXP)


struct PKCS12_SAFEBAG_EXT_st {
    ASN1_OBJECT *type;
    union {
        PKCS12_BAGS_EXP *bag; /* secret, crl and certbag */
        PKCS8_PRIV_KEY_INFO_EXP *keybag; /* keybag */
        X509_SIG_EXP *shkeybag;     /* shrouded key bag */
        STACK_OF(PKCS12_SAFEBAG_EXP) *safes;
        ASN1_TYPE *other;
    } value;
    STACK_OF(X509_ATTRIBUTE_EXP) *attrib;
};

typedef struct PKCS12_SAFEBAG_EXT_st PKCS12_SAFEBAG_EXP;

ASN1_ADB_TEMPLATE(safebag_default_exp) = ASN1_EXP(PKCS12_SAFEBAG_EXP, value.other, ASN1_ANY, 0);

DECLARE_ASN1_ITEM(PKCS12_SAFEBAG_EXP)

ASN1_ADB(PKCS12_SAFEBAG_EXP) = {
        ADB_ENTRY(NID_keyBag, ASN1_EXP(PKCS12_SAFEBAG_EXP, value.keybag, PKCS8_PRIV_KEY_INFO_EXP, 0)),
        ADB_ENTRY(NID_pkcs8ShroudedKeyBag, ASN1_EXP(PKCS12_SAFEBAG_EXP, value.shkeybag, X509_SIG_EXP, 0)),
        ADB_ENTRY(NID_safeContentsBag, ASN1_EXP_SEQUENCE_OF(PKCS12_SAFEBAG_EXP, value.safes, PKCS12_SAFEBAG_EXP, 0)),
        ADB_ENTRY(NID_certBag, ASN1_EXP(PKCS12_SAFEBAG_EXP, value.bag, PKCS12_BAGS_EXP, 0)),
        ADB_ENTRY(NID_crlBag, ASN1_EXP(PKCS12_SAFEBAG_EXP, value.bag, PKCS12_BAGS_EXP, 0)),
        ADB_ENTRY(NID_secretBag, ASN1_EXP(PKCS12_SAFEBAG_EXP, value.bag, PKCS12_BAGS_EXP, 0))
} ASN1_ADB_END(PKCS12_SAFEBAG_EXP, 0, type, 0, &safebag_default_exp_tt, NULL);

ASN1_SEQUENCE(PKCS12_SAFEBAG_EXP) = {
        ASN1_SIMPLE(PKCS12_SAFEBAG_EXP, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(PKCS12_SAFEBAG_EXP),
        ASN1_SET_OF_OPT(PKCS12_SAFEBAG_EXP, attrib, X509_ATTRIBUTE_EXP)
} ASN1_SEQUENCE_END(PKCS12_SAFEBAG_EXP)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12_SAFEBAG_EXP)

DEFINE_STACK_OF(PKCS12_SAFEBAG_EXP)

// 1.2.840.113549.1.12.10.1.1
//#define KEY_BAG_OID                          "keybag"
#define KEY_BAG_OID                          "1.2.840.113549.1.12.10.1.1"
#define KEY_BAG_STR                          "keyBag"
#define SHROUDED_KEY_BAG_OID                 "shroudedkeybag"
#define SAFE_CONTENT_BAG_OID                 "safecontentbag"
#define CERT_BAG_OID                         "certbag"
#define CLR_BAG_OID                          "crlbag"
#define SECRET_BAG_OID                       "secretbag"


int encode_X509_ATTRIBUTE_EXP(jvalue* pj,X509_ATTRIBUTE_EXP* pobj)
{
	int ret;
	const jvalue* chldarr= NULL;
	jvalue* npj =NULL;	
	ASN1_TYPE* curset=NULL;
	unsigned int arrsize,i;
	int err;
	jvalue* chldpj=NULL;
	ret = set_asn1_object(&(pobj->object),"object",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldarr = (const jvalue*)jobject_get_array(pj,"set",&err);
	DEBUG_INFO("chldarr in X509_ATTRIBUTE_EXP %p",chldarr);
	if (chldarr != NULL) {
		DEBUG_INFO("chldarr %p",chldarr);
		if (pobj->set == NULL) {
			pobj->set = sk_ASN1_TYPE_new_null();
			if (pobj->set == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		arrsize = jarray_size(chldarr);
		for(i=0;i<arrsize;i++) {
			chldpj = jarray_get(chldarr,i,&err);
			if (chldpj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			if (npj != NULL) {
				jvalue_destroy(npj);
			}
			npj = NULL;
			if (chldpj->type != JOBJECT) {
				ret = -EINVAL;
				ERROR_INFO("set.[%d] not array type",i);
				goto fail;
			}
			npj = jobject_create();
			if (npj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = jobject_put_object(npj,"set",chldpj);
			if (ret != 0) {
				GETERRNO(ret);
				goto fail;
			}

			ASSERT_IF(curset == NULL);
			ret = set_asn1_any(&curset,"set",npj);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			sk_ASN1_TYPE_push(pobj->set,curset);
			curset = NULL;
		}
	}

	if (npj != NULL) {
		jvalue_destroy(npj);
	}
	npj = NULL;

	return 0;
fail:
	if (curset) {
		ASN1_TYPE_free(curset);
	}
	curset = NULL;

	if (npj != NULL) {
		jvalue_destroy(npj);
	}
	npj = NULL;

	SETERRNO(ret);
	return ret;
}

int encode_PKCS8_PRIV_KEY_INFO_EXP(jvalue* pj,PKCS8_PRIV_KEY_INFO_EXP* pobj)
{
	int ret;
	jvalue* chldpj= NULL;
	const jvalue* chldarr = NULL;
	X509_ATTRIBUTE_EXP* attrib=NULL;
	int err;
	unsigned int arrsize,i;
	ret = set_asn1_integer(&(pobj->version),"version",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("no version get");
		goto fail;
	}

	chldpj = jobject_get(pj,"keyalg");
	if (chldpj == NULL) {
		ret = -EINVAL;
		ERROR_INFO("no keyalg");
		goto fail;
	}

	if (pobj->pkeyalg == NULL) {
		pobj->pkeyalg = X509_ALGOR_new();
		if (pobj->pkeyalg == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ret = encode_X509_ALGOR(chldpj,pobj->pkeyalg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_octstr(&pobj->pkey,"key",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldarr = (const jvalue*)jobject_get_array(pj,"attributes",&err);
	DEBUG_INFO("attributes %p",chldarr);
	if (chldarr != NULL) {
		if (pobj->attributes == NULL) {
			pobj->attributes = sk_X509_ATTRIBUTE_EXP_new_null();
			if (pobj->attributes == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		arrsize = jarray_size(chldarr);
		for(i=0;i<arrsize;i++) {
			chldpj = jarray_get(chldarr,i,&err);
			if (chldpj == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not get attributes.[%d] ",i);
				goto fail;
			}

			ASSERT_IF(attrib == NULL);
			attrib = X509_ATTRIBUTE_EXP_new();
			if (attrib == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = encode_X509_ATTRIBUTE_EXP(chldpj,attrib);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			sk_X509_ATTRIBUTE_EXP_push(pobj->attributes,attrib);
			DEBUG_INFO("attributes %d",sk_X509_ATTRIBUTE_EXP_num(pobj->attributes));
			attrib = NULL;
		}
	}





	return 0;
fail:
	if(attrib != NULL) {
		X509_ATTRIBUTE_EXP_free(attrib);
	}
	attrib = NULL;

	SETERRNO(ret);
	return ret;
}

int encode_X509_SIG_EXP(jvalue* pj,X509_SIG_EXP* pobj)
{
	return 0;
}

int encode_PKCS12_BAGS_EXP(jvalue* pj,PKCS12_BAGS_EXP* pobj)
{
	return 0;
}


int encode_PKCS12_SAFEBAG_EXP(jvalue* pj, PKCS12_SAFEBAG_EXP* pobj)
{
	int ret;
	const char* otype=NULL;
	int err;
	jvalue* chldpj=NULL;
	const jvalue* chldarr=NULL;
	unsigned int i;
	unsigned int arrsize;
	PKCS12_SAFEBAG_EXP* safebag=NULL;

	ret = set_asn1_object(&(pobj->type), "type", pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("set type error[%d]", ret);
		goto fail;
	}

	otype = jobject_get_string(pj,"type",&err);
	if (otype == NULL) {
		ret = -EINVAL;
		ERROR_INFO("no type found");
		goto fail;
	}
	DEBUG_INFO("otype [%s]",otype);
	if (strcmp(otype,KEY_BAG_OID) == 0 || strcmp(otype,KEY_BAG_STR) == 0) {
		chldpj = jobject_get(pj,"keybag");
		if (chldpj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no keybag found");
			goto fail;
		}

		if (pobj->value.keybag == NULL) {
			pobj->value.keybag = PKCS8_PRIV_KEY_INFO_EXP_new();
			if (pobj->value.keybag == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		ret = encode_PKCS8_PRIV_KEY_INFO_EXP(chldpj,pobj->value.keybag);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (strcmp(otype,SHROUDED_KEY_BAG_OID) == 0) {
		chldpj = jobject_get(pj,"shkeybag");
		if (chldpj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no shkeybag found");
			goto fail;
		}

		if (pobj->value.shkeybag == NULL) {
			pobj->value.shkeybag = X509_SIG_EXP_new();
			if (pobj->value.shkeybag == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		ret = encode_X509_SIG_EXP(chldpj,pobj->value.shkeybag);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (strcmp(otype,SAFE_CONTENT_BAG_OID) == 0) {
		chldarr = (const jvalue*)jobject_get_array(pj,"safes",&err);
		if (chldarr == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no safes found");
			goto fail;
		}

		if (pobj->value.safes == NULL) {
			pobj->value.safes = sk_PKCS12_SAFEBAG_EXP_new_null();
			if (pobj->value.safes == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		/*now we should give the value*/

		arrsize = jarray_size(chldarr);
		for(i=0;i< arrsize;i++) {
			chldpj = jarray_get(chldarr,i,&err);
			if (chldpj == NULL) {
				ret = -EINVAL;
				ERROR_INFO("can not get %d safes",i);
				goto fail;
			}

			ASSERT_IF(safebag == NULL);
			safebag = PKCS12_SAFEBAG_EXP_new();
			if (safebag == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = encode_PKCS12_SAFEBAG_EXP(chldpj,safebag);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			sk_PKCS12_SAFEBAG_EXP_push(pobj->value.safes,safebag);
			safebag = NULL;
		}
	} else if (strcmp(otype,CERT_BAG_OID) == 0 ) {
		chldpj = jobject_get(pj,"certbag");
		if (chldpj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no certbag found");
			goto fail;
		}

		if (pobj->value.bag == NULL) {
			pobj->value.bag = PKCS12_BAGS_EXP_new();
			if (pobj->value.safes == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		ret = encode_PKCS12_BAGS_EXP(chldpj,pobj->value.bag);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (strcmp(otype,CLR_BAG_OID) == 0 ) {
		chldpj = jobject_get(pj,"crlbag");
		if (chldpj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no crlbag found");
			goto fail;
		}

		if (pobj->value.bag == NULL) {
			pobj->value.bag = PKCS12_BAGS_EXP_new();
			if (pobj->value.safes == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		ret = encode_PKCS12_BAGS_EXP(chldpj,pobj->value.bag);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (strcmp(otype,SECRET_BAG_OID) == 0 ) {
		chldpj = jobject_get(pj,"secretbag");
		if (chldpj == NULL) {
			ret = -EINVAL;
			ERROR_INFO("no secretbag found");
			goto fail;
		}

		if (pobj->value.bag == NULL) {
			pobj->value.bag = PKCS12_BAGS_EXP_new();
			if (pobj->value.safes == NULL) {
				ret = -ENOMEM;
				goto fail;
			}
		}
		ret = encode_PKCS12_BAGS_EXP(chldpj,pobj->value.bag);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		ret = -EINVAL;
		ERROR_INFO("not valid otype [%s]",otype);
		goto fail;
	}

	return 0;
fail:
	if (safebag != NULL) {
		PKCS12_SAFEBAG_EXP_free(safebag);
	}
	safebag = NULL;

	SETERRNO(ret);
	return ret;
}

int safebagenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(PKCS12_SAFEBAG_EXP);
}

int decode_X509_ATTRIBUTE_EXP(X509_ATTRIBUTE_EXP* pobj,jvalue* pj)
{
	int ret;
	jvalue* chldarr = NULL;
	jvalue* chldpj = NULL;
	jvalue* clonepj = NULL;
	unsigned int arrsize,i;
	int err;
	ret = get_asn1_object(&(pobj->object),"object",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->set != NULL) {
		arrsize = sk_ASN1_TYPE_num(pobj->set);
		chldarr = jarray_create();
		if (chldarr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		for(i=0;i<arrsize;i++) {
			ASN1_TYPE* curset = NULL;
			jvalue* sc=NULL;
			curset = sk_ASN1_TYPE_value(pobj->set,i);
			if (curset == NULL) {
				GETERRNO(ret);
				ERROR_INFO("set [%d] error",i);
				goto fail;
			}
			ASSERT_IF(chldpj == NULL);
			chldpj = jobject_create();
			if (chldpj == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = get_asn1_any(&curset,"set",chldpj);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			sc = (jvalue*)jobject_get_object(chldpj,"set",&err);
			if (sc == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			clonepj = jvalue_clone(sc);
			if (clonepj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret=  jarray_put_object(chldarr,clonepj);
			if (ret != 0) {
				GETERRNO(ret);
				goto fail;
			}
			clonepj = NULL;
			if (chldpj) {
				jvalue_destroy(chldpj);
			}
			chldpj = NULL;
		}
		ret = jobject_put_array(pj,"set",chldarr);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldarr = NULL;
	}


	return 0;
fail:
	if (clonepj) {
		jvalue_destroy(clonepj);
	}
	clonepj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (chldarr) {
		jarray_destroy((jarray*)chldarr);
	}
	chldarr = NULL;
	SETERRNO(ret);
	return ret;
}

int decode_PKCS8_PRIV_KEY_INFO_EXP(PKCS8_PRIV_KEY_INFO_EXP* pobj,jvalue* pj)
{
	int ret;
	jvalue* chldarr = NULL;
	jvalue* chldpj = NULL;
	unsigned int arrsize=0;
	unsigned int i;
	ret = get_asn1_integer(&(pobj->version),"version",pj);
	if (ret <= 0 ) {
		ret = -EINVAL;
		ERROR_INFO("no version ");
		goto fail;
	}

	chldpj = jobject_create();
	if (chldpj == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = decode_X509_ALGOR(pobj->pkeyalg,chldpj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = jobject_put_object(pj,"keyalg",chldpj);
	if (ret != 0) {
		GETERRNO(ret);
		goto fail;
	}
	chldpj = NULL;

	ret = get_asn1_octstr(&(pobj->pkey),"key",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->attributes != NULL) {
		chldarr = jarray_create();
		if (chldarr == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		arrsize = sk_X509_ATTRIBUTE_EXP_num(pobj->attributes);
		for(i=0;i<arrsize;i++) {
			X509_ATTRIBUTE_EXP*curset=NULL;
			curset = sk_X509_ATTRIBUTE_EXP_value(pobj->attributes,i);
			if (curset == NULL) {
				ret = -EINVAL;
				ERROR_INFO("can not get attributes [%d]",i);
				goto fail;
			}
			chldpj = jobject_create();
			if (chldpj == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = decode_X509_ATTRIBUTE_EXP(curset,chldpj);
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

		jobject_put_array(pj,"attributes",chldarr);
		chldarr = NULL;
	}



	return 0;
fail:
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;

	if (chldarr) {
		jarray_destroy((jarray*)chldarr);
	}
	chldarr = NULL;

	SETERRNO(ret);
	return ret;
}


int decode_PKCS12_SAFEBAG_EXP(PKCS12_SAFEBAG_EXP* pobj, jvalue* pj)
{
	int ret;
	const char* otype=NULL;
	int err;
	jvalue* chldpj=NULL;

	ret = get_asn1_object(&pobj->type,"type",pj);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("no type ");
		goto fail;
	}

	otype = jobject_get_string(pj,"type",&err);
	if (otype == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	DEBUG_INFO("otype [%s]",otype);
	if (strcmp(otype,KEY_BAG_OID) == 0 || strcmp(otype,KEY_BAG_STR) == 0) {
		chldpj = jobject_create();
		ret = decode_PKCS8_PRIV_KEY_INFO_EXP(pobj->value.keybag,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = jobject_put_object(pj,"keybag",chldpj);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
	} else if (strcmp(otype,SHROUDED_KEY_BAG_OID) == 0) {
	} else if (strcmp(otype,SAFE_CONTENT_BAG_OID) == 0) {
	} else if (strcmp(otype,CERT_BAG_OID) == 0 ) {
	} else if (strcmp(otype,CLR_BAG_OID) == 0 ) {
	} else if (strcmp(otype,SECRET_BAG_OID) == 0 ) {
	} else {
		ret = -EINVAL;
		ERROR_INFO("not support type [%s]",otype);
		goto fail;
	}

	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;

	return 0;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}



int safebagdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(PKCS12_SAFEBAG_EXP);
}
