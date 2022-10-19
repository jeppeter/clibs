

typedef struct {
	int type;
	union {
		ASN1_BMPSTRING *unicode;
		ASN1_IA5STRING *ascii;
	} value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)


typedef struct {
	ASN1_OCTET_STRING *classId;
	ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)


typedef struct {
	int type;
	union {
		ASN1_IA5STRING *url;
		SpcSerializedObject *moniker;
		SpcString *file;
	} value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)


typedef struct {
	SpcString *programName;
	SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)


typedef struct {
	ASN1_OBJECT *type;
	ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)


typedef struct {
	ASN1_OBJECT *algorithm;
	ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)


typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)


typedef struct {
	SpcAttributeTypeAndOptionalValue *data;
	DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)


typedef struct CatalogAuthAttr_st {
	ASN1_OBJECT *type;
	ASN1_TYPE *contents;
} CatalogAuthAttr;

DEFINE_STACK_OF(CatalogAuthAttr)
DECLARE_ASN1_FUNCTIONS(CatalogAuthAttr)

ASN1_SEQUENCE(CatalogAuthAttr) = {
	ASN1_SIMPLE(CatalogAuthAttr, type, ASN1_OBJECT),
	ASN1_OPT(CatalogAuthAttr, contents, ASN1_ANY)
} ASN1_SEQUENCE_END(CatalogAuthAttr)

IMPLEMENT_ASN1_FUNCTIONS(CatalogAuthAttr)


typedef struct {
	ASN1_OCTET_STRING *digest;
	STACK_OF(CatalogAuthAttr) *attributes;
} CatalogInfo;

DEFINE_STACK_OF(CatalogInfo)
DECLARE_ASN1_FUNCTIONS(CatalogInfo)

ASN1_SEQUENCE(CatalogInfo) = {
	ASN1_SIMPLE(CatalogInfo, digest, ASN1_OCTET_STRING),
	ASN1_SET_OF(CatalogInfo, attributes, CatalogAuthAttr)
} ASN1_SEQUENCE_END(CatalogInfo)

IMPLEMENT_ASN1_FUNCTIONS(CatalogInfo)


typedef struct {
	/* 1.3.6.1.4.1.311.12.1.1 szOID_CATALOG_LIST */
	SpcAttributeTypeAndOptionalValue *type;
	ASN1_OCTET_STRING *identifier;
	ASN1_UTCTIME *time;
	/* 1.3.6.1.4.1.311.12.1.2 CatalogVersion = 1
	 * 1.3.6.1.4.1.311.12.1.3 CatalogVersion = 2 */
	SpcAttributeTypeAndOptionalValue *version;
	STACK_OF(CatalogInfo) *header_attributes;
	/* 1.3.6.1.4.1.311.12.2.1 CAT_NAMEVALUE_OBJID */
	ASN1_TYPE *filename;
} MsCtlContent;

DECLARE_ASN1_FUNCTIONS(MsCtlContent)

ASN1_SEQUENCE(MsCtlContent) = {
	ASN1_SIMPLE(MsCtlContent, type, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(MsCtlContent, identifier, ASN1_OCTET_STRING),
	ASN1_SIMPLE(MsCtlContent, time, ASN1_UTCTIME),
	ASN1_SIMPLE(MsCtlContent, version, SpcAttributeTypeAndOptionalValue),
	ASN1_SEQUENCE_OF(MsCtlContent, header_attributes, CatalogInfo),
	ASN1_OPT(MsCtlContent, filename, ASN1_ANY)
} ASN1_SEQUENCE_END(MsCtlContent)

IMPLEMENT_ASN1_FUNCTIONS(MsCtlContent)


typedef struct {
	ASN1_BIT_STRING *flags;
	SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData)

ASN1_SEQUENCE(SpcPeImageData) = {
	ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
	ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)


typedef struct {
	ASN1_INTEGER *a;
	ASN1_OCTET_STRING *string;
	ASN1_INTEGER *b;
	ASN1_INTEGER *c;
	ASN1_INTEGER *d;
	ASN1_INTEGER *e;
	ASN1_INTEGER *f;
} SpcSipInfo;

DECLARE_ASN1_FUNCTIONS(SpcSipInfo)

ASN1_SEQUENCE(SpcSipInfo) = {
	ASN1_SIMPLE(SpcSipInfo, a, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, string, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSipInfo, b, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, c, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, d, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, e, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSipInfo)


typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

#ifdef ENABLE_CURL

typedef struct {
	ASN1_OBJECT *type;
	ASN1_OCTET_STRING *signature;
} TimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(TimeStampRequestBlob)

ASN1_SEQUENCE(TimeStampRequestBlob) = {
	ASN1_SIMPLE(TimeStampRequestBlob, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(TimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequestBlob)


typedef struct {
	ASN1_OBJECT *type;
	TimeStampRequestBlob *blob;
} TimeStampRequest;

DECLARE_ASN1_FUNCTIONS(TimeStampRequest)

ASN1_SEQUENCE(TimeStampRequest) = {
	ASN1_SIMPLE(TimeStampRequest, type, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampRequest, blob, TimeStampRequestBlob)
} ASN1_SEQUENCE_END(TimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequest)

/* RFC3161 Time stamping */

typedef struct {
	ASN1_INTEGER *status;
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
} PKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(PKIStatusInfo)

ASN1_SEQUENCE(PKIStatusInfo) = {
	ASN1_SIMPLE(PKIStatusInfo, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(PKIStatusInfo, statusString, ASN1_UTF8STRING),
	ASN1_OPT(PKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(PKIStatusInfo)


typedef struct {
	PKIStatusInfo *status;
	PKCS7 *token;
} TimeStampResp;

DECLARE_ASN1_FUNCTIONS(TimeStampResp)

ASN1_SEQUENCE(TimeStampResp) = {
	ASN1_SIMPLE(TimeStampResp, status, PKIStatusInfo),
	ASN1_OPT(TimeStampResp, token, PKCS7)
} ASN1_SEQUENCE_END(TimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampResp)


typedef struct {
	ASN1_INTEGER *version;
	MessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN *certReq;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

ASN1_SEQUENCE(TimeStampReq) = {
	ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
	ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, certReq, ASN1_BOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */

typedef struct {
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

ASN1_SEQUENCE(TimeStampAccuracy) = {
	ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)


typedef struct {
	ASN1_INTEGER *version;
	ASN1_OBJECT *policy_id;
	MessageImprint *messageImprint;
	ASN1_INTEGER *serial;
	ASN1_GENERALIZEDTIME *time;
	TimeStampAccuracy *accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER *nonce;
	GENERAL_NAME *tsa;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampToken;

DECLARE_ASN1_FUNCTIONS(TimeStampToken)

ASN1_SEQUENCE(TimeStampToken) = {
	ASN1_SIMPLE(TimeStampToken, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, policy_id, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampToken, messageImprint, MessageImprint),
	ASN1_SIMPLE(TimeStampToken, serial, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, time, ASN1_GENERALIZEDTIME),
	ASN1_OPT(TimeStampToken, accuracy, TimeStampAccuracy),
	ASN1_OPT(TimeStampToken, ordering, ASN1_FBOOLEAN),
	ASN1_OPT(TimeStampToken, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(TimeStampToken, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampToken, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TimeStampToken)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampToken)



int encode_SpcString(jvalue* pj, SpcString* pstr)
{
	int ret;
	int type = -1;
	ret = set_asn1_bmpstr(&(pstr->value.unicode), "unicode", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		type = 0;
	}

	ret = set_asn1_ia5str(&(pstr->value.ascii), "ascii", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		type = 1;
	}

	if (type < 0) {
		ret = -EINVAL;
		ERROR_INFO("can not find type SpcString");
		goto fail;
	}

	pstr->type = type;

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcString(SpcString* pstr, jvalue* pj)
{
	int ret = 0;
	if (pstr->type == 1) {
		ret = get_asn1_ia5str(&(pstr->value.ascii), "ascii", pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (pstr->type == 0) {
		ret =  get_asn1_bmpstr(&(pstr->value.unicode), "unicode", pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_SpcSerializedObject(jvalue* pj, SpcSerializedObject* pobj)
{
	int ret;
	ret = set_asn1_octstr(&(pobj->classId), "classid", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_octstr(&(pobj->serializedData), "serializeddata", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcSerializedObject(SpcSerializedObject* pobj, jvalue* pj)
{
	int ret = 0;
	ret = get_asn1_octstr(&(pobj->classId), "classid", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret =  get_asn1_octstr(&(pobj->serializedData), "serializeddata", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_SpcLink(jvalue* pj,SpcLink* plink)
{
	int type = -1;
	int ret = 0;
	jvalue* chldpj=NULL;
	ret = set_asn1_ia5str(&(plink->value.url),"url",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		type = 0;
	}

	if (type < 0) {
		chldpj = jobject_get(pj,"moniker");
		if (chldpj != NULL) {
			plink->value.moniker = SpcSerializedObject_new();
			if (plink->value.moniker == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = encode_SpcSerializedObject(chldpj,plink->value.moniker);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = 1;
		}
	}

	if (type < 0) {
		chldpj = jobject_get(pj,"file");
		if (chldpj != NULL) {
			plink->value.file = SpcString_new();
			if (plink->value.file == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = encode_SpcString(chldpj,plink->value.file);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = 2;
		}
	}

	if (type < 0) {
		ret = -EINVAL;
		ERROR_INFO("no type specified for SpcLink");
		goto fail;
	}

	plink->type = type;
	return 0;	
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcLink(SpcLink* plink,jvalue* pj)
{
	jvalue* chldpj=NULL;
	jvalue* retpj= NULL;
	int ret;
	int error=0;
	if (plink->type == 0) {
		ret = get_asn1_ia5str(&(plink->value.url),"url",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (plink->type == 1) {
		chldpj = jobject_create();
		if (chldpj ==NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = decode_SpcSerializedObject(plink->value.moniker,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj,"moniker",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj != NULL) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	} else if (plink->type == 2) {
		chldpj = jobject_create();
		if (chldpj ==NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = decode_SpcString(plink->value.file,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj,"file",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj != NULL) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	} else {
		ret = -EINVAL;
		ERROR_INFO("invalid type [%d]", plink->type);
		goto fail;
	}


	return 0;
fail:
	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
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
                                                                                                  \
	if (jsonfile == NULL) {                                                                       \
		ret = -EINVAL;                                                                            \
		ERROR_INFO("no jsonfile specified");                                                      \
		goto out;                                                                                 \
	}                                                                                             \
                                                                                                  \
	ret = read_file_whole(jsonfile, &jbuf, &jsize);                                               \
	if (ret < 0) {                                                                                \
		GETERRNO(ret);                                                                            \
		goto out;                                                                                 \
	}                                                                                             \
	jlen = ret;                                                                                   \
	jbuf[jlen] = 0x0;                                                                             \
	jsonlen = jlen + 1;                                                                           \
                                                                                                  \
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
		ERROR_INFO("can not i2d %s [%d]",#typev, ret);                                            \
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
			ERROR_INFO("[%s] not valid %s", binfile,#typev);                                      \
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

int spcstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcString);
}

int spcstrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcString);
}


int spcserialobjenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcSerializedObject);
}


int spcserialobjdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcSerializedObject);
}


int spclinkenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcLink);
}

int spclinkdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcLink);
}
