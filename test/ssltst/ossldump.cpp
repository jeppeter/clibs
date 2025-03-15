

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

#define ENABLE_CURL   1

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

struct UX509_extension_st {
    ASN1_OBJECT *object;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING value;
};

typedef struct UX509_extension_st UX509_EXTENSION;

typedef STACK_OF(UX509_EXTENSION) UX509_EXTENSIONS;

ASN1_SEQUENCE(UX509_EXTENSION) = {
        ASN1_SIMPLE(UX509_EXTENSION, object, ASN1_OBJECT),
        ASN1_OPT(UX509_EXTENSION, critical, ASN1_BOOLEAN),
        ASN1_EMBED(UX509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(UX509_EXTENSION)

ASN1_ITEM_TEMPLATE(UX509_EXTENSIONS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, UX509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(UX509_EXTENSIONS)

DEFINE_STACK_OF(UX509_EXTENSION)

IMPLEMENT_ASN1_FUNCTIONS(UX509_EXTENSION)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(UX509_EXTENSIONS, UX509_EXTENSIONS, UX509_EXTENSIONS)
//IMPLEMENT_ASN1_DUP_FUNCTION(UX509_EXTENSION)

int encode_UX509_EXTENSION(jvalue* pj, UX509_EXTENSION*pext)
{
	int ret;
	ASN1_OCTET_STRING* pdupstr=NULL;
	const unsigned char* pdata=NULL;
	int datalen=0;
	ASN1_BOOLEAN* pbval;


	ret=  set_asn1_object(&(pext->object),"object",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pbval = &(pext->critical);
	ret = set_asn1_bool(&pbval,"critical",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pext->critical) {
		DEBUG_INFO("crital true");
	} else {
		DEBUG_INFO("crital false");
	}


	ret = set_asn1_octstr(&pdupstr,"value",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pdupstr != NULL) {
		pdata = ASN1_STRING_get0_data(pdupstr);
		datalen = ASN1_STRING_length(pdupstr);
		ret = ASN1_STRING_set(&(pext->value),pdata,datalen);
		if (ret <= 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (pdupstr) {
		ASN1_OCTET_STRING_free(pdupstr);
	}
	pdupstr = NULL;

	return 1;
fail:
	if (pdupstr) {
		ASN1_OCTET_STRING_free(pdupstr);
	}
	pdupstr = NULL;
	SETERRNO(ret);
	return ret;
}

int decode_UX509_EXTENSION(UX509_EXTENSION* pext, jvalue* pj)
{
	int ret;
	ASN1_OCTET_STRING* pdupstr=NULL;
	const unsigned char* pdata=NULL;
	int datalen=0;
	ASN1_BOOLEAN* pbval;


	ret=  get_asn1_object(&(pext->object),"object",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pbval = &(pext->critical);

	ret = get_asn1_bool(&pbval,"critical",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pdata = ASN1_STRING_get0_data(&(pext->value));
	datalen = ASN1_STRING_length(&(pext->value));
	if (pdata != NULL && datalen > 0) {
		pdupstr = ASN1_OCTET_STRING_dup(&(pext->value));
		ret = get_asn1_octstr(&pdupstr,"value",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (pdupstr) {
		ASN1_OCTET_STRING_free(pdupstr);
	}
	pdupstr = NULL;




	return 1;
fail:
	if (pdupstr) {
		ASN1_OCTET_STRING_free(pdupstr);
	}
	pdupstr = NULL;
	SETERRNO(ret);
	return ret;
}


typedef struct {
	ASN1_INTEGER *version;
	MessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN *certReq;
	STACK_OF(UX509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

ASN1_SEQUENCE(TimeStampReq) = {
	ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
	ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, certReq, ASN1_BOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, UX509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

int encode_MessageImprint(jvalue* pj, MessageImprint* pobj);
int decode_MessageImprint(MessageImprint* pobj, jvalue* pj);

int encode_TimeStampReq(jvalue* pj,TimeStampReq* preq)
{
	int ret;
	jvalue* chldpj=NULL,*curobj=NULL;
	unsigned int arrsize;
	unsigned int i;
	UX509_EXTENSION* pcurext=NULL;


	ret = set_asn1_integer(&(preq->version),"version",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldpj = jobject_get(pj,"messageimprint");
	if (chldpj != NULL) {
		if (preq->messageImprint) {
			MessageImprint_free(preq->messageImprint);
		}
		preq->messageImprint = NULL;
		preq->messageImprint = MessageImprint_new();
		if (preq->messageImprint == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = encode_MessageImprint(chldpj,preq->messageImprint);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ret = set_asn1_object(&(preq->reqPolicy),"reqpolicy",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_integer(&(preq->nonce),"nonce",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	ret = set_asn1_bool(&(preq->certReq),"certreq",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO("certreq set");

	ret=  0;
	chldpj =(jvalue*) jobject_get_array(pj,"extensions",&ret);
	if (ret != 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (chldpj != NULL) {
		arrsize = jarray_size(chldpj);
		if (preq->extensions) {
			sk_UX509_EXTENSION_free(preq->extensions);
			preq->extensions = NULL;
		}

		preq->extensions = sk_UX509_EXTENSION_new_null();
		if (preq->extensions == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		for(i=0;i<arrsize;i++) {
			curobj = jarray_get(chldpj,i,&ret);
			if (curobj == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ASSERT_IF(pcurext == NULL);
			pcurext = UX509_EXTENSION_new();
			if (pcurext == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret= encode_UX509_EXTENSION(curobj,pcurext);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			sk_UX509_EXTENSION_push(preq->extensions,pcurext);
			pcurext = NULL;
		}
	}

	return 1;
fail:	
	if (pcurext) {
		UX509_EXTENSION_free(pcurext);
	}
	pcurext = NULL;
	SETERRNO(ret);
	return ret;
}

int decode_TimeStampReq(TimeStampReq* preq,jvalue* pj)
{
	int ret;
	jvalue* chldpj = NULL;
	jvalue* arrpj=NULL;
	jvalue *oldpj=NULL;
	UX509_EXTENSION* pcurext=NULL;
	unsigned int arrsize;
	unsigned int i;

	ret = get_asn1_integer(&(preq->version),"version",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (preq->messageImprint != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = decode_MessageImprint(preq->messageImprint,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = 0;
		oldpj = jobject_put(pj,"messageimprint",chldpj,&ret);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;

		if (oldpj) {
			jvalue_destroy(oldpj);
		}
		oldpj = NULL;
	}

	ret = get_asn1_object(&(preq->reqPolicy),"reqpolicy",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(preq->nonce),"nonce",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_bool(&(preq->certReq),"certreq",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (preq->extensions) {
		arrsize = sk_UX509_EXTENSION_num(preq->extensions);
		arrpj = jarray_create();
		if (arrpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		for(i=0;i<arrsize;i++) {
			pcurext = sk_UX509_EXTENSION_value(preq->extensions,i);
			if (pcurext == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ASSERT_IF(chldpj == NULL);
			chldpj = jobject_create();
			if (chldpj == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			ret = decode_UX509_EXTENSION(pcurext,chldpj);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			ret = jarray_put(arrpj,chldpj);
			if (ret != 0) {
				GETERRNO(ret);
				goto fail;
			}
			chldpj = NULL;
		}

		ret = 0;
		oldpj = jobject_put(pj,"extensions",arrpj,&ret);
		if (ret != 0) {
			GETERRNO(ret);
			goto fail;
		}
		arrpj = NULL;
		if (oldpj != NULL) {
			jvalue_destroy(oldpj);
		}
		oldpj = NULL;
	}

	return 1;
fail:
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	if (oldpj) {
		jvalue_destroy(oldpj);
	}
	oldpj = NULL;

	if (arrpj) {
		jvalue_destroy(arrpj);
	}
	arrpj = NULL;

	SETERRNO(ret);
	return ret;
}

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


typedef struct {
	ASN1_OCTET_STRING *classId;
	STACK_OF(ASN1_OBJECT)* serializedData;
	STACK_OF(ASN1_INTEGER)* intval;
	ASN1_INTEGER* ccval;
} SpcAsn1Code;

DECLARE_ASN1_FUNCTIONS(SpcAsn1Code)

ASN1_SEQUENCE(SpcAsn1Code) = {
	ASN1_SIMPLE(SpcAsn1Code, classId, ASN1_OCTET_STRING),
	ASN1_IMP_SEQUENCE_OF_OPT(SpcAsn1Code, serializedData, ASN1_OBJECT,0),
	ASN1_IMP_SET_OF_OPT(SpcAsn1Code, intval, ASN1_INTEGER, 1),
	ASN1_SIMPLE(SpcAsn1Code, ccval, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcAsn1Code)

IMPLEMENT_ASN1_FUNCTIONS(SpcAsn1Code)

typedef struct {
	SpcAsn1Code* cert;
	SpcAsn1Code* crl;
} NdefClose;

ASN1_NDEF_SEQUENCE(NdefClose) = {
        ASN1_IMP_SEQUENCE_OF_OPT(NdefClose, cert, SpcAsn1Code, 0),
        ASN1_IMP_SET_OF_OPT(NdefClose, crl, SpcAsn1Code, 1),
} ASN1_NDEF_SEQUENCE_END(NdefClose)

IMPLEMENT_ASN1_FUNCTIONS(NdefClose)


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

int encode_SpcLink(jvalue* pj, SpcLink* plink)
{
	int type = -1;
	int ret = 0;
	jvalue* chldpj = NULL;
	ret = set_asn1_ia5str(&(plink->value.url), "url", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		type = 0;
	}

	if (type < 0) {
		chldpj = jobject_get(pj, "moniker");
		if (chldpj != NULL) {
			if (plink->value.moniker == NULL) {
				plink->value.moniker = SpcSerializedObject_new();
				if (plink->value.moniker == NULL) {
					GETERRNO(ret);
					goto fail;
				}
			}
			ret = encode_SpcSerializedObject(chldpj, plink->value.moniker);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = 1;
		}
	}

	if (type < 0) {
		DEBUG_INFO(" ");
		chldpj = jobject_get(pj, "file");
		if (chldpj != NULL) {
			plink->value.file = SpcString_new();
			if (plink->value.file == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			ret = encode_SpcString(chldpj, plink->value.file);
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

int decode_SpcLink(SpcLink* plink, jvalue* pj)
{
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int ret;
	int error = 0;
	if (plink->type == 0) {
		ret = get_asn1_ia5str(&(plink->value.url), "url", pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (plink->type == 1) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = decode_SpcSerializedObject(plink->value.moniker, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "moniker", chldpj, &error);
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
		if (chldpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = decode_SpcString(plink->value.file, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "file", chldpj, &error);
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

int encode_SpcSpOpusInfo(jvalue* pj, SpcSpOpusInfo* pobj)
{
	int ret;
	jvalue* chldpj = NULL;
	chldpj = jobject_get(pj, "programname");
	if (chldpj != NULL) {
		if (pobj->programName == NULL) {
			pobj->programName = SpcString_new();
			if (pobj->programName == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}
		ret = encode_SpcString(chldpj, pobj->programName);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}
	chldpj = NULL;

	chldpj = jobject_get(pj, "moreinfo");
	if (chldpj != NULL) {
		if (pobj->moreInfo == NULL) {
			pobj->moreInfo = SpcLink_new();
			if (pobj->moreInfo == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}
		ret = encode_SpcLink(chldpj, pobj->moreInfo);
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

int decode_SpcSpOpusInfo(SpcSpOpusInfo* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* retpj = NULL;
	jvalue* chldpj = NULL;
	int error;
	if (pobj->programName != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create programName chldpj error[%d]", ret);
			goto fail;
		}
		ret = decode_SpcString(pobj->programName, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "programname", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("replace programname error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	if (pobj->moreInfo) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create moreInfo chldpj error[%d]", ret);
			goto fail;
		}
		ret = decode_SpcLink(pobj->moreInfo, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "moreinfo", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("replace moreinfo error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_SpcAttributeTypeAndOptionalValue(jvalue* pj, SpcAttributeTypeAndOptionalValue* pobj)
{
	int ret;

	DEBUG_INFO(" ");
	ret = set_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	DEBUG_INFO(" ");
	ret =  set_asn1_any(&(pobj->value), "value", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO(" ");

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcAttributeTypeAndOptionalValue(SpcAttributeTypeAndOptionalValue* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_any(&(pobj->value), "value", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_AlgorithmIdentifier(jvalue* pj, AlgorithmIdentifier* pobj)
{
	int ret;

	DEBUG_INFO(" ");
	ret = set_asn1_object(&(pobj->algorithm), "algorithm", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	DEBUG_INFO(" ");
	ret =  set_asn1_any(&(pobj->parameters), "parameters", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO(" ");

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_AlgorithmIdentifier(AlgorithmIdentifier* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_object(&(pobj->algorithm), "algorithm", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_any(&(pobj->parameters), "parameters", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_DigestInfo(jvalue* pj, DigestInfo* pobj)
{
	int ret;
	jvalue* chldpj = NULL;

	chldpj = jobject_get(pj, "digestalgorithm");
	if (chldpj != NULL) {
		if (chldpj->type != JOBJECT) {
			ret = -EINVAL;
			ERROR_INFO("digestalgorithm not object");
			goto fail;
		}
		ret = encode_AlgorithmIdentifier(chldpj, pobj->digestAlgorithm);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ret = set_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_DigestInfo(DigestInfo* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	chldpj = jobject_create();
	if (chldpj == NULL) {
		GETERRNO(ret);
		ERROR_INFO("could not create digestalgorithm object [%d]", ret);
		goto fail;
	}

	ret = decode_AlgorithmIdentifier(pobj->digestAlgorithm, chldpj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	error = 0;
	retpj = jobject_put(pj, "digestalgorithm", chldpj, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("could not insert digestalgorithm [%d]", ret);
		goto fail;
	}
	chldpj = NULL;
	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	ret = get_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;

	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	SETERRNO(ret);
	return ret;
}


int encode_SpcIndirectDataContent(jvalue* pj, SpcIndirectDataContent* pobj)
{
	int ret;
	jvalue* chldpj = NULL;

	chldpj = jobject_get(pj, "data");
	if (chldpj != NULL) {
		if (chldpj->type != JOBJECT) {
			ret = -EINVAL;
			ERROR_INFO("data not object");
			goto fail;
		}
		ret = encode_SpcAttributeTypeAndOptionalValue(chldpj, pobj->data);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
	}

	chldpj = jobject_get(pj, "messagedigest");
	if (chldpj != NULL) {
		if (chldpj->type != JOBJECT) {
			ret = -EINVAL;
			ERROR_INFO("messagedigest not object");
			goto fail;
		}
		ret = encode_DigestInfo(chldpj, pobj->messageDigest);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcIndirectDataContent(SpcIndirectDataContent* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	chldpj = jobject_create();
	if (chldpj == NULL) {
		GETERRNO(ret);
		ERROR_INFO("could not create data object [%d]", ret);
		goto fail;
	}

	ret = decode_SpcAttributeTypeAndOptionalValue(pobj->data, chldpj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	error = 0;
	retpj = jobject_put(pj, "data", chldpj, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("could not insert data [%d]", ret);
		goto fail;
	}
	chldpj = NULL;
	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	chldpj = jobject_create();
	if (chldpj == NULL) {
		GETERRNO(ret);
		ERROR_INFO("could not create messagedigest object [%d]", ret);
		goto fail;
	}

	ret = decode_DigestInfo(pobj->messageDigest, chldpj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	error = 0;
	retpj = jobject_put(pj, "messagedigest", chldpj, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("could not insert messagedigest [%d]", ret);
		goto fail;
	}
	chldpj = NULL;
	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	return 0;
fail:
	if (chldpj != NULL) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;

	if (retpj != NULL) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;

	SETERRNO(ret);
	return ret;
}

int encode_CatalogAuthAttr(jvalue* pj, CatalogAuthAttr* pobj)
{
	int ret;

	ret = set_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret = set_asn1_any(&(pobj->contents), "contents", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_CatalogAuthAttr(CatalogAuthAttr* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret =  get_asn1_any(&(pobj->contents), "contents", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int set_cataattr_array(STACK_OF(CatalogAuthAttr)** ppattr, const char* key, jvalue* pj)
{
	jvalue* arrobj = NULL;
	int error;
	unsigned int arrsize = 0;
	jvalue* curobj = NULL;
	CatalogAuthAttr* curattr = NULL;
	unsigned int i;
	int ret;


	error = 0;
	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		DEBUG_INFO("no [%s] CatalogAuthAttr", key);
		return 0;
	}

	arrsize = jarray_size(arrobj);
	for (i = 0; i < arrsize; i++) {
		error = 0;
		curobj = jarray_get(arrobj, i, &error);
		if (curobj == NULL || error != 0) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(curattr == NULL);
		curattr = CatalogAuthAttr_new();
		if (curattr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		ret = encode_CatalogAuthAttr(curobj, curattr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		if (ppattr && *ppattr == NULL) {
			*ppattr = sk_CatalogAuthAttr_new_null();
			if (*ppattr == NULL) {
				GETERRNO(ret);
				ERROR_INFO("new [%s] error[%d]", key);
				goto fail;
			}
		}

		ret = sk_CatalogAuthAttr_push(*ppattr, curattr);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO("push [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		curattr = NULL;
	}


	return (int)arrsize;
fail:
	if (curattr != NULL) {
		CatalogAuthAttr_free(curattr);
	}
	curattr = NULL;
	SETERRNO(ret);
	return ret;
}

int get_cataattr_array(STACK_OF(CatalogAuthAttr)** ppattr, const char* key, jvalue* pj)
{
	STACK_OF(CatalogAuthAttr)* pattr = NULL;
	jvalue* parr = NULL;
	jvalue* retpj = NULL;
	CatalogAuthAttr* pcurattr = NULL;
	jvalue* pcurobj = NULL;
	int ret;
	int arrsize = 0;
	int i;
	int error;
	if (ppattr == NULL || *ppattr == NULL) {
		DEBUG_INFO("[%s] has no array", key);
		return 0;
	}

	pattr = *ppattr;
	if (parr == NULL) {
		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] array error[%d]", key, ret);
			goto fail;
		}
	}

	arrsize = sk_CatalogAuthAttr_num(pattr);
	for (i = 0; i < sk_CatalogAuthAttr_num(pattr); i++) {
		ASSERT_IF(pcurattr == NULL);
		pcurattr = sk_CatalogAuthAttr_value(pattr, i);
		if (pcurattr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(pcurobj == NULL);
		pcurobj = jobject_create();
		if (pcurobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s].[%d] object error[%d]", key, i, ret);
			goto fail;
		}

		ret = decode_CatalogAuthAttr(pcurattr, pcurobj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = jarray_put_object(parr, pcurobj);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		pcurobj = NULL;
		pcurattr = NULL;
	}

	error = 0;
	retpj = jobject_put(pj, key, parr, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("put [%s] error[%d]", key, ret);
		goto fail;
	}
	parr = NULL;
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;


	return (int)arrsize;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (pcurobj) {
		jvalue_destroy(pcurobj);
	}
	pcurobj = NULL;
	if (parr) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}


int encode_CatalogInfo(jvalue* pj, CatalogInfo* pobj)
{
	int ret;

	ret = set_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret = set_cataattr_array(&(pobj->attributes), "attributes", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_CatalogInfo(CatalogInfo* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret =  get_cataattr_array(&(pobj->attributes), "attributes", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int set_catainfo_array(STACK_OF(CatalogInfo)** ppinfo, const char* key, jvalue* pj)
{
	jvalue* arrobj = NULL;
	int error;
	unsigned int arrsize = 0;
	jvalue* curobj = NULL;
	CatalogInfo* curinfo = NULL;
	unsigned int i;
	int ret;


	error = 0;
	arrobj = (jvalue*)jobject_get_array(pj, key, &error);
	if (arrobj == NULL) {
		DEBUG_INFO("no [%s] CatalogInfo", key);
		return 0;
	}

	arrsize = jarray_size(arrobj);
	for (i = 0; i < arrsize; i++) {
		error = 0;
		curobj = jarray_get(arrobj, i, &error);
		if (curobj == NULL || error != 0) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(curinfo == NULL);
		curinfo = CatalogInfo_new();
		if (curinfo == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		ret = encode_CatalogInfo(curobj, curinfo);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		if (ppinfo && *ppinfo == NULL) {
			*ppinfo = sk_CatalogInfo_new_null();
			if (*ppinfo == NULL) {
				GETERRNO(ret);
				ERROR_INFO("new [%s] error[%d]", key);
				goto fail;
			}
		}

		ret = sk_CatalogInfo_push(*ppinfo, curinfo);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO("push [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		curinfo = NULL;
	}


	return (int)arrsize;
fail:
	if (curinfo != NULL) {
		CatalogInfo_free(curinfo);
	}
	curinfo = NULL;
	SETERRNO(ret);
	return ret;
}

int get_catainfo_array(STACK_OF(CatalogInfo)** ppinfo, const char* key, jvalue* pj)
{
	STACK_OF(CatalogInfo)* pinfo = NULL;
	jvalue* parr = NULL;
	jvalue* retpj = NULL;
	CatalogInfo* pcurinfo = NULL;
	jvalue* pcurobj = NULL;
	int ret;
	int arrsize = 0;
	int i;
	int error;
	if (ppinfo == NULL || *ppinfo == NULL) {
		DEBUG_INFO("[%s] has no array", key);
		return 0;
	}

	pinfo = *ppinfo;
	if (parr == NULL) {
		parr = jarray_create();
		if (parr == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s] array error[%d]", key, ret);
			goto fail;
		}
	}

	arrsize = sk_CatalogInfo_num(pinfo);
	for (i = 0; i < sk_CatalogInfo_num(pinfo); i++) {
		ASSERT_IF(pcurinfo == NULL);
		pcurinfo = sk_CatalogInfo_value(pinfo, i);
		if (pcurinfo == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}

		ASSERT_IF(pcurobj == NULL);
		pcurobj = jobject_create();
		if (pcurobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%s].[%d] object error[%d]", key, i, ret);
			goto fail;
		}

		ret = decode_CatalogInfo(pcurinfo, pcurobj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = jarray_put_object(parr, pcurobj);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put [%s].[%d] error[%d]", key, i, ret);
			goto fail;
		}
		pcurobj = NULL;
		pcurinfo = NULL;
	}

	error = 0;
	retpj = jobject_put(pj, key, parr, &error);
	if (error != 0) {
		GETERRNO(ret);
		ERROR_INFO("put [%s] error[%d]", key, ret);
		goto fail;
	}
	parr = NULL;
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;


	return (int)arrsize;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (pcurobj) {
		jvalue_destroy(pcurobj);
	}
	pcurobj = NULL;
	if (parr) {
		jvalue_destroy(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}


int encode_MsCtlContent(jvalue* pj, MsCtlContent* pobj)
{
	int ret;
	jvalue* chldpj = NULL;
	chldpj = jobject_get(pj, "type");
	if (chldpj != NULL) {
		ret = encode_SpcAttributeTypeAndOptionalValue(chldpj, pobj->type);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}


	ret = set_asn1_octstr(&(pobj->identifier), "identifier", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_utctime(&(pobj->time), "time", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldpj = jobject_get(pj, "version");
	if (chldpj != NULL) {
		ret = encode_SpcAttributeTypeAndOptionalValue(chldpj, pobj->version);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ret = set_catainfo_array(&(pobj->header_attributes), "headerattributes", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_any(&(pobj->filename), "filename", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_MsCtlContent(MsCtlContent* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	if (pobj->type != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create type object error[%d]", ret);
			goto fail;
		}
		ret = decode_SpcAttributeTypeAndOptionalValue(pobj->type, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		retpj = jobject_put(pj, "type", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put type object error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	ret = get_asn1_octstr(&(pobj->identifier), "identifier", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_utctime(&(pobj->time), "time", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->version != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create version object error[%d]", ret);
			goto fail;
		}
		ret = decode_SpcAttributeTypeAndOptionalValue(pobj->version, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		retpj = jobject_put(pj, "version", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put version object error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	ret = get_catainfo_array(&(pobj->header_attributes), "headerattributes", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_any(&(pobj->filename), "filename", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_SpcPeImageData(jvalue* pj, SpcPeImageData* pobj)
{
	int ret;
	jvalue* chldpj = NULL;

	ret = set_asn1_bitstr(&(pobj->flags), "flags", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldpj = jobject_get(pj, "file");
	if (chldpj != NULL) {
		if (pobj->file == NULL) {
			pobj->file = SpcLink_new();
			if (pobj->file == NULL) {
				GETERRNO(ret);
				ERROR_INFO("new file error[%d]", ret);
				goto fail;
			}
		}
		ret = encode_SpcLink(chldpj, pobj->file);
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

int decode_SpcPeImageData(SpcPeImageData* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	ret = get_asn1_bitstr(&(pobj->flags), "flags", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->file != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create file object error[%d]", ret);
			goto fail;
		}

		ret = decode_SpcLink(pobj->file, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		retpj = jobject_put(pj, "file", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_SpcSipInfo(jvalue* pj, SpcSipInfo* pobj)
{
	int ret;

	ret = set_asn1_integer(&(pobj->a), "a", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_octstr(&(pobj->string), "string", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_integer(&(pobj->b), "b", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret = set_asn1_integer(&(pobj->c), "c", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret = set_asn1_integer(&(pobj->d), "d", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ret = set_asn1_integer(&(pobj->e), "e", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_integer(&(pobj->f), "f", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcSipInfo(SpcSipInfo* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_integer(&(pobj->a), "a", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_octstr(&(pobj->string), "string", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->b), "b", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->c), "c", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->d), "d", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->e), "e", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->f), "f", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int encode_MessageImprint(jvalue* pj, MessageImprint* pobj)
{
	int ret;
	jvalue* chldpj = NULL;

	chldpj = jobject_get(pj, "digestalgorithm");
	if (chldpj != NULL) {
		if (pobj->digestAlgorithm == NULL) {
			pobj->digestAlgorithm = AlgorithmIdentifier_new();
			if (pobj->digestAlgorithm == NULL) {
				GETERRNO(ret);
				ERROR_INFO("AlgorithmIdentifier_new error[%d]", ret);
				goto fail;
			}
		}
		ret = encode_AlgorithmIdentifier(chldpj, pobj->digestAlgorithm);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ret = set_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_MessageImprint(MessageImprint* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	if (pobj->digestAlgorithm != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("jobject_create error[%d]", ret);
			goto fail;
		}
		ret = decode_AlgorithmIdentifier(pobj->digestAlgorithm, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		error = 0;
		retpj = jobject_put(pj, "digestalgorithm", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put digestalgorithm error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	ret = get_asn1_octstr(&(pobj->digest), "digest", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_TimeStampRequestBlob(jvalue* pj, TimeStampRequestBlob* pobj)
{
	int ret;

	ret = set_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_octstr(&(pobj->signature), "signature", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_TimeStampRequestBlob(TimeStampRequestBlob* pobj, jvalue* pj)
{
	int ret = 0;

	ret = get_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_octstr(&(pobj->signature), "signature", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_TimeStampRequest(jvalue* pj, TimeStampRequest* pobj)
{
	int ret;
	jvalue* chldpj = NULL;

	ret = set_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	chldpj = jobject_get(pj, "blob");
	if (chldpj != NULL) {
		if (pobj->blob == NULL) {
			pobj->blob = TimeStampRequestBlob_new();
			if (pobj->blob == NULL) {
				GETERRNO(ret);
				ERROR_INFO("TimeStampRequestBlob_new error[%d]", ret);
				goto fail;
			}
		}

		ret = encode_TimeStampRequestBlob(chldpj, pobj->blob);
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

int decode_TimeStampRequest(TimeStampRequest* pobj, jvalue* pj)
{
	int ret = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	int error;

	ret = get_asn1_object(&(pobj->type), "type", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pobj->blob != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("jobject_create error[%d]", ret);
			goto fail;
		}

		ret = decode_TimeStampRequestBlob(pobj->blob, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "blob", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put blob error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	}

	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_PKIStatusInfo(jvalue* pj, PKIStatusInfo* pobj)
{
	int ret;

	ret = set_asn1_integer(&(pobj->status), "status", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_string_array(&(pobj->statusString), "statusstring", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_bitstr(&(pobj->failInfo), "failinfo", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_PKIStatusInfo(PKIStatusInfo* pobj, jvalue* pj)
{
	int ret = 0;
	ret = get_asn1_integer(&(pobj->status), "status", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_string_array(&(pobj->statusString), "statusstring", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_bitstr(&(pobj->failInfo), "failinfo", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_OTHERNAME(jvalue* pj, OTHERNAME* pobj)
{
	int ret;

	ret = set_asn1_object(&(pobj->type_id), "typeid", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_any(&(pobj->value), "value", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_OTHERNAME(OTHERNAME* pobj, jvalue* pj)
{
	int ret = 0;
	ret = get_asn1_object(&(pobj->type_id), "typeid", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_any(&(pobj->value), "value", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_EDIPARTYNAME(jvalue* pj, EDIPARTYNAME* pobj)
{
	int ret;
	ret = set_asn1_string(&(pobj->nameAssigner), "nameassigner", pj);
	if (ret < 0 ) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_string(&(pobj->partyName), "partyname", pj);
	if (ret < 0 ) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_EDIPARTYNAME(EDIPARTYNAME* pobj, jvalue* pj)
{
	int ret = 0;
	DEBUG_INFO(" ");
	ret = get_asn1_string(&(pobj->nameAssigner), "nameassigner", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}

	DEBUG_INFO(" ");
	ret = get_asn1_string(&(pobj->partyName), "partyname", pj);
	if (ret < 0 || ret == 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO(" ");

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_X509_NAME_ENTRY(jvalue* pj, X509_NAME_ENTRY* pobj)
{
	ASN1_OBJECT* obj=NULL;
	int ret;
	const char* pobjstr=NULL;
	const char* pvalstr= NULL;
	int setted = 0;
	X509_NAME_ENTRY* pretobj=NULL;
	int error;	

	pobjstr = jobject_get_string(pj,"object",&error);
	pvalstr = jobject_get_string(pj,"value",&error);
	if (pobjstr != NULL && pvalstr != NULL) {
		ret = set_asn1_object(&obj,"object",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}


		pretobj = X509_NAME_ENTRY_create_by_OBJ(&pobj,obj,V_ASN1_UTF8STRING,(const unsigned char*)pvalstr,strlen(pvalstr));
		if (pretobj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("X509_NAME_ENTRY_create_by_OBJ error[%d] ",ret);
			goto fail;
		}
		setted = 1;
	}


	if (obj) {
		ASN1_OBJECT_free(obj);
	}
	obj = NULL;

	return setted;
fail:
	if (obj) {
		ASN1_OBJECT_free(obj);
	}
	obj = NULL;
	SETERRNO(ret);
	return ret;
}

int decode_X509_NAME_ENTRY(X509_NAME_ENTRY* pobj, jvalue* pj)
{
	ASN1_OBJECT* obj=NULL;
	ASN1_STRING* pval=NULL;
	int ret;

	obj = X509_NAME_ENTRY_get_object(pobj);
	pval = X509_NAME_ENTRY_get_data(pobj);
	if (obj == NULL || pval == NULL) {
		ret= -EINVAL;
		goto fail;
	}

	ret = get_asn1_object(&obj,"object",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_string(&pval,"value",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_X509_NAME(jvalue* pj, X509_NAME* pobj)
{
	int ret;
	unsigned int size;
	unsigned int i;
	jvalue* chldpj = NULL;
	X509_NAME_ENTRY* pentry=NULL;
	int error;
	char* jsons= NULL;
	unsigned int jsonsize=0;

	jsons = jvalue_write_pretty(pj,&jsonsize);
	if (jsons != NULL) {
		DEBUG_INFO("jsons\n%s",jsons);
		free(jsons);
	} else {
		DEBUG_INFO("no jsons");
	}

	size = jarray_size(pj);
	for(i=0;i<size;i++) {
		error = 0;
		chldpj = jarray_get(pj,i,&error);
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%d] error[%d]", i, ret);
			goto fail;
		}
		ASSERT_IF(pentry == NULL);
		pentry = X509_NAME_ENTRY_new();
		if (pentry == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create [%d] entry error[%d]", i,ret);
			goto fail;
		}
		ret = encode_X509_NAME_ENTRY(chldpj,pentry);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = X509_NAME_add_entry(pobj,pentry,-1,0);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("push [%d] entry error[%d]",i, ret);
			goto fail;
		}
		pentry = NULL;
	}

	return (int)size;
fail:
	if (pentry) {
		X509_NAME_ENTRY_free(pentry);
	}
	pentry = NULL;
	SETERRNO(ret);
	return ret;
}

int decode_X509_NAME(X509_NAME* pobj, jvalue* pj)
{
	jvalue* chldpj = NULL;
	int size=0;
	int i;
	int ret;
	X509_NAME_ENTRY* pentry=NULL;

	size = X509_NAME_entry_count(pobj);
	for(i=0;i<size;i++) {
		ASSERT_IF(chldpj == NULL);
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create entry [%d] error[%d]",i,ret);
			goto fail;
		}
		ASSERT_IF(pentry == NULL);
		pentry = X509_NAME_get_entry(pobj,i);
		if (pentry == NULL) {
			GETERRNO(ret);
			ERROR_INFO("get [%d] entry error[%d]", i ,ret);
			goto fail;
		}

		ret = decode_X509_NAME_ENTRY(pentry,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = jarray_put(pj,chldpj);
		if (ret < 0){
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		pentry = NULL;
	}


	return size;
fail:
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}



int encode_GENERAL_NAME(jvalue* pj, GENERAL_NAME* pobj)
{
	int ret;
	int type = -1;
	int error ;
	jvalue* chldpj = NULL;
	chldpj = jobject_get(pj, "othername");
	if (chldpj != NULL) {
		if (pobj->d.otherName == NULL) {
			pobj->d.otherName = OTHERNAME_new();
			if (pobj->d.otherName == NULL) {
				GETERRNO(ret);
				ERROR_INFO("OTHER_NAME_new error[%d]", ret);
				goto fail;
			}
		}
		ret = encode_OTHERNAME(chldpj, pobj->d.otherName);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		type = GEN_OTHERNAME;
	}

	if (type < 0) {
		ret = set_asn1_ia5str(&(pobj->d.rfc822Name),"rfc822name",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			type = GEN_EMAIL;
		}
	}

	if (type < 0) {
		ret = set_asn1_ia5str(&(pobj->d.dNSName),"dnsname",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			type = GEN_DNS;
		}
	}

	if (type < 0) {
		ret = set_asn1_seq((ASN1_STRING**)&(pobj->d.x400Address),"x400address",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			DEBUG_INFO("d.x400Address [%p]", pobj->d.x400Address);
			type = GEN_X400;
		}
	}

	if (type < 0) {
		error = 0;
		chldpj = (jvalue*)jobject_get_array(pj,"directoryname",&error);
		if (chldpj != NULL) {
			DEBUG_INFO("directoryname [%p]",chldpj);
			if (pobj->d.directoryName == NULL) {
				pobj->d.directoryName = X509_NAME_new();
				if (pobj->d.directoryName == NULL) {
					GETERRNO(ret);
					ERROR_INFO("X509_NAME_new error[%d]", ret);
					goto fail;
				}
			}
			ret = encode_X509_NAME(chldpj,pobj->d.directoryName);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = GEN_DIRNAME;
		}
	}

	if (type < 0) {
		chldpj = jobject_get(pj,"edipartyname");
		DEBUG_INFO("edipartyname [%p]",chldpj);
		if (chldpj != NULL) {
			if (pobj->d.ediPartyName == NULL) {
				pobj->d.ediPartyName = EDIPARTYNAME_new();
				if (pobj->d.ediPartyName == NULL) {
					GETERRNO(ret);
					ERROR_INFO("EDIPARTYNAME_new error[%d]", ret);
					goto fail;
				}
			}
			ret = encode_EDIPARTYNAME(chldpj,pobj->d.ediPartyName);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			type = GEN_EDIPARTY;
		}
	}

	if (type < 0) {
		ret = set_asn1_ia5str(&(pobj->d.uniformResourceIdentifier),"uniformresourceidentifier",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			type = GEN_URI;
		}
	}

	if (type < 0) {
		ret = set_asn1_octstr(&(pobj->d.iPAddress),"ipaddress", pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			type = GEN_IPADD;
		}
	}

	if (type < 0) {
		ret = set_asn1_object(&(pobj->d.registeredID),"registerid",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			type = GEN_RID;
		}
	}


	if (type < 0) {
		ret = -EINVAL;
		ERROR_INFO("no type specified for GENERAL_NAME");
		goto fail;
	}
	pobj->type = type;
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int decode_GENERAL_NAME(GENERAL_NAME* pobj, jvalue* pj)
{
	int ret = 0;
	int type = -1;
	int error = 0;
	jvalue* chldpj = NULL;
	jvalue* retpj = NULL;
	type = pobj->type;
	DEBUG_INFO("GENERAL_NAME type [%d]", type);
	if (type == GEN_OTHERNAME) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create OTHERNAME object error[%d]", ret);
			goto fail;
		}
		ret = decode_OTHERNAME(pobj->d.otherName, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "othername", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put othername error[%d]" , ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	} else if (type == GEN_EMAIL) {
		ret = get_asn1_ia5str(&(pobj->d.rfc822Name),"rfc822name",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (type == GEN_DNS) {
		ret = get_asn1_ia5str(&(pobj->d.dNSName),"dnsname",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (type == GEN_X400) {
		ret = get_asn1_seq((ASN1_STRING**)&(pobj->d.x400Address),"x400address",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (type == GEN_DIRNAME) {
		chldpj = jarray_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create directoryname array error[%d]", ret);
			goto fail;
		}
		ret = decode_X509_NAME(pobj->d.directoryName,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = jobject_put_array(pj,"directoryname",chldpj);
		if (ret != 0) {
			GETERRNO(ret);
			ERROR_INFO("put directoryname error[%d]", ret);
			goto fail;
		}
		chldpj = NULL;
	} else if (type == GEN_EDIPARTY) {		
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			ERROR_INFO("create EDIPARTYNAME object error[%d]", ret);
			goto fail;
		}
		ret = decode_EDIPARTYNAME(pobj->d.ediPartyName, chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj, "edipartyname", chldpj, &error);
		if (error != 0) {
			GETERRNO(ret);
			ERROR_INFO("put edipartyname error[%d]" , ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
	} else if (type == GEN_URI) {
		ret = get_asn1_ia5str(&(pobj->d.uniformResourceIdentifier),"uniformresourceidentifier",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (type == GEN_IPADD) {
		ret = get_asn1_octstr(&(pobj->d.iPAddress),"ipaddress",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (type == GEN_RID) {
		ret = get_asn1_object(&(pobj->d.registeredID),"registerid",pj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		ret = -EINVAL;
		ERROR_INFO("GENERAL_NAME type [%d] not supported", type);
		goto fail;
	}

	return 0;
fail:
	if (retpj) {
		jvalue_destroy(retpj);
	}
	retpj = NULL;
	if (chldpj) {
		jvalue_destroy(chldpj);
	}
	chldpj = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_SpcAsn1Code(jvalue* pj, SpcAsn1Code* pobj)
{
	int ret;

	ret = set_asn1_octstr(&(pobj->classId),"classid",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_object_array(&(pobj->serializedData),"serializeddata",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_integer_array(&(pobj->intval),"intval",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = set_asn1_integer(&(pobj->ccval),"ccval",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_SpcAsn1Code(SpcAsn1Code* pobj, jvalue* pj)
{
	int ret;

	ret = get_asn1_octstr(&(pobj->classId),"classid",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_object_array(&(pobj->serializedData),"serializeddata",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer_array(&(pobj->intval),"intval",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = get_asn1_integer(&(pobj->ccval),"ccval",pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int encode_NdefClose(jvalue* pj, NdefClose* pobj)
{
	int ret;
	jvalue* chldpj = NULL;
	int retval = 0;

	DEBUG_INFO(" ");
	chldpj = jobject_get(pj,"cert");
	if (chldpj != NULL) {
		if (pobj->cert == NULL) {
			DEBUG_INFO(" ");
			pobj->cert = SpcAsn1Code_new();
			if (pobj->cert == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		DEBUG_INFO(" ");
		ret = encode_SpcAsn1Code(chldpj,pobj->cert);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		retval = 1;
		DEBUG_INFO(" ");
	}

	chldpj = jobject_get(pj,"crl");
	if (chldpj != NULL) {
		DEBUG_INFO(" ");
		if (pobj->crl == NULL) {
			DEBUG_INFO(" ");
			pobj->crl = SpcAsn1Code_new();
			if (pobj->crl == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		DEBUG_INFO(" ");
		ret = encode_SpcAsn1Code(chldpj,pobj->crl);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		retval = 1;
		DEBUG_INFO(" ");
	}


	return retval;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_NdefClose(NdefClose* pobj, jvalue* pj)
{
	int ret;
	jvalue* chldpj= NULL;
	jvalue* retpj = NULL;
	int error = 0;
	int retval = 0;

	if (pobj->cert != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		ret = decode_SpcAsn1Code(pobj->cert,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj,"cert",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj != NULL) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
		retval ++;
	}

	if (pobj->crl != NULL) {
		chldpj = jobject_create();
		if (chldpj == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		ret = decode_SpcAsn1Code(pobj->crl,chldpj);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		error = 0;
		retpj = jobject_put(pj,"crl",chldpj,&error);
		if (error != 0) {
			GETERRNO(ret);
			goto fail;
		}
		chldpj = NULL;
		if (retpj != NULL) {
			jvalue_destroy(retpj);
		}
		retpj = NULL;
		retval ++;
	}

	return retval;
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


int spcopusinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcSpOpusInfo);
}

int spcopusinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcSpOpusInfo);
}

int spcattrvalenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcAttributeTypeAndOptionalValue);
}

int spcattrvaldec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcAttributeTypeAndOptionalValue);
}

int algoidentenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(AlgorithmIdentifier);
}

int algoidentdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(AlgorithmIdentifier);
}


int diginfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(DigestInfo);
}

int diginfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(DigestInfo);
}

int spcinddatacontentenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcIndirectDataContent);
}

int spcinddatacontentdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcIndirectDataContent);
}

int cataauthattrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(CatalogAuthAttr);
}

int cataauthattrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(CatalogAuthAttr);
}

int catainfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(CatalogInfo);
}

int catainfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(CatalogInfo);
}

int msctlconenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(MsCtlContent);
}

int msctlcondec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(MsCtlContent);
}


int spcpeimgenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcPeImageData);
}

int spcpeimgdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcPeImageData);
}

int spcsipinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcSipInfo);
}

int spcsipinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcSipInfo);
}

int msgimpprnenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(MessageImprint);
}

int msgimpprndec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(MessageImprint);
}

int timestampreqblobenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(TimeStampRequestBlob);
}

int timestampreqblobdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(TimeStampRequestBlob);
}

int timestamprqstenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(TimeStampRequest);
}

int timestamprqstdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(TimeStampRequest);
}

int pkistatusinfoenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(PKIStatusInfo);
}

int pkistatusinfodec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(PKIStatusInfo);
}

int ia5strset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	ASN1_IA5STRING* pia5 = NULL;
	int ret;
	int idx = 0;
	char* str;
	unsigned char* pbuf = NULL;
	int buflen = 0;
	int bufsize = 0;
	unsigned char* pform = NULL;
	pargs_options_t pargs = (pargs_options_t)popt;

	init_log_verbose(pargs);
	pia5 = ASN1_IA5STRING_new();
	if (pia5 == NULL) {
		GETERRNO(ret);
		goto out;
	}

	for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
		str = parsestate->leftargs[idx];
		ret = ASN1_STRING_set(pia5, str, -1);
		if (ret == 0) {
			GETERRNO(ret);
			ERROR_INFO("set [%s] error[%d]", str, ret);
			goto out;
		}

		buflen = i2d_ASN1_IA5STRING(pia5, NULL);
		if (buflen >= bufsize || pbuf == NULL) {
			if (buflen >= bufsize) {
				bufsize = buflen + 1;
			}
			if (pbuf != NULL) {
				free(pbuf);
			}
			pbuf = NULL;
			pbuf = (unsigned char*)malloc(bufsize);
			if (pbuf == NULL) {
				GETERRNO(ret);
				goto out;
			}
		}
		memset(pbuf, 0, bufsize);
		pform = pbuf;
		buflen = i2d_ASN1_IA5STRING(pia5, &pform);
		if (pargs->m_output != NULL) {
			ret = write_file_whole(pargs->m_output, (char*)pbuf, buflen);
		} else {
			dump_buffer_out(stdout, pbuf, buflen, "iastr");
			ret = 0;
		}
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
	}

	ret = 0;
out:
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	if (pia5) {
		ASN1_IA5STRING_free(pia5);
	}
	pia5 = NULL;
	SETERRNO(ret);
	return ret;
}

int encode_ASN1_BMPSTRING(jvalue* pj, ASN1_BMPSTRING* pobj)
{
	int ret;

	DEBUG_INFO("ASN1_BMPSTRING");
	ret = set_asn1_bmpstr(&pobj, "value", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int decode_ASN1_BMPSTRING(ASN1_BMPSTRING* pobj, jvalue* pj)
{
	int ret = 0;

	DEBUG_INFO("ASN1_BMPSTRING");
	ret = get_asn1_bmpstr(&pobj, "value", pj);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int generalnameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(GENERAL_NAME);
}

int generalnamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(GENERAL_NAME);
}

int othernameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(OTHERNAME);
}

int othernamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(OTHERNAME);	
}

int edipartynameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(EDIPARTYNAME);
}

int edipartynamedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(EDIPARTYNAME);
}


int x509nameenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(X509_NAME);	
}

int x509namedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(X509_NAME);	
}

int timestamprespdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* fname = NULL;
	TimeStampResp* resp=NULL;
	unsigned char* p = NULL;
	int i;
	pargs_options_t pargs = (pargs_options_t) popt;
	unsigned char* ccbuf = NULL;
	int ccsize = 0;
	int cclen = 0;
	int ret;
	char* pout=NULL;
	int outsize=0;

	init_log_verbose(pargs);

	for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
		fname = parsestate->leftargs[i];
		ret = read_file_whole(fname,(char**)&ccbuf,&ccsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("read [%s] error[%d]", fname,ret);
			goto out;
		}
		cclen = ret;
		p = ccbuf;

		ASSERT_IF(resp == NULL);
		resp = d2i_TimeStampResp(NULL,(const unsigned char**)&p,cclen);
		if (resp == NULL) {
			GETERRNO(ret);
			ERROR_INFO("decode [%s] error[%d]",fname,ret);
			goto out;
		}


		if (pout != NULL) {
			free(pout);
		}
		pout = NULL;
		pout = (char*)malloc(outsize);
		if (pout == NULL) {
			GETERRNO(ret);
			goto out;
		}

		ret = i2d_TimeStampResp(resp,NULL);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("d2i_TimeStampResp error[%d]",ret);
			goto out;
		}

		outsize = ret;
		pout = (char*)malloc(outsize);
		if (pout == NULL) {
			GETERRNO(ret);
			goto out;
		}

		p= (unsigned char*)pout;
		ret = i2d_TimeStampResp(resp,&p);
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("d2i_TimeStampResp error[%d]",ret);
			goto out;
		}

		if (pargs->m_output) {
			ret = write_file_whole(pargs->m_output,pout,outsize);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("write [%s] error[%d]", pargs->m_output,ret);
				goto out;
			}
		} else {
			dump_buffer_out(stdout,(uint8_t*)pout,outsize,"TimeStampResp");
		}

		TimeStampResp_free(resp);
		resp = NULL;
	}

	ret = 0;
out:
	if (resp) {
		TimeStampResp_free(resp);
	}
	resp = NULL;
	if (pout) {
		OPENSSL_free(pout);	
	}	
	pout = NULL;
	read_file_whole(NULL,(char**)&ccbuf,&ccsize);	
	SETERRNO(ret);
	return ret;	
}

int spcasn1codeenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(SpcAsn1Code);
}

int spcasn1codedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(SpcAsn1Code);
}

int x509algrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(X509_ALGOR);	
}

int x509algrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(X509_ALGOR);	
}


int ndefcloseenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(NdefClose);
}
int ndefclosedec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(NdefClose);
}


int pkcs7vfy_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* p7file=NULL;
	char* certfile = NULL;
	char* mapfile = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const unsigned char* p=NULL;
	char* p7buf=NULL;
	int p7len=0,p7size=0;
	PKCS7* p7ptr=NULL;
	char* mapbuf=NULL;
	int mapsize=0,maplen=0;
	int ret;
	X509_STORE* store = NULL;
	X509_LOOKUP* lookup = NULL;
	X509_VERIFY_PARAM* param = NULL;
	BIO* bio=NULL;

	init_log_verbose(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		p7file = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			certfile = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				mapfile = parsestate->leftargs[2];
			}
		}
	}

	if (p7file == NULL || certfile == NULL || mapfile == NULL) {
		ret = -EINVAL;
		ERROR_INFO("need p7file certfile mapfile");
		goto out;
	}

	ret = read_file_whole(p7file,&p7buf,&p7size);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	p7len = ret;
	p = (unsigned char*) p7buf;
	p7ptr = d2i_PKCS7(NULL,&p,p7len);
	if (p7ptr == NULL) {
		GETERRNO(ret);
		ERROR_INFO("decode [%s] PKCS7 error [%d]", p7file,ret);
		goto out;
	}

	store = X509_STORE_new();
	if (store == NULL) {
		GETERRNO(ret);
		ERROR_INFO("X509_STORE_new error[%d]", ret);
		goto out;
	}

	lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
	if (lookup == NULL) {
		GETERRNO(ret);
		ERROR_INFO("X509_STORE_add_lookup error[%d]", ret);
		goto out;
	}

	ret = X509_load_cert_file(lookup,certfile,X509_FILETYPE_PEM);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("load [%s] error[%d]",certfile,ret);
		goto out;
	}


	param = X509_STORE_get0_param(store);
	if (param == NULL) {
		GETERRNO(ret);
		ERROR_INFO("X509_STORE_get0_param error[%d]", ret);
		goto out;
	}

	ret = X509_VERIFY_PARAM_set_purpose(param,X509_PURPOSE_ANY);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("X509_VERIFY_PARAM_set_purpose error[%d]", ret);
		goto out;
	}

	ret = X509_STORE_set1_param(store,param);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("X509_STORE_set1_param error[%d]", ret);
		goto out;
	}

	ret = read_file_whole(mapfile,&mapbuf,&mapsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}
	maplen = ret;

	bio = BIO_new_mem_buf(mapbuf,maplen);
	if (bio == NULL) {
		GETERRNO(ret);
		ERROR_INFO("map [%s] error[%d]", mapfile,ret);
		goto out;
	}

	ret = PKCS7_verify(p7ptr,NULL,store,bio,NULL,0);
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("PKCS7_verify error[%d]", ret);
		goto out;
	}

	fprintf(stdout, "verify [%s] [%s] [%s] succ\n", p7file,certfile,mapfile);
	ret = 0;
out:
	if (bio != NULL) {
		BIO_free(bio);
	}
	bio = NULL;
	read_file_whole(NULL,&mapbuf,&mapsize);
	maplen = 0;
	if (store) {
		X509_STORE_free(store);
	}
	store = NULL;

	if (p7ptr) {
		PKCS7_free(p7ptr);
	}
	p7ptr = NULL;
	read_file_whole(NULL,&p7buf,&p7size);
	p7len = 0;
	SETERRNO(ret);
	return ret;
}

int bmpstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(ASN1_BMPSTRING);
}
int bmpstrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(ASN1_BMPSTRING);
}


int x509extenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(UX509_EXTENSION);
}
int x509extdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(UX509_EXTENSION);
}

int tsreqenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_ENCODE_HANDLER(TimeStampReq);
}
int tsreqdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	EXPAND_DECODE_HANDLER(TimeStampReq);
}	
