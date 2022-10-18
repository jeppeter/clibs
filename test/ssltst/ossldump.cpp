

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

int spcstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	return 0;
}

int spcstrdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	return 0;
}