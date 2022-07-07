#include <openssl/pkcs7.h>

#define NID_pkcs7_data_ex   21

int pkcs7octstrenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	PKCS7* p7=NULL;
	char* str = NULL;
	int slen = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	ASN1_OCTET_STRING* octstr=NULL;
	FILE* fp=NULL;
	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}

	DEBUG_INFO(" ");

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		str = parsestate->leftargs[0];
		slen = (int) strlen(str);
	}

	DEBUG_INFO(" ");


	p7 = PKCS7_new_ex(NULL,NULL);
	if (p7 == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not new PKCS7 error[%d]\n", ret);
		goto out;
	}

	DEBUG_INFO(" ");

	ret = PKCS7_set_type(p7,NID_pkcs7_data_ex);
	if (ret == 0) {
		ret = -EINVAL;
		fprintf(stderr, "can not set NID_pkcs7_data\n");
		goto out;
	}

	DEBUG_INFO(" ");


	octstr = (ASN1_OCTET_STRING*)p7->d.data;
	if (str != NULL) {
		if (octstr == NULL) {
			ret = -EINVAL;
			fprintf(stderr, "data null\n");
			goto out;
		}

		DEBUG_INFO(" ");

		ret = ASN1_STRING_set((ASN1_STRING*) octstr, str,slen);
		if (ret == 0) {
			ret = -EINVAL;
			fprintf(stderr, "set [%s] error\n", str);
			goto out;
		}		
	} else {
		if (octstr != NULL) {
			ASN1_OCTET_STRING_free(octstr);
		}
		p7->d.data = NULL;
	}


	DEBUG_INFO(" ");
	if (pargs->m_output != NULL) {
		fp = fopen(pargs->m_output,"wb");
		if (fp == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for write\n", pargs->m_output);
			goto out;
		}
	} else {
		fp = stdout;
	}

	DEBUG_INFO(" ");

	ret = i2d_PKCS7_fp(fp,p7);
	if (ret == 0) {
		ret=  -EINVAL;
		fprintf(stderr, "out [%s] error\n", pargs->m_output != NULL ? pargs->m_output : "stdout");
		goto out;
	}

	ret = 0;
out:
	if (fp != NULL && fp != stdout) {
		fclose(fp);
	}
	fp = NULL;
	PKCS7_free(p7);
	p7 = NULL;
	SETERRNO(ret);
	return ret;

}

int pkcs7dump_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	PKCS7* p7=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	FILE* fout=NULL,*fin = NULL;

	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}

	if (pargs->m_input != NULL) {
		fin = fopen(pargs->m_input,"rb");
		if (fin == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for read\n", pargs->m_input);
			goto out;
		}
	} else {
		fin = stdin;
	}

	p7 = d2i_PKCS7_fp(fin,NULL);
	if (p7 == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not read PKCS7 from [%s] error[%d]\n", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}



	DEBUG_INFO(" ");
	if (pargs->m_output != NULL) {
		fout = fopen(pargs->m_output,"wb");
		if (fout == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not open [%s] for write\n", pargs->m_output);
			goto out;
		}
	} else {
		fout = stdout;
	}

	ret = i2d_PKCS7_fp(fout,p7);
	if (ret == 0) {
		ret=  -EINVAL;
		fprintf(stderr, "out [%s] error\n", pargs->m_output != NULL ? pargs->m_output : "stdout");
		goto out;
	}


	ret = 0;
out:
	if (fin != NULL && fin != stdin) {
		fclose(fin);
	}
	fin = NULL;

	if (fout != NULL && fout != stdout) {
		fclose(fout);
	}
	fout = NULL;
	PKCS7_free(p7);
	p7 = NULL;
	SETERRNO(ret);
	return ret;
}