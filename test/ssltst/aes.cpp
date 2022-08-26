
int hex_value(char v,int* perr)
{
	int retval = 0;
	if (v >= '0' && v <= '9') {
		retval = v - '0';
	} else if (v >= 'a' && v <= 'f') {
		retval = v - 'a' + 10;
	} else if (v >= 'A' && v <= 'F') {
		retval = v - 'A' + 10;
	} else {
		if (perr) {
			*perr = 1;
		}
	}
	return retval;
}


int parse_hex_string(const char* hexstr,uint8_t** ppv8,int* psize)
{
	int ret;
	int slen = 0;
	int idx;
	int didx;
	uint8_t* pretv8=NULL;
	int retsize=0;
	int retlen=0;
	int errnum = 0;
	if (hexstr == NULL) {
		if (ppv8 && *ppv8) {
			free(*ppv8);
			*ppv8 = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppv8 == NULL || psize == NULL) {
		ret=  -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (*ppv8 == NULL && *psize != 0) {
		ret=  -EINVAL;
		SETERRNO(ret);
		return ret;		
	}

	pretv8 = *ppv8;
	retsize = *psize;

	slen = (int)strlen(hexstr);
	if (slen > 0) {
		idx = 0;
		didx = 0;
		retlen = slen / 2;
		if ((slen % 2) != 0){
			retlen ++;
			idx = 1;
		}
		if (retlen > retsize) {
			retsize = retlen;
			pretv8 = (uint8_t*)malloc(retlen);
			if (pretv8 ==NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}
		memset(pretv8,0,retsize);

		if (idx > 0) {
			pretv8[didx] = hex_value(hexstr[0],&errnum);
			didx = 1;
		}

		while (idx < slen) {
			pretv8[didx] |= (hex_value(hexstr[idx],&errnum) << 4);
			pretv8[didx] |= hex_value(hexstr[idx+1],&errnum);
			idx += 2;
			didx += 1;
		}
	}

	if (errnum != 0) {
		ret = -EINVAL;
		goto fail;
	}

	if (*ppv8 && *ppv8 != pretv8) {
		free(*ppv8);
	}
	*ppv8 = pretv8;
	*psize = retsize;
	return retlen;
fail:
	if (pretv8 && pretv8 != *ppv8) {
		free(pretv8);
	}
	pretv8 = NULL;
	retsize = 0;
	SETERRNO(ret);
	return ret;
}


int aes256cfbenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	uint8_t* pkey=NULL;
	int keylen=0;
	int keysize=0;
	uint8_t* piv=NULL;
	int ivlen=0;
	int ivsize=0;
	int idx=0;
	char* inbuf=NULL,*outbuf=NULL;
	int insize=0,outsize=0;
	int inlen=0,outlen =0;
	char* ptmp=NULL;

	pargs_options_t pargs =(pargs_options_t)popt;
	gcry_cipher_hd_t hd = NULL;
	gcry_error_t err = 0;

	init_log_verbose(pargs);

	if (parsestate->leftargs && parsestate->leftargs[idx]) {
		ret = parse_hex_string(parsestate->leftargs[idx],&pkey,&keysize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s] not valid key\n", parsestate->leftargs[idx]);
			goto out;
		}
		keylen = ret;
		idx += 1;
	}

	if (parsestate->leftargs && parsestate->leftargs[idx]) {
		ret = parse_hex_string(parsestate->leftargs[idx],&piv,&ivsize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s] not valid key\n", parsestate->leftargs[idx]);
			goto out;
		}
		ivlen = ret;
		idx += 1;
	}

	if (pkey == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "must spcified key\n");
		goto out;
	}

	DEBUG_BUFFER_FMT(pkey,keylen,"key");
	DEBUG_BUFFER_FMT(piv,ivlen,"iv");


	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("read [%s] error[%d]", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}
	inlen = ret;

	err = gcry_cipher_open(&hd,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CFB,GCRY_CIPHER_SECURE);
	if (err) {
		GETERRNO(ret);
		ERROR_INFO("open GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CFB,GCRY_CIPHER_SECURE error[%d]",ret);
		goto out;
	}

	err = gcry_cipher_setkey(hd,pkey,keylen);
	if (err) {
		GETERRNO(ret);
		ERROR_BUFFER_FMT(pkey,keylen,"set key error[%d]",ret);
		goto out;
	}

	err = gcry_cipher_setiv(hd,piv,ivlen);
	if (err) {
		GETERRNO(ret);
		ERROR_BUFFER_FMT(piv,ivlen,"set iv error[%d]",ret);
		goto out;		
	}

	if (pargs->m_input == NULL) {
		ret = read_stdin_whole(0, &inbuf, &insize);
	} else {
		ret = read_file_whole(pargs->m_input, &inbuf, &insize);
	}

	inlen = ret;


	outsize = inlen;
	outbuf = (char*)malloc(outsize);
	if (outbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}

	memset(outbuf,0,outsize);
	outlen = outsize;
	outlen = inlen;

	err = gcry_cipher_encrypt(hd,outbuf,inlen,inbuf,inlen);
	if (err) {
		GETERRNO(ret);
		ERROR_INFO("encrypt buffer error[%d]",ret);
		goto out;
	}

	DEBUG_BUFFER_FMT(outbuf,inlen,"encrypt [%s]", pargs->m_input ? pargs->m_input : "stdin");

	while (parsestate->leftargs && parsestate->leftargs[idx]) {
		char* fname = parsestate->leftargs[idx];

		ret = read_file_whole(fname,&inbuf,&insize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("can not read[%s] error[%d]", fname,ret);
			goto out;
		}
		inlen = ret;

		if (outsize < (outlen + inlen)) {
			outsize = (outlen + inlen);
			ptmp = (char*) malloc(outsize);
			if (ptmp == NULL) {
				GETERRNO(ret);
				goto out;
			}

			memset(ptmp,0,outsize);
			if (outlen > 0) {
				memcpy(ptmp, outbuf, outlen);
			}
			if (outbuf != NULL) {
				free(outbuf);
			}
			outbuf = ptmp;
			ptmp = NULL;
		}

		err = gcry_cipher_encrypt(hd,&outbuf[outlen],inlen,inbuf,inlen);
		if (err) {
			GETERRNO(ret);
			ERROR_INFO("encrypt buffer error[%d]",ret);
			goto out;
		}

		DEBUG_BUFFER_FMT(&(outbuf[outlen]),inlen,"for [%s] encrypt", fname);
		outlen += inlen;
		idx += 1;
	}

	if (pargs->m_output) {
		ret = write_file_whole(pargs->m_output,outbuf,outlen);
	} else {
		ret = write_out_whole(STDOUT_FILE_FLAG,outbuf,outlen);
	}

	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("write [%s] error[%d]", pargs->m_output ? pargs->m_output : "stdout", ret);
		goto out;
	}

	DEBUG_BUFFER_FMT(outbuf,outlen, "encrypt buffer");
	ret = 0;
out:
	if(ptmp) {
		free(ptmp);
	}

	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;
	outlen = 0;
	outsize = 0;

	if (pargs->m_input) {
		read_stdin_whole(1,&inbuf,&insize);
	} else {
		read_file_whole(NULL,&inbuf,&insize);
	}

	if (hd != NULL) {
		gcry_cipher_close(hd);
	}
	hd = NULL;
	parse_hex_string(NULL,&pkey,&keysize);
	keylen = 0;
	parse_hex_string(NULL,&piv,&ivsize);
	ivlen = 0;
	SETERRNO(ret);
	return ret;
}

int aes256cfbdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	uint8_t* pkey=NULL;
	int keylen=0;
	int keysize=0;
	uint8_t* piv=NULL;
	int ivlen=0;
	int ivsize=0;
	int idx=0;
	char* inbuf=NULL,*outbuf=NULL;
	int insize=0,outsize=0;
	int inlen=0,outlen =0;
	char* ptmp=NULL;

	pargs_options_t pargs =(pargs_options_t)popt;
	gcry_cipher_hd_t hd = NULL;
	gcry_error_t err = 0;

	init_log_verbose(pargs);

	if (parsestate->leftargs && parsestate->leftargs[idx]) {
		ret = parse_hex_string(parsestate->leftargs[idx],&pkey,&keysize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s] not valid key\n", parsestate->leftargs[idx]);
			goto out;
		}
		keylen = ret;
		idx += 1;
	}

	if (parsestate->leftargs && parsestate->leftargs[idx]) {
		ret = parse_hex_string(parsestate->leftargs[idx],&piv,&ivsize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "[%s] not valid key\n", parsestate->leftargs[idx]);
			goto out;
		}
		ivlen = ret;
		idx += 1;
	}

	if (pkey == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "must spcified key\n");
		goto out;
	}

	DEBUG_BUFFER_FMT(pkey,keylen,"key");
	DEBUG_BUFFER_FMT(piv,ivlen,"iv");


	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("read [%s] error[%d]", pargs->m_input ? pargs->m_input : "stdin", ret);
		goto out;
	}
	inlen = ret;

	err = gcry_cipher_open(&hd,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CFB,GCRY_CIPHER_SECURE);
	if (err) {
		GETERRNO(ret);
		ERROR_INFO("open GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CFB,GCRY_CIPHER_SECURE error[%d]",ret);
		goto out;
	}

	err = gcry_cipher_setkey(hd,pkey,keylen);
	if (err) {
		GETERRNO(ret);
		ERROR_BUFFER_FMT(pkey,keylen,"set key error[%d]",ret);
		goto out;
	}

	err = gcry_cipher_setiv(hd,piv,ivlen);
	if (err) {
		GETERRNO(ret);
		ERROR_BUFFER_FMT(piv,ivlen,"set iv error[%d]",ret);
		goto out;		
	}

	if (pargs->m_input == NULL) {
		ret = read_stdin_whole(0, &inbuf, &insize);
	} else {
		ret = read_file_whole(pargs->m_input, &inbuf, &insize);
	}

	inlen = ret;


	outsize = inlen;
	outbuf = (char*)malloc(outsize);
	if (outbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}

	memset(outbuf,0,outsize);
	outlen = outsize;
	outlen = inlen;

	err = gcry_cipher_decrypt(hd,outbuf,inlen,inbuf,inlen);
	if (err) {
		GETERRNO(ret);
		ERROR_INFO("encrypt buffer error[%d]",ret);
		goto out;
	}

	while (parsestate->leftargs && parsestate->leftargs[idx]) {
		char* fname = parsestate->leftargs[idx];

		ret = read_file_whole(fname,&inbuf,&insize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("can not read[%s] error[%d]", fname,ret);
			goto out;
		}
		inlen = ret;

		if (outsize < (outlen + inlen)) {
			outsize = (outlen + inlen);
			ptmp = (char*) malloc(outsize);
			if (ptmp == NULL) {
				GETERRNO(ret);
				goto out;
			}

			memset(ptmp,0,outsize);
			if (outlen > 0) {
				memcpy(ptmp, outbuf, outlen);
			}
			if (outbuf != NULL) {
				free(outbuf);
			}
			outbuf = ptmp;
			ptmp = NULL;
		}

		err = gcry_cipher_decrypt(hd,&outbuf[outlen],inlen,inbuf,inlen);
		if (err) {
			GETERRNO(ret);
			ERROR_INFO("encrypt buffer error[%d]",ret);
			goto out;
		}

		DEBUG_BUFFER_FMT(&(outbuf[outlen]),inlen,"for [%s] encrypt", fname);
		outlen += inlen;
		idx += 1;
	}

	if (pargs->m_output) {
		ret = write_file_whole(pargs->m_output,outbuf,outlen);
	} else {
		ret = write_out_whole(STDOUT_FILE_FLAG,outbuf,outlen);
	}

	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("write [%s] error[%d]", pargs->m_output ? pargs->m_output : "stdout", ret);
		goto out;
	}

	DEBUG_BUFFER_FMT(outbuf,outlen, "encrypt buffer");
	ret = 0;
out:
	if(ptmp) {
		free(ptmp);
	}

	if (outbuf) {
		free(outbuf);
	}
	outbuf = NULL;
	outlen = 0;
	outsize = 0;

	if (pargs->m_input) {
		read_stdin_whole(1,&inbuf,&insize);
	} else {
		read_file_whole(NULL,&inbuf,&insize);
	}

	if (hd != NULL) {
		gcry_cipher_close(hd);
	}
	hd = NULL;
	parse_hex_string(NULL,&pkey,&keysize);
	keylen = 0;
	parse_hex_string(NULL,&piv,&ivsize);
	ivlen = 0;
	SETERRNO(ret);
	return ret;
}