

void format_line(int tabs,FILE* fp, const char* fmt,...)
{
	int i;
	va_list ap;
	for(i=0;i<tabs;i++) {
		fprintf(fp,"    ");
	}
	va_start(ap,fmt);
	vfprintf(fp,fmt,ap);
	fprintf(fp,"\n");
	fflush(fp);
	return;
}

void debug_byte_array(int tabs,FILE* fp,ByteArray* pbarr, const char* fmt,...)
{
	int i;
	int j;
	int lasti;
	va_list ap;
	for(i=0;i<tabs;i++) {
		fprintf(fp,"    ");
	}
	va_start(ap,fmt);
	vfprintf(fp,fmt,ap);
	lasti = 0;
	for (i=0;i<pbarr->len;i++) {
		if ((i%16) == 0 ){
			if (i > 0) {
				fprintf(fp, "    ");
				while(lasti != i) {
					if (pbarr->data[lasti] >= 0x20 && pbarr->data[lasti] <= 0x7e) {
						fprintf(fp,"%c", pbarr->data[lasti]);
					} else {
						fprintf(fp, ".");
					}
					lasti ++;
				}
			}
			fprintf(fp,"\n");
			for(j=0;j<(tabs+1);j++) {
				fprintf(fp,"    ");
			}
			fprintf(fp,"0x%08x:",i);
		}
		fprintf(fp," 0x%02x",pbarr->data[i]);
	}

	if (lasti != i) {
		while((i%16) != 0) {
			fprintf(fp, "     ");
			i ++;
		}

		fprintf(fp, "    ");
		for(;lasti < pbarr->len;lasti ++) {
			if (pbarr->data[lasti] >= 0x20 && pbarr->data[lasti] <= 0x7e) {
				fprintf(fp,"%c", pbarr->data[lasti]);
			} else {
				fprintf(fp, ".");
			}
		}
	}
	fprintf(fp, "\n");
	return;
}

void debug_cert_array(int tabs,FILE* fp, CertificateArray* certarr);

void debug_signer(int tabs, FILE* fp,Signer* signer)
{
	debug_byte_array(tabs,fp, &(signer->digest),"signer digest");
	format_line(tabs,fp,"signer digest_alg [%s]", signer->digest_alg);
	format_line(tabs,fp,"signer program_name [%s]", signer->program_name);
	if (signer->chain != NULL) {
		debug_cert_array(tabs + 1 , fp, signer->chain);
	}	
	return;
}

void debug_attributes(int tabs, FILE* fp,Attributes * pattr)
{
	debug_byte_array(tabs, fp, &(pattr->country),"country");
	debug_byte_array(tabs, fp, &(pattr->organization),"organization");
	debug_byte_array(tabs, fp, &(pattr->organizationalUnit),"organizationalUnit");
	debug_byte_array(tabs, fp, &(pattr->nameQualifier),"nameQualifier");
	debug_byte_array(tabs, fp, &(pattr->state),"state");
	debug_byte_array(tabs, fp, &(pattr->commonName),"commonName");
	debug_byte_array(tabs, fp, &(pattr->serialNumber),"serialNumber");
	debug_byte_array(tabs, fp, &(pattr->locality),"locality");
	debug_byte_array(tabs, fp, &(pattr->title),"title");
	debug_byte_array(tabs, fp, &(pattr->surname),"surname");
	debug_byte_array(tabs, fp, &(pattr->givenName),"givenName");
	debug_byte_array(tabs, fp, &(pattr->initials),"initials");
	debug_byte_array(tabs, fp, &(pattr->pseudonym),"pseudonym");
	debug_byte_array(tabs, fp, &(pattr->generationQualifier),"generationQualifier");
	debug_byte_array(tabs, fp, &(pattr->emailAddress),"emailAddress");
	return;
}


void debug_cert(int tabs,FILE* fp,Certificate* cert)
{
	format_line(tabs, fp,"version [0x%x]", cert->version);
	format_line(tabs, fp,"issuer [%s]", cert->issuer);
	format_line(tabs, fp,"subject [%s]", cert->subject);
	format_line(tabs, fp,"serial [%s]", cert->serial);
	debug_byte_array(tabs + 1, fp, &(cert->sha1),"cert sha1");
	debug_byte_array(tabs + 1, fp, &(cert->sha256),"cert sha256");
	format_line(tabs, fp,"key_alg [%s]", cert->key_alg);
	format_line(tabs, fp,"sig_alg [%s]", cert->sig_alg);
	format_line(tabs, fp,"sig_alg_oid [%s]", cert->sig_alg_oid);
	format_line(tabs, fp,"not_before [0x%x]", cert->not_before);
	format_line(tabs, fp,"not_after [0x%x]", cert->not_after);
	format_line(tabs, fp,"key [%s]", cert->key);
	format_line(tabs, fp,"issuer attributes");
	debug_attributes(tabs + 1, fp, &(cert->issuer_attrs));
	format_line(tabs, fp,"subject attributes");
	debug_attributes(tabs + 1, fp, &(cert->subject_attrs));
	return;
}

void debug_cert_array(int tabs,FILE* fp, CertificateArray* certarr)
{
	size_t i;
	for(i=0;i<certarr->count ;i++) {
		format_line(tabs,fp,"cert [%d]", i);
		debug_cert(tabs + 1, fp, certarr->certs[i]);
	}
	return;
}

void debug_counter_signature(int tabs,FILE* fp,Countersignature* csig)
{
	format_line(tabs, fp, "verify_flags [0x%x]", csig->verify_flags);
	format_line(tabs, fp, "sign_time [0x%x]", csig->sign_time);
	format_line(tabs, fp, "digest_alg [%s]", csig->digest_alg);
	debug_byte_array(tabs, fp, &(csig->digest),  "digest");

	if (csig->chain) {
		debug_cert_array(tabs + 1, fp, csig->chain);	
	}
	return;	
}

void debug_counter_sig_array(int tabs,FILE* fp,CountersignatureArray* carr)
{
	size_t i;
	for(i=0;i<carr->count;i++) {
		format_line(tabs,fp, "counter siganture [%d]", i);
		debug_counter_signature(tabs + 1, fp, carr->counters[i]);
	}
	return;
}

void debug_authenticode(int tabs, FILE* fp,Authenticode* code)
{
	format_line(tabs,fp,"verify_flags [0x%x]", code->verify_flags);
	format_line(tabs,fp,"version [0x%x]", code->version);
	format_line(tabs,fp,"digest_alg [%s]", code->digest_alg);
	debug_byte_array(tabs + 1, fp,&(code->digest), "digest byte array");
	debug_byte_array(tabs + 1, fp,&(code->file_digest), "file digest byte array");
	if (code->signer != NULL) {
		debug_signer(tabs + 1, fp, code->signer);	
	}	
	if (code->certs) {
		debug_cert_array(tabs + 1, fp, code->certs);	
	}	
	if (code->countersigs) {
		debug_counter_sig_array(tabs + 1, fp, code->countersigs);	
	}
	
}

void debug_file_auth(FILE* fp, AuthenticodeArray* parray, char* fname)
{
	size_t i;
	fprintf(fp,"dump [%s] authenticode\n", fname);
	for (i=0;i<parray->count ;i ++) {
		format_line(0,fp,"[%d] Authenticode",i);
		debug_authenticode(1,fp,parray->signatures[i]);
	}
	return;
}


int peauth_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	int i;
	char* fname=NULL;
	char* pbuf=NULL;
	int bufsize=0;
	int buflen=0;
	AuthenticodeArray *parray=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	ret = init_log_verbose(pargs);
	if (ret < 0) {
		GETERRNO(ret);
		return ret;
	}

	initialize_authenticode_parser();

	for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		fname = parsestate->leftargs[i];
		ret=  read_file_whole(fname,&pbuf,&bufsize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not read [%s] error[%d]\n", fname,ret);
			goto out;
		}
		buflen = ret;

		if (parray != NULL) {
			authenticode_array_free(parray);
			parray = NULL;
		}

		parray = parse_authenticode((const uint8_t*)pbuf,buflen);
		if (parray == NULL) {
			ret = -EINVAL;
			fprintf(stderr, "can not parse [%s] for pe format\n", fname);
			goto out;
		}

		debug_file_auth(stdout,parray,fname);
	}

	ret = 0;
	out:
	if (parray) {
		authenticode_array_free(parray);
		parray = NULL;
	}

	read_file_whole(NULL,&pbuf,&bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}