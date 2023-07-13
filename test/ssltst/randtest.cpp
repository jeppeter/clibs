
int randprivate_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	BIGNUM* rnd=NULL;
	int bits = 163;
	char *xptr=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	int num = 1;
	int top = -1;
	int bottom = 0;
	int strength = 0;
	BN_CTX* ctx=NULL;
	int i;

	init_log_verbose(pargs);


	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			bits = atoi(parsestate->leftargs[0]);
			if (parsestate->leftargs[1]) {
				top = atoi(parsestate->leftargs[1]);
				if (parsestate->leftargs[2]) {
					bottom = atoi(parsestate->leftargs[2]);
					if (parsestate->leftargs[3]) {
						strength = atoi(parsestate->leftargs[3]);
						if (parsestate->leftargs[4]) {
							num = atoi(parsestate->leftargs[4]);
						}
					}
				}
			}
		}
	}

	rnd = BN_new();
	if (rnd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		GETERRNO(ret);
		goto out;
	}

	for(i=0;i<num;i++) {
		ret = BN_priv_rand_ex(rnd,bits,top,bottom,strength,ctx);
		if (ret <= 0){
			GETERRNO(ret);
			fprintf(stderr, "[%d] rand error[%d]\n", i,ret);
			goto out;
		}
		if (xptr) {
			free(xptr);
		}
		xptr = NULL;
		xptr = BN_bn2hex(rnd);
		if (xptr == NULL) {
			GETERRNO(ret);
			goto out;
		}
		fprintf(stdout, "[%d] 0x%s\n", i,xptr);
	}


	ret = 0;
	out:
	if (rnd) {
		BN_free(rnd);
	}
	rnd = NULL;
	if (ctx) {
		BN_CTX_free(ctx);
	}
	ctx = NULL;
	if (xptr) {
		free(xptr);
	}
	xptr = NULL;
	SETERRNO(ret);
	return ret;
}

int randmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	BIGNUM* order = NULL,*privkey=NULL;
	BIGNUM* rnd = NULL;
	int ret;
	int i;
	int num = 1;
	int bytes = 10;
	unsigned char* msgbuf=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	char* xptr=NULL;
	BN_CTX* ctx=NULL;

	init_log_verbose(pargs);

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			order = get_bn(parsestate->leftargs[0]);
			if (order == NULL) {
				GETERRNO(ret);
				goto out;
			}
			if (parsestate->leftargs[1]) {
			privkey = get_bn(parsestate->leftargs[1]);
			if (privkey == NULL) {
				GETERRNO(ret);
				goto out;
			}
			if (parsestate->leftargs[2]) {
				bytes = atoi(parsestate->leftargs[2]);
				if (parsestate->leftargs[3]) {
					num = atoi(parsestate->leftargs[3]);
				}
			}
			}
		}		
	}

	if (order == NULL || privkey == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need order and privkey\n");
		goto out;
	}

	if (bytes > 0) {
		msgbuf = (unsigned char*)malloc(bytes);
		if (msgbuf == NULL) {
			GETERRNO(ret);
			goto out;
		}
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		GETERRNO(ret);
		goto out;
	}

	rnd = BN_new();
	if (rnd == NULL) {
		GETERRNO(ret);
		goto out;
	}


	for(i=0;i<num;i++) {
		if (msgbuf) {
			memset(msgbuf,0,bytes);
		}
		ret = BN_generate_dsa_nonce(rnd,order,privkey,msgbuf,bytes,ctx);
		if (ret <= 0){
			GETERRNO(ret);
			fprintf(stderr, "[%d] dsa_nonce error [%d]\n", i, ret);
			goto out;
		}

		if (xptr) {
			free(xptr);
		}
		xptr = NULL;
		xptr = BN_bn2hex(rnd);
		fprintf(stdout, "[%d] number 0x%s\n", i, xptr);
	}

	ret = 0;

out:
	if (msgbuf) {
		free(msgbuf);
	}
	msgbuf = NULL;
	if (ctx) {
		BN_CTX_free(ctx);
	}
	ctx = NULL;
	if (order) {
		BN_free(order);
	}
	order = NULL;
	if (privkey) {
		BN_free(privkey);
	}
	privkey = NULL;
	if (rnd) {
		BN_free(rnd);
	}
	rnd = NULL;
	SETERRNO(ret);
	return ret;
}