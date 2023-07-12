
BIGNUM* get_bn(const char* str)
{
	int slen = 0;
	char* ptr = NULL;
	int base = 10;
	BIGNUM* bn = NULL;
	int ret;

	slen = strlen(str);
	ptr = (char*)str;
	if (strncasecmp(str, "0x", 2) == 0) {
		slen -= 2;
		ptr += 2;
		base = 16;
	} else if (strncasecmp(str, "x", 1) == 0) {
		slen -= 1;
		ptr += 1;
		base = 16;
	}

	bn = BN_new();
	if (bn == NULL) {
		GETERRNO(ret);
		ERROR_INFO("BN_value_one error[%d]", ret);
		goto fail;
	}

	while (slen > 0) {
		int word = 0;
		if (*ptr >= '0' && *ptr <= '9') {
			word = *ptr - '0';
		} else if (base == 16 && *ptr >= 'a' && *ptr <= 'f') {
			word = *ptr - 'a'  + 10;
		} else if (base == 16 && *ptr >= 'A' && *ptr <= 'F') {
			word = *ptr - 'A' + 10;
		} else {
			ret = -EINVAL;
			ERROR_INFO("ptr [0x%x] not valid", *ptr);
			goto fail;
		}
		BN_mul_word(bn, base);
		BN_add_word(bn, word);
		slen --;
		ptr ++;
	}

	return bn;
fail:
	if (bn) {
		BN_free(bn);
	}
	bn = NULL;
	SETERRNO(ret);
	return NULL;
}


static void bn_GF2m_mul_1x1(uint64_t *r1, uint64_t *r0, const uint64_t a,
                            const uint64_t b)
{
	uint64_t h, l, s;
	uint64_t tab[16], top3b = a >> 61;
	uint64_t a1, a2, a4, a8;

	a1 = a & (0x1FFFFFFFFFFFFFFFULL);
	a2 = a1 << 1;
	a4 = a2 << 1;
	a8 = a4 << 1;

	tab[0] = 0;
	tab[1] = a1;
	tab[2] = a2;
	tab[3] = a1 ^ a2;
	tab[4] = a4;
	tab[5] = a1 ^ a4;
	tab[6] = a2 ^ a4;
	tab[7] = a1 ^ a2 ^ a4;
	tab[8] = a8;
	tab[9] = a1 ^ a8;
	tab[10] = a2 ^ a8;
	tab[11] = a1 ^ a2 ^ a8;
	tab[12] = a4 ^ a8;
	tab[13] = a1 ^ a4 ^ a8;
	tab[14] = a2 ^ a4 ^ a8;
	tab[15] = a1 ^ a2 ^ a4 ^ a8;

	s = tab[b & 0xF];
	l = s;
	s = tab[b >> 4 & 0xF];
	l ^= s << 4;
	h = s >> 60;
	s = tab[b >> 8 & 0xF];
	l ^= s << 8;
	h ^= s >> 56;
	s = tab[b >> 12 & 0xF];
	l ^= s << 12;
	h ^= s >> 52;
	s = tab[b >> 16 & 0xF];
	l ^= s << 16;
	h ^= s >> 48;
	s = tab[b >> 20 & 0xF];
	l ^= s << 20;
	h ^= s >> 44;
	s = tab[b >> 24 & 0xF];
	l ^= s << 24;
	h ^= s >> 40;
	s = tab[b >> 28 & 0xF];
	l ^= s << 28;
	h ^= s >> 36;
	s = tab[b >> 32 & 0xF];
	l ^= s << 32;
	h ^= s >> 32;
	s = tab[b >> 36 & 0xF];
	l ^= s << 36;
	h ^= s >> 28;
	s = tab[b >> 40 & 0xF];
	l ^= s << 40;
	h ^= s >> 24;
	s = tab[b >> 44 & 0xF];
	l ^= s << 44;
	h ^= s >> 20;
	s = tab[b >> 48 & 0xF];
	l ^= s << 48;
	h ^= s >> 16;
	s = tab[b >> 52 & 0xF];
	l ^= s << 52;
	h ^= s >> 12;
	s = tab[b >> 56 & 0xF];
	l ^= s << 56;
	h ^= s >> 8;
	s = tab[b >> 60];
	l ^= s << 60;
	h ^= s >> 4;

	/* compensate for the top three bits of a */

	if (top3b & 01) {
		l ^= b << 61;
		h ^= b >> 3;
	}
	if (top3b & 02) {
		l ^= b << 62;
		h ^= b >> 2;
	}
	if (top3b & 04) {
		l ^= b << 63;
		h ^= b >> 1;
	}

	*r1 = h;
	*r0 = l;
}


int bnbinmul_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	uint64_t a = 0, b = 0;
	uint64_t rh, rl;
	int idx = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;

	init_log_verbose(pargs);

	GET_OPT_TYPE(a, "a", uint64_t);
	GET_OPT_TYPE(b, "b", uint64_t);

	bn_GF2m_mul_1x1(&rh, &rl, a, b);

	fprintf(stdout, " 0x%016lx x 0x%016lx = 0x%016lx%016lx\n", a, b, rh, rl);

out:
	ret = 0;
	SETERRNO(ret);
	return ret;
}

int binadd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	BIGNUM *aval = NULL, *bval = NULL, *cval = NULL;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	init_log_verbose(pargs);
	char* xptr = NULL;

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			aval = get_bn(parsestate->leftargs[0]);
			if (aval == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "can not parse [%s] error[%d]\n", parsestate->leftargs[0], ret);
				goto out;
			}

			if (parsestate->leftargs[1]) {
				bval = get_bn(parsestate->leftargs[1]);
				if (bval == NULL) {
					GETERRNO(ret);
					fprintf(stderr, "can not parse [%s] error[%d]\n", parsestate->leftargs[1], ret );
					goto out;
				}
			}
		}
	}

	if (aval == NULL || bval == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need anum bnum\n");
		goto out;
	}

	cval = BN_new();
	if (cval == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = BN_GF2m_add(cval, aval, bval);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "add value error [%d]\n", ret);
		goto out;
	}

	xptr = BN_bn2hex(cval);
	if (xptr == NULL) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "%s + %s = 0x%s\n", parsestate->leftargs[0], parsestate->leftargs[1], xptr);
	ret = 0;
out:
	if (xptr) {
		free(xptr);
	}
	xptr = NULL;

	if (aval) {
		BN_free(aval);
	}
	aval = NULL;
	if (bval) {
		BN_free(bval);
	}
	bval = NULL;
	SETERRNO(ret);
	return ret;

}

int binmulmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	BIGNUM *aval = NULL, *bval = NULL, *pval = NULL, *rval = NULL;
	BN_CTX *ctx = NULL;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	init_log_verbose(pargs);
	char* rptr = NULL, *aptr = NULL, *bptr = NULL;

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			aval = get_bn(parsestate->leftargs[0]);
			if (aval == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "can not parse [%s] error[%d]\n", parsestate->leftargs[0], ret);
				goto out;
			}

			if (parsestate->leftargs[1]) {
				bval = get_bn(parsestate->leftargs[1]);
				if (bval == NULL) {
					GETERRNO(ret);
					fprintf(stderr, "can not parse [%s] error[%d]\n", parsestate->leftargs[1], ret );
					goto out;
				}

				if (parsestate->leftargs[2]) {
					pval = get_bn(parsestate->leftargs[2]);
					if (pval == NULL) {
						GETERRNO(ret);
						fprintf(stderr, "can not parse [%s] error[%d]\n", parsestate->leftargs[2], ret );
						goto out;
					}
				}
			}
		}
	}

	if (aval == NULL || bval == NULL || pval == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need anum bnum pnum\n");
		goto out;
	}

	rval = BN_new();
	if (rval == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = BN_GF2m_mod_mul(rval, aval, bval, pval, ctx);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "BN_GF2m_mod_mul error[%d]\n", ret);
		goto out;
	}

	rptr = BN_bn2hex(rval);
	if (rptr == NULL) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "%s * %s = 0x%s %% %s\n", parsestate->leftargs[0], parsestate->leftargs[1], rptr,parsestate->leftargs[2]);
	ret = 0;
out:
	if (aptr) {
		free(aptr);
	}
	aptr = NULL;
	if (bptr) {
		free(bptr);
	}
	bptr = NULL;
	if (rptr) {
		free(rptr);
	}
	rptr = NULL;

	if (aval) {
		BN_free(aval);
	}
	aval = NULL;
	if (bval) {
		BN_free(bval);
	}
	bval = NULL;
	if (rval) {
		BN_free(rval);
	}
	rval = NULL;
	if (pval) {
		BN_free(pval);
	}
	pval = NULL;
	if (ctx) {
		BN_CTX_free(ctx);
	}
	ctx = NULL;

	SETERRNO(ret);
	return ret;

}

int binmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	BIGNUM *aval = NULL, *pval = NULL, *rval = NULL;
	char* rptr = NULL;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	init_log_verbose(pargs);

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			aval = get_bn(parsestate->leftargs[0]);
			if (aval == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "parse [%s] error[%d]\n", parsestate->leftargs[0], ret);
				goto out;
			}
			if (parsestate->leftargs[1]) {
				pval = get_bn(parsestate->leftargs[1]);
				if (pval == NULL) {
					GETERRNO(ret);
					fprintf(stderr, "parse [%s] error[%d]\n", parsestate->leftargs[1], ret);
					goto out;
				}
			}
		}
	}

	if (aval == NULL || pval == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need aval and pval\n");
		goto out;
	}

	rval = BN_new();
	if (rval == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret= BN_GF2m_mod(rval,aval,pval);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "BN_GF2m_mod error[%d]\n", ret);
		goto out;
	}

	rptr = BN_bn2hex(rval);
	if (rptr == NULL) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "%s %% %s = 0x%s\n", parsestate->leftargs[0],parsestate->leftargs[1], rptr);

	ret = 0;
out:
	if (rptr) {
		free(rptr);
	}
	rptr = NULL;

	if (aval) {
		BN_free(aval);
	}
	aval = NULL;
	if (pval) {
		BN_free(pval);
	}
	pval = NULL;
	SETERRNO(ret);
	return ret;
}

int bininv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	BIGNUM *aval = NULL, *pval = NULL, *rval = NULL;
	char* rptr = NULL;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	BN_CTX *ctx= NULL;
	init_log_verbose(pargs);

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			aval = get_bn(parsestate->leftargs[0]);
			if (aval == NULL) {
				GETERRNO(ret);
				fprintf(stderr, "parse [%s] error[%d]\n", parsestate->leftargs[0], ret);
				goto out;
			}
			if (parsestate->leftargs[1]) {
				pval = get_bn(parsestate->leftargs[1]);
				if (pval == NULL) {
					GETERRNO(ret);
					fprintf(stderr, "parse [%s] error[%d]\n", parsestate->leftargs[1], ret);
					goto out;
				}
			}
		}
	}

	if (aval == NULL || pval == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need aval and pval\n");
		goto out;
	}

	rval = BN_new();
	if (rval == NULL) {
		GETERRNO(ret);
		goto out;
	}
	ctx = BN_CTX_new();
	if (ctx == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret= BN_GF2m_mod_inv(rval,aval,pval,ctx);
	if (ret <= 0) {
		GETERRNO(ret);
		fprintf(stderr, "BN_GF2m_mod_inv error[%d]\n", ret);
		goto out;
	}

	rptr = BN_bn2hex(rval);
	if (rptr == NULL) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "%s * 0x%s = 1 %% 0x%s\n", parsestate->leftargs[0],rptr,parsestate->leftargs[1]);

	ret = 0;
out:
	if (ctx) {
		BN_CTX_free(ctx);
	}
	ctx = NULL;

	if (rptr) {
		free(rptr);
	}
	rptr = NULL;

	if (aval) {
		BN_free(aval);
	}
	aval = NULL;
	if (pval) {
		BN_free(pval);
	}
	pval = NULL;
	SETERRNO(ret);
	return ret;
}