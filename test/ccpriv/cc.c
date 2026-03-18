#include "cc.h"
#include "cc_priv.h"
#include <stdlib.h>

CC_PRIV* new_cc(int a,int b)
{
	CC_PRIV* pret=NULL;
	pret = malloc(sizeof(*pret));
	pret->a = a;
	pret->b = b;
	return pret;
}

void free_cc(CC_PRIV** ppret)
{
	if (ppret && *ppret) {
		free(*ppret);
		*ppret = NULL;
	}
}

int get_a(CC_PRIV* pret)
{
	return pret->a;
}

int get_b(CC_PRIV* pret)
{
	return pret->b;
}

int set_a(CC_PRIV* pret,int a)
{
	int ret = pret->a;
	pret->a = a;
	return ret;
}

int set_b(CC_PRIV* pret, int b)
{
	int ret = pret->b;
	pret->b = b;
	return ret;
}