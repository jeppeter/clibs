#include "cc.h"
#include <stdio.h>

int main(int argc,char* argv[])
{
	CC_PRIV* pret = new_cc(1,2);
	argc = argc;
	if (argv) {
		argv = argv;
	}

	printf("a %d b %d\n",get_a(pret),get_b(pret));
	set_a(pret,3);
	set_b(pret,4);
	printf("a %d b %d\n",get_a(pret),get_b(pret));

	free_cc(&pret);

	return 0;
}