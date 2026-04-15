#define _HAS_EXCEPTIONS 0
#include <class.h>

int main(int argc,char* argv[])
{
	if (argc != 0) {
		argc = argc;
	}
	if (argv != NULL) {
		argv = argv;
	}
	ExpClass* pcls = new ExpClass();
	pcls->print_hello("cc");
	pcls->put_i(3);
	pcls->put_map_i(3,9);
	delete pcls;
	return 0;
}