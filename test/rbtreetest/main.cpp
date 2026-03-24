#define _HAS_EXCEPTIONS 0
#include "rbtree.h"

#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1910
#pragma warning(disable:5045)
#endif
#endif


int main(int argc,char* argv[]) {
	RBTree tree;
	int i;
	int val;
	for(i=1;i<argc; i+= 1) {
		val = atoi(argv[i]);
		if (val < 0) {
			conitnue;
		}
		tree.insert(val);
		fprintf(stderr,"after insert %d\n",val);
		tree.PrintTree(stderr);
	}



	for(i=1;i<argc;i++) {
		val = atoi(argv[i]);
		if (val < 0) {
			tree.deleteByVal(-val);
			fprintf(stderr,"after delete %d\n",-val);
			tree.PrintTree(stderr);
		}
	}

	return 0;
}

#pragma warning(pop)