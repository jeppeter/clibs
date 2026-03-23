#include "rbtree.h"



int main(int argc,char* argv[]) {
	RBTree tree;
	int i;
	int val;
	for(i=1;i<argc; i+= 1) {
		val = atoi(argv[i]);
		tree.insert(val);
		tree.PrintTree(stdout);
	}



	for(i=1;i<argc;i++) {
		val = atoi(argv[i]);
		tree.deleteByVal(val);
	}

	return 0;
}