#ifndef __RBTREE_H_74FBCB78B536A0BA8FFEE420F40DC210__
#define __RBTREE_H_74FBCB78B536A0BA8FFEE420F40DC210__

#include <iostream>
#include <queue>
#include <stdlib.h>
#include <stdio.h>

#define DEBUG_INFO(...) do{fprintf(stdout,"[%s:%d] ",__FILE__,__LINE__); fprintf(stdout,__VA_ARGS__); fprintf(stdout,"\n"); fflush(stdout);} while(0)

enum COLOR { RED, BLACK };

class RBNode {
public:
  int val;
  COLOR color;
  RBNode *left, *right, *parent;
  RBNode(int val);
  RBNode *uncle();
  bool isOnLeft();
  RBNode *sibling();
  void moveDown(RBNode *nParent);
  bool hasRedChild();
};

class RBTree {
private:
  RBNode *root;
  void leftRotate(RBNode *x);
  void rightRotate(RBNode *x);
  void swapColors(RBNode *x1, RBNode *x2);
  void swapValues(RBNode *u, RBNode *v);
  void fixRedRed(RBNode *x);
  RBNode *successor(RBNode *x);
  RBNode *BSTreplace(RBNode *x);
  void deleteRBNode(RBNode *v);
  void fixDoubleBlack(RBNode *x);
public:
	RBTree();
	RBNode *getRoot();
	RBNode *search(int n);
	void insert(int n);
	void deleteByVal(int n);
	void PrintTree(FILE* fp);
	void PrintNode(FILE* fp, RBNode* node,int tab);
};

#endif /* __RBTREE_H_74FBCB78B536A0BA8FFEE420F40DC210__ */
