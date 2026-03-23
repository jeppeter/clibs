#define _HAS_EXCEPTIONS 0
#include "rbtree.h"


  RBNode::RBNode(int val) : val(val) {
    parent = left = right = NULL;

    // RBNode is created during insertion
    // RBNode is red at insertion
    color = RED;
  }

  // returns pointer to uncle
  RBNode *RBNode::uncle() {
    // If no parent or grandparent, then no uncle
    if (parent == NULL || parent->parent == NULL)
      return NULL;

    if (parent->isOnLeft())
      // uncle on right
      return parent->parent->right;
    else
      // uncle on left
      return parent->parent->left;
  }

  // check if node is left child of parent
  bool RBNode::isOnLeft() { return this == parent->left; }

  // returns pointer to sibling
  RBNode *RBNode::sibling() {
    // sibling null if no parent
    if (parent == NULL)
      return NULL;

    if (isOnLeft())
      return parent->right;

    return parent->left;
  }

  // moves node down and moves given node in its place
  void RBNode::moveDown(RBNode *nParent) {
    if (parent != NULL) {
      if (isOnLeft()) {
        parent->left = nParent;
      } else {
        parent->right = nParent;
      }
    }
    nParent->parent = parent;
    parent = nParent;
  }

  bool RBNode::hasRedChild() {
    return (left != NULL && left->color == RED) ||
           (right != NULL && right->color == RED);
  }


  // left rotates the given node
  void RBTree::leftRotate(RBNode *x) {
    // new parent will be node's right child
    RBNode *nParent = x->right;

    // update root if current node is root
    if (x == root)
      root = nParent;

    x->moveDown(nParent);

    // connect x with new parent's left element
    x->right = nParent->left;
    // connect new parent's left element with node
    // if it is not null
    if (nParent->left != NULL)
      nParent->left->parent = x;

    // connect new parent with x
    nParent->left = x;
  }

  void RBTree::rightRotate(RBNode *x) {
    // new parent will be node's left child
    RBNode *nParent = x->left;

    // update root if current node is root
    if (x == root)
      root = nParent;

    x->moveDown(nParent);

    // connect x with new parent's right element
    x->left = nParent->right;
    // connect new parent's right element with node
    // if it is not null
    if (nParent->right != NULL)
      nParent->right->parent = x;

    // connect new parent with x
    nParent->right = x;
  }

  void RBTree::swapColors(RBNode *x1, RBNode *x2) {
    COLOR temp;
    temp = x1->color;
    x1->color = x2->color;
    x2->color = temp;
  }

  void RBTree::swapValues(RBNode *u, RBNode *v) {
    int temp;
    temp = u->val;
    u->val = v->val;
    v->val = temp;
  }

  // fix red red at given node
  void RBTree::fixRedRed(RBNode *x) {
    // if x is root color it black and return
    if (x == root) {
      x->color = BLACK;
      return;
    }

    // initialize parent, grandparent, uncle
    RBNode *parent = x->parent, *grandparent = parent->parent,
         *uncle = x->uncle();

    if (parent->color != BLACK) {
      if (uncle != NULL && uncle->color == RED) {
        // uncle red, perform recoloring and recurse
        parent->color = BLACK;
        uncle->color = BLACK;
        grandparent->color = RED;
        fixRedRed(grandparent);
      } else {
        // Else perform LR, LL, RL, RR
        if (parent->isOnLeft()) {
          if (x->isOnLeft()) {
            // for left right
            swapColors(parent, grandparent);
          } else {
            leftRotate(parent);
            swapColors(x, grandparent);
          }
          // for left left and left right
          rightRotate(grandparent);
        } else {
          if (x->isOnLeft()) {
            // for right left
            rightRotate(parent);
            swapColors(x, grandparent);
          } else {
            swapColors(parent, grandparent);
          }

          // for right right and right left
          leftRotate(grandparent);
        }
      }
    }
  }

  // find node that do not have a left child
  // in the subtree of the given node
  RBNode *RBTree::successor(RBNode *x) {
    RBNode *temp = x;

    while (temp->left != NULL)
      temp = temp->left;

    return temp;
  }

  // find node that replaces a deleted node in BST
  RBNode *RBTree::BSTreplace(RBNode *x) {
    // when node have 2 children
    if (x->left != NULL && x->right != NULL)
      return successor(x->right);

    // when leaf
    if (x->left == NULL && x->right == NULL)
      return NULL;

    // when single child
    if (x->left != NULL)
      return x->left;
    else
      return x->right;
  }

  // deletes the given node
  void RBTree::deleteRBNode(RBNode *v) {
    RBNode *u = BSTreplace(v);

    // True when u and v are both black
    bool uvBlack = ((u == NULL || u->color == BLACK) && (v->color == BLACK));
    RBNode *parent = v->parent;

    if (u == NULL) {
      // u is NULL therefore v is leaf
      if (v == root) {
        // v is root, making root null
        root = NULL;
      } else {
        if (uvBlack) {
          // u and v both black
          // v is leaf, fix double black at v
          fixDoubleBlack(v);
        } else {
          // u or v is red
          if (v->sibling() != NULL)
            // sibling is not null, make it red"
            v->sibling()->color = RED;
        }

        // delete v from the tree
        if (v->isOnLeft()) {
          parent->left = NULL;
        } else {
          parent->right = NULL;
        }
      }
      delete v;
      return;
    }

    if (v->left == NULL || v->right == NULL) {
      // v has 1 child
      if (v == root) {
        // v is root, assign the value of u to v, and delete u
        v->val = u->val;
        v->left = v->right = NULL;
        delete u;
      } else {
        // Detach v from tree and move u up
        if (v->isOnLeft()) {
          parent->left = u;
        } else {
          parent->right = u;
        }
        delete v;
        u->parent = parent;
        if (uvBlack) {
          // u and v both black, fix double black at u
          fixDoubleBlack(u);
        } else {
          // u or v red, color u black
          u->color = BLACK;
        }
      }
      return;
    }

    // v has 2 children, swap values with successor and recurse
    swapValues(u, v);
    deleteRBNode(u);
  }

  void RBTree::fixDoubleBlack(RBNode *x) {
    if (x == root)
      // Reached root
      return;

    RBNode *sibling = x->sibling(), *parent = x->parent;
    if (sibling == NULL) {
      // No sibling, double black pushed up
      fixDoubleBlack(parent);
    } else {
      if (sibling->color == RED) {
        // Sibling red
        parent->color = RED;
        sibling->color = BLACK;
        if (sibling->isOnLeft()) {
          // left case
          rightRotate(parent);
        } else {
          // right case
          leftRotate(parent);
        }
        fixDoubleBlack(x);
      } else {
        // Sibling black
        if (sibling->hasRedChild()) {
          // at least 1 red children
          if (sibling->left != NULL && sibling->left->color == RED) {
            if (sibling->isOnLeft()) {
              // left left
              sibling->left->color = sibling->color;
              sibling->color = parent->color;
              rightRotate(parent);
            } else {
              // right left
              sibling->left->color = parent->color;
              rightRotate(sibling);
              leftRotate(parent);
            }
          } else {
            if (sibling->isOnLeft()) {
              // left right
              sibling->right->color = parent->color;
              leftRotate(sibling);
              rightRotate(parent);
            } else {
              // right right
              sibling->right->color = sibling->color;
              sibling->color = parent->color;
              leftRotate(parent);
            }
          }
          parent->color = BLACK;
        } else {
          // 2 black children
          sibling->color = RED;
          if (parent->color == BLACK)
            fixDoubleBlack(parent);
          else
            parent->color = BLACK;
        }
      }
    }
  }



  // constructor
  // initialize root
  RBTree::RBTree() { root = NULL; }

  RBNode *RBTree::getRoot() { return root; }

  // searches for given value
  // if found returns the node (used for delete)
  // else returns the last node while traversing (used in insert)
  RBNode *RBTree::search(int n) {
    RBNode *temp = root;
    while (temp != NULL) {
      if (n < temp->val) {
        if (temp->left == NULL)
          break;
        else
          temp = temp->left;
      } else if (n == temp->val) {
        break;
      } else {
        if (temp->right == NULL)
          break;
        else
          temp = temp->right;
      }
    }

    return temp;
  }

  // inserts the given value to tree
  void RBTree::insert(int n) {
    RBNode *newRBNode = new RBNode(n);
    if (root == NULL) {
      // when root is null
      // simply insert value at root
      newRBNode->color = BLACK;
      root = newRBNode;
    } else {
      RBNode *temp = search(n);

      if (temp->val == n) {
        // return if value already exists
        return;
      }

      // if value is not found, search returns the node
      // where the value is to be inserted

      // connect new node to correct node
      newRBNode->parent = temp;

      if (n < temp->val)
        temp->left = newRBNode;
      else
        temp->right = newRBNode;

      // fix red red violation if exists
      fixRedRed(newRBNode);
    }
  }

  // utility function that deletes the node with given value
  void RBTree::deleteByVal(int n) {
    if (root == NULL)
      // Tree is empty
      return;

    RBNode *v = search(n);

    if (v->val != n) {
      std::cout << "No node found to delete with value:" << n << std::endl;
      return;
    }

    deleteRBNode(v);
  }



  void RBTree::PrintNode(FILE* fp, RBNode* node,int tab) {
    int i;
    if (node == NULL) {
      return;
    }

    for(i=0;i<tab;i++) {
      fprintf(fp,"    ");
    }
    fprintf(fp,"%p value %d color %s\n",node,node->val, node->color == RED ? "RED" : "BLACK");

    this->PrintNode(fp,node->left,tab + 1);
    this->PrintNode(fp,node->right,tab + 1);

  }

  void RBTree::PrintTree(FILE* fp) {
    this->PrintNode(fp,this->root, 1);
    return;
  }

