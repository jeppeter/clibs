#define _HAS_EXCEPTIONS 0
#include "rbtree.h"
#include <stdarg.h>

#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1910
#pragma warning(disable:5045)
#endif
#endif


  void __debug_node(RBNode* node,const char* file,int lineno,const char* fmt, ...)
  {
    va_list ap;
    va_start(ap,fmt);

    if (node == NULL) {
      fprintf(stderr,"[%s:%d] NULL DEBUG_NODE ",file,lineno);
      vfprintf(stderr,fmt,ap);
      fprintf(stderr,"\n");
      return;
    }

    fprintf(stderr,"[%s:%d] %p DEBUG_NODE ",file,lineno,node);
    vfprintf(stderr,fmt,ap);
    fprintf(stderr," color %s m_value %d\n",node->color == RED ? "RED" : "BLACK", node->val);
    return;

  }

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

    __debug_node(x,__FILE__,__LINE__,"before leftRotate");
    if (x->parent != NULL) {
      __debug_node(x->parent,__FILE__,__LINE__,"parent value");
    }
    if (x->left != NULL) {
      __debug_node(x->left,__FILE__,__LINE__,"left value");
    }

    if (x->right != NULL) {
      __debug_node(x->right,__FILE__,__LINE__,"right value");
    }
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

    __debug_node(x,__FILE__,__LINE__,"after leftRotate");
    if (x->parent != NULL) {
      __debug_node(x->parent,__FILE__,__LINE__,"parent value");
    }
    if (x->left != NULL) {
      __debug_node(x->left,__FILE__,__LINE__,"left value");
    }

    if (x->right != NULL) {
      __debug_node(x->right,__FILE__,__LINE__,"right value");
    }

  }

  void RBTree::rightRotate(RBNode *x) {
    // new parent will be node's left child
    RBNode *nParent = x->left;

    __debug_node(x,__FILE__,__LINE__,"before rightRotate");
    if (x->parent != NULL) {
      __debug_node(x->parent,__FILE__,__LINE__,"parent value");
    }
    if (x->left != NULL) {
      __debug_node(x->left,__FILE__,__LINE__,"left value");
    }

    if (x->right != NULL) {
      __debug_node(x->right,__FILE__,__LINE__,"right value");
    }


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

    __debug_node(x,__FILE__,__LINE__,"after rightRotate");
    if (x->parent != NULL) {
      __debug_node(x->parent,__FILE__,__LINE__,"parent value");
    }
    if (x->left != NULL) {
      __debug_node(x->left,__FILE__,__LINE__,"left value");
    }

    if (x->right != NULL) {
      __debug_node(x->right,__FILE__,__LINE__,"right value");
    }

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
      __debug_node(parent,__FILE__,__LINE__," parent color != BLACK");
      __debug_node(uncle,__FILE__,__LINE__,"uncle check");
      if (uncle != NULL && uncle->color == RED) {
        // uncle red, perform recoloring and recurse
        parent->color = BLACK;
        uncle->color = BLACK;
        grandparent->color = RED;
        __debug_node(grandparent,__FILE__,__LINE__,"grandparent = RED");
        fixRedRed(grandparent);
      } else {
        // Else perform LR, LL, RL, RR
        if (parent->isOnLeft()) {
          __debug_node(parent,__FILE__,__LINE__," parent is on left");
          if (x->isOnLeft()) {
            // for left right
            __debug_node(x,__FILE__,__LINE__," x is on left");
            swapColors(parent, grandparent);
            __debug_node(parent,__FILE__,__LINE__," parent new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");
          } else {
            __debug_node(parent,__FILE__,__LINE__," x is on right");
            leftRotate(parent);
            swapColors(x, grandparent);
            __debug_node(x,__FILE__,__LINE__," x new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");            
          }
          // for left left and left right
          rightRotate(grandparent);
        } else {
          if (x->isOnLeft()) {
            // for right left
            __debug_node(x,__FILE__,__LINE__," x is on left");
            rightRotate(parent);
            swapColors(x, grandparent);
            __debug_node(x,__FILE__,__LINE__," x new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");            
          } else {
            swapColors(parent, grandparent);
            __debug_node(parent,__FILE__,__LINE__," parent new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");            
          }

          // for right right and right left
          leftRotate(grandparent);
          __debug_node(grandparent,__FILE__,__LINE__," grandparent after rotate left");
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

    __debug_node(v,__FILE__,__LINE__,"v node");
    __debug_node(u,__FILE__,__LINE__,"u node");

    // True when u and v are both black
    bool uvBlack = ((u == NULL || u->color == BLACK) && (v->color == BLACK));
    RBNode *parent = v->parent;
    __debug_node(parent,__FILE__,__LINE__,"parent node");

    if (u == NULL) {
      // u is NULL therefore v is leaf
      if (v == root) {
        // v is root, making root null
        __debug_node(v,__FILE__,__LINE__,"root clear");
        root = NULL;
      } else {
        if (uvBlack) {
          // u and v both black
          // v is leaf, fix double black at v
          __debug_node(v,__FILE__,__LINE__,"fixDoubleBlack");
          fixDoubleBlack(v);
        } else {
          // u or v is red
          if (v->sibling() != NULL)
            // sibling is not null, make it red"
            __debug_node(v->sibling(),__FILE__,__LINE__,"sibling color set");
            v->sibling()->color = RED;
        }

        // delete v from the tree
        if (v->isOnLeft()) {
          __debug_node(v,__FILE__,__LINE__,"leftset");
          parent->left = NULL;
        } else {
          __debug_node(v,__FILE__,__LINE__,"rightset");
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
        __debug_node(v,__FILE__,__LINE__,"v set right left clear");
        v->val = u->val;
        v->left = v->right = NULL;
        delete u;
      } else {
        // Detach v from tree and move u up
        if (v->isOnLeft()) {
          __debug_node(u,__FILE__,__LINE__,"parent left = u");
          parent->left = u;
        } else {
          __debug_node(u,__FILE__,__LINE__,"parent right = u");
          parent->right = u;
        }
        delete v;
        __debug_node(u,__FILE__,__LINE__,"u set parent");
        u->parent = parent;
        if (uvBlack) {
          // u and v both black, fix double black at u
          __debug_node(u,__FILE__,__LINE__,"fixDoubleBlack");
          fixDoubleBlack(u);
        } else {
          // u or v red, color u black
          __debug_node(u,__FILE__,__LINE__,"u set black");
          u->color = BLACK;
        }
      }
      return;
    }

    // v has 2 children, swap values with successor and recurse
    __debug_node(u,__FILE__,__LINE__,"swapValues");
    swapValues(u, v);
    __debug_node(u,__FILE__,__LINE__,"recursive");
    deleteRBNode(u);
  }

  void RBTree::fixDoubleBlack(RBNode *x) {
    if (x == root){
      // Reached root
      __debug_node(x,__FILE__,__LINE__,"x == root");
      return;
    }

    RBNode *sibling = x->sibling(), *parent = x->parent;
    if (sibling == NULL) {
      // No sibling, double black pushed up
      __debug_node(parent,__FILE__,__LINE__,"fixDoubleBlack parent");
      fixDoubleBlack(parent);
    } else {
      if (sibling->color == RED) {
        // Sibling red
        __debug_node(parent,__FILE__,__LINE__,"parent set color RED");
        parent->color = RED;
        __debug_node(sibling,__FILE__,__LINE__,"sibling set color BLACK");
        sibling->color = BLACK;
        if (sibling->isOnLeft()) {
          // left case
          __debug_node(parent,__FILE__,__LINE__,"parent rightRotate");
          rightRotate(parent);
        } else {
          // right case
          __debug_node(parent,__FILE__,__LINE__,"parent leftRotate");
          leftRotate(parent);
        }
        __debug_node(x,__FILE__,__LINE__,"fixDoubleBlack x");
        fixDoubleBlack(x);
      } else {
        // Sibling black
        if (sibling->hasRedChild()) {
          // at least 1 red children
          __debug_node(sibling,__FILE__,__LINE__,"hasRedChild");
          if (sibling->left != NULL && sibling->left->color == RED) {
            if (sibling->isOnLeft()) {
              // left left
              __debug_node(sibling,__FILE__,__LINE__,"sibling color fixup");
              sibling->left->color = sibling->color;
              __debug_node(sibling,__FILE__,__LINE__,"sibling parent color set");
              sibling->color = parent->color;
              __debug_node(parent,__FILE__,__LINE__,"rightRotate parent");
              rightRotate(parent);
            } else {
              // right left
              __debug_node(sibling,__FILE__,__LINE__,"sibling color fixup");
              sibling->left->color = parent->color;
              __debug_node(sibling,__FILE__,__LINE__,"rightRotate sibling");
              rightRotate(sibling);
              __debug_node(parent,__FILE__,__LINE__,"leftRotate parent");
              leftRotate(parent);
            }
          } else {
            __debug_node(sibling,__FILE__,__LINE__,"check sibling isOnLeft");
            if (sibling->isOnLeft()) {
              // left right
              __debug_node(sibling,__FILE__,__LINE__,"sibling right color set");
              sibling->right->color = parent->color;
              __debug_node(sibling,__FILE__,__LINE__,"leftRotate sibling");
              leftRotate(sibling);
              __debug_node(parent,__FILE__,__LINE__,"rightRotate parent");
              rightRotate(parent);
            } else {
              // right right
              __debug_node(sibling,__FILE__,__LINE__,"sibling right color set");
              sibling->right->color = sibling->color;
              __debug_node(sibling,__FILE__,__LINE__,"sibling color parent set");
              sibling->color = parent->color;
              __debug_node(parent,__FILE__,__LINE__,"leftRotate parent");
              leftRotate(parent);
            }
          }
          __debug_node(parent,__FILE__,__LINE__,"parent color BLACK");
          parent->color = BLACK;
        } else {
          // 2 black children
          __debug_node(sibling,__FILE__,__LINE__,"sibling color RED");
          sibling->color = RED;
          if (parent->color == BLACK){
            __debug_node(parent,__FILE__,__LINE__,"fixDoubleBlack parent");
            fixDoubleBlack(parent);
          }
          else{
            __debug_node(parent,__FILE__,__LINE__,"parent color BLACK");
            parent->color = BLACK;
          }
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
      __debug_node(root,__FILE__,__LINE__,"new root");
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
      __debug_node(newRBNode,__FILE__,__LINE__,"set parent");

      if (n < temp->val){
        temp->left = newRBNode;
        __debug_node(temp,__FILE__,__LINE__,"set left");
      }
      else {
        temp->right = newRBNode;
        __debug_node(temp,__FILE__,__LINE__,"set right");
      }

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
    fprintf(fp,"node %p .m_parent %p .m_left %p .m_right %p DISPLAY_NODE .m_color %s  .m_val %d\n",node,node->parent,node->left,node->right, node->color == RED ? "RED" : "BLACK",node->val);

    this->PrintNode(fp,node->left,tab + 1);
    this->PrintNode(fp,node->right,tab + 1);

  }

  void RBTree::PrintTree(FILE* fp) {
    this->PrintNode(fp,this->root, 1);
    return;
  }

#pragma warning(pop)