#ifndef __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__
#define __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__

#include <cmn_err.h>

#include <rb_func.h>

typedef struct rb_tree_st   RB_TREE;
typedef struct rb_node_st   RB_NODE;



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API RB_TREE* init_rb_tree(rb_malloc_func_t mallocfunc, rb_free_func_t freefunc,rb_compare_func_t comparefunc,rb_destroy_func_t destroyfunc);
WINLIB_API void destroy_rb_tree(RB_TREE** pptree,int keep);
WINLIB_API RB_NODE* rb_insert(RB_TREE* ptree,void* arg);
WINLIB_API RB_NODE* rb_first(RB_TREE* ptree);
WINLIB_API void rb_delete(RB_TREE* ptree,RB_NODE* pnode,int keep);
WINLIB_API RB_NODE* rb_find(RB_TREE* ptree,void* arg);
WINLIB_API void* rb_node_get(RB_NODE* pnode);
WINLIB_API RB_NODE* rb_node_next(RB_NODE* pnode);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__ */
