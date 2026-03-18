#ifndef __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__
#define __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__


typedef struct rb_tree_st   RB_TREE;
typedef struct rb_node_st   RB_NODE;

/*for malloc functions*/
typedef void* (rb_malloc_func_t)(size_t size);
/*for free functions*/
typedef void (rb_free_func_t)(void* ptr);
/*to destroy the function*/
typedef void (rb_destroy_func_t)(void* arg);
/*function return 0 for equal < 0 for less > 0 for greater*/
typedef int (rb_compare_func_t)(void* arg1,void arg2);


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API RB_TREE* init_rb_tree(rb_malloc_func_t mallocfunc, rb_free_func_t freefunc,rb_compare_func_t comparefunc,rb_destroy_func_t destroyfunc);
WINLIB_API void destroy_rb_tree(RB_TREE* ptree);
WINLIB_API RB_NODE* rb_insert(RB_TREE* ptree,void* arg);
WINLIB_API void* rb_delete(RB_TREE* ptree,RB_NODE* pnode,int keep);
WINLIB_API RB_NODE* rb_find(RB_TREE* ptree,void* arg);
WINLIB_API void* rb_node_get(RB_NODE* pnode);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __RB_TREE_H_966B4A48DBA392C406A62C7843443B06__ */
