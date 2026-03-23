#ifndef __RB_PRIV_H_333E36D88C2767273ED17FD6EB382A7F__
#define __RB_PRIV_H_333E36D88C2767273ED17FD6EB382A7F__

#include <rb_func.h>

#define RB_BLACK          1
#define RB_RED            2

struct rb_node_st {
	struct rb_node_st*    m_left;
	struct rb_node_st*    m_right;
	struct rb_node_st*    m_parent;
	void*    m_value;
	int      m_color;
	int      m_reserv1;
};


struct rb_tree_st {
	rb_malloc_func_t   m_mallocfunc;
	rb_free_func_t     m_freefunc;
	rb_destroy_func_t  m_destroyfunc;
	rb_compare_func_t  m_comparefunc;
	rb_print_func_t m_printfunc;
	struct rb_node_st* m_root;
};


#endif /* __RB_PRIV_H_333E36D88C2767273ED17FD6EB382A7F__ */
