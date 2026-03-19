#ifndef __RB_FUNC_H_23C3F3A1A84E44B7E15C3043C1CDD6BC__
#define __RB_FUNC_H_23C3F3A1A84E44B7E15C3043C1CDD6BC__

/*for malloc functions*/
typedef void* (*rb_malloc_func_t)(size_t size);
/*for free functions*/
typedef void (*rb_free_func_t)(void* ptr);
/*to destroy the function*/
typedef void (*rb_destroy_func_t)(void* arg);
/*function return 0 for equal < 0 for less > 0 for greater*/
typedef int (*rb_compare_func_t)(void* arg1,void* arg2);


#endif /* __RB_FUNC_H_23C3F3A1A84E44B7E15C3043C1CDD6BC__ */
