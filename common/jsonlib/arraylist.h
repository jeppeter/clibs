#ifndef UT_JARRAYLIST_H
#define UT_JARRAYLIST_H

#include "jvalue.h"

extern jarraylist *jarraylist_create(void);

extern void jarraylist_destroy(jarraylist *list);

extern void jarraylist_clear(jarraylist *list);

extern unsigned int jarraylist_size(jarraylist *list);

extern jvalue *jarraylist_set(jarraylist *list, unsigned int index, jvalue *value);

extern jvalue *jarraylist_get(jarraylist *list, unsigned int index);

extern int jarraylist_add(jarraylist *list, jvalue *value);

extern int jarraylist_insert(jarraylist *list, unsigned int index, jvalue *value);

extern jvalue *jarraylist_remove(jarraylist *list, unsigned int index);

#endif
