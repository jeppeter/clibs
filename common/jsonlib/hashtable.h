#ifndef UT_HASHTABLE_H
#define UT_HASHTABLE_H

#include "jvalue.h"

extern jhashtable *jhashtable_create(void);

extern void jhashtable_destroy(jhashtable* table);

extern jvalue *jhashtable_put(jhashtable* table, const char* key, jvalue* value, int *error);

extern jvalue *jhashtable_get(jhashtable* table, const char* key);

extern int jhashtable_remove(jhashtable* table, const char* key);

extern unsigned int jhashtable_size(jhashtable* table);

extern int jhashtable_isempty(jhashtable* table);

extern jentry **jhashtable_entries(jhashtable* table, unsigned int *size);

#endif
