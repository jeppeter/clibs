/*
 * This is free and unencumbered software released into the public domain.
 */

#include <stdlib.h>
#include <jvalue.h>
#include "jstring.h"
#include "util.h"
#include "hashtable.h"
#include "arraylist.h"

#if defined(_MSC_VER)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif
#endif


jvalue *jobject_create(void)
{
  jobject *object = (jobject *) util_malloc(sizeof(jobject));
  if (object == 0) return 0;
  object->type = JOBJECT;
  object->table = jhashtable_create();
  if (object->table == 0) {
    util_free(object);
    return 0;
  }
  return (jvalue *) object;
}

static int jobject_destroy(jvalue *value)
{
  jobject *object;
  if (value == 0) return JERROR_NULL_PARAM;
  object = (jobject *) value;
  jhashtable_destroy(object->table);
  util_free(object);
  return 0;
}

int jobject_remove(jvalue *value, const char* key)
{
  jobject *object;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  object = (jobject *) value;
  return jhashtable_remove(object->table, key);
}

int jobject_isempty(const jvalue *value)
{
  const jobject *object;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  object = (const jobject *) value;
  return jhashtable_isempty(object->table);
}

/* returns the number of the entry objects in the hashtable */
int jobject_size(const jvalue *value)
{
  const jobject *object;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  object = (const jobject *) value;
  return (int) jhashtable_size(object->table);
}

/* returns an array of the entry objects in the hashtable */
jentry **jobject_entries(const jvalue *value, unsigned int *size)
{
  const jobject *object;
  if (value == 0 || value->type != JOBJECT) {
    if (size) *size = 0;
    return 0;
  }
  object = (const jobject *) value;
  return jhashtable_entries(object->table, size);
}

void jentries_destroy(jentry*** pppentries)
{
  if (pppentries && *pppentries) {
    util_free(*pppentries);
    *pppentries = (jentry**)0;
  }
  return;
}

static jobject *jobject_clone(const jobject *table);
static jarray *jarray_clone(const jarray *array);

static void jobject_clone_object(jobject *table, jentry *entry)
{
  char *key;
  jvalue *value;
  if (table == 0 || entry == 0) return;
  key = entry->key;
  value = entry->value;
  if (value->type == JNULL) {
    jobject_put_null((jvalue *) table, key);
  } if (value->type == JSTORE) {
    jobject_put_store((jvalue*) table,key);
  } if (value->type == JBOOL) {
    jbool *v = (jbool *) value;
    jobject_put_bool((jvalue *) table, key, v->value);
  } if (value->type == JINT) {
    jint *v = (jint *) value;
    jobject_put_int((jvalue *) table, key, v->value);    
  } if (value->type == JINT64) {
    jint64 *v = (jint64 *) value;
    jobject_put_int64((jvalue *) table, key, v->value);
  } if (value->type == JREAL) {
    jreal *v = (jreal *) value;
    jobject_put_real((jvalue *) table, key, v->value);
  } if (value->type == JSTRING) {
    jstring *v = (jstring *) value;
    jobject_put_string((jvalue *) table, key, v->value);
  } if (value->type == JOBJECT) {
    jobject *v = (jobject *) value;
    jobject *t = jobject_clone(v);
    if (t) {
      jobject_put_object((jvalue *) table, key, (jvalue *) t);
    }
  } if (value->type == JARRAY) {
    jarray *p = jarray_clone((const jarray *) value);
    if (p) {
      jobject_put_array((jvalue *) table, key, (jvalue *) p);
    }
  }
}

/* creates a clone of the hashtable */
static jobject *jobject_clone(const jobject *object)
{
  unsigned int i, size;
  jobject *dup;
  jentry ** entries;
  if (object == 0) return 0;
  dup = (jobject *) jobject_create();
  if (dup == 0) return 0;
  entries = jhashtable_entries(object->table, &size);
  for (i = 0; i < size; i++) {
    jentry *entry = entries[i];
    jobject_clone_object(dup, entry);
  }
  util_free(entries);
  return dup;
}

jvalue *jobject_put(jvalue *value, const char* key, jvalue *key_value, int *error)
{
  jobject *object;
  if (value == 0 || key == 0 || *key == 0 || key_value == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  object = (jobject *) value;
  if (error) *error = 0;
  return jhashtable_put(object->table, key, key_value, error);
}

jvalue *jobject_get(const jvalue *value, const char* key)
{
  const jobject *object;
  if (value == 0 || value->type != JOBJECT || key == 0 || *key == 0) return 0;
  object = (const jobject *) value;
  return jhashtable_get(object->table, key);
}

int jobject_put_int(jvalue *value, const char* key, int number)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jint_create(number);
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_int64(jvalue *value, const char* key, long long int number)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jint64_create(number);
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_real(jvalue *value, const char* key, double number)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jreal_create(number);
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_string(jvalue *value, const char* key, const char *str)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jstring_create(str, &status);
  if (key_value == 0) return status;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_bool(jvalue *value, const char* key, int bvalue)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jbool_create(bvalue);
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_null(jvalue *value, const char* key)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jnull_create();
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_store(jvalue* value, const char* key)
{
  jvalue *key_value;
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = jstore_create();
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;

}

int jobject_put_object(jvalue *value, const char* key, jvalue *key_value)
{
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  if (!(key_value && key_value->type == JOBJECT)) return JERROR_WRONG_PARAM_TYPE;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_array(jvalue *value, const char* key, jvalue *key_value)
{
  jvalue *old;
  int status;
  if (value == 0 || key == 0 || *key == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  if (!(key_value && key_value->type == JARRAY)) return JERROR_WRONG_PARAM_TYPE;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_put_user(jvalue *value, const char* key, void *data,
                     juser_write write, juser_destroy destroy)
{
  jvalue *old;
  jvalue *key_value;
  int status;
  if (value == 0 || key == 0 || *key == 0 || data == 0) return JERROR_NULL_PARAM;
  if (value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  key_value = juser_create(data, write, destroy);
  if (key_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  old = jobject_put(value, key, key_value, &status);
  if (status) jvalue_destroy(key_value);
  if (old) jvalue_destroy(old);
  return status;
}

int jobject_get_int(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JINT) {
      jint *v = (jint *) data;
      if (error) *error = 0;
      return v->value;
    } else {
      UTIL_DEBUG("type [%d]", data->type);
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

long long int jobject_get_int64(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {    
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JINT64) {
      jint64 *v = (jint64 *) data;
      if (error) *error = 0;
      return v->value;
    } else {
      UTIL_DEBUG("type [%d]", data->type);
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

double jobject_get_real(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JREAL) {
      jreal *v = (jreal *) data;
      if (error) *error = 0;
      return v->value;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

const char *jobject_get_string(const  jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JSTRING) {
      jstring *v = (jstring *) data;
      if (error) *error = 0;
      return v->value;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

int jobject_get_bool(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JBOOL) {
      jbool *v = (jbool *) data;
      if (error) *error = 0;
      return v->value;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

int jobject_get_null(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return JERROR_NULL_PARAM;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return JERROR_WRONG_PARAM_TYPE;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JNULL) {
      if (error) *error = 0;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return JERROR_WRONG_VALUE_TYPE;
    }
  } else {
    if (error) *error = JERROR_VALUE_NOT_FOUND;
    return JERROR_VALUE_NOT_FOUND;
  }
  return 0;
}

int jobject_get_store(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return JERROR_NULL_PARAM;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return JERROR_WRONG_PARAM_TYPE;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JSTORE) {
      if (error) *error = 0;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return JERROR_WRONG_VALUE_TYPE;
    }
  } else {
    if (error) *error = JERROR_VALUE_NOT_FOUND;
    return JERROR_VALUE_NOT_FOUND;
  }
  return 0;
}


jarray *jobject_get_array(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JARRAY) {
      if (error) *error = 0;
      return (jarray *) data;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

jobject *jobject_get_object(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JOBJECT) {
      if (error) *error = 0;
      return (jobject *) data;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

void *jobject_get_user(const jvalue *value, const char* key, int *error)
{
  jvalue *data;
  if (value == 0 || key == 0 || *key == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JOBJECT) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  data = jobject_get(value, key);
  if (data) {
    if (data->type == JUSER) {
      juser *user = (juser *) data;
      if (error) *error = 0;
      return user->value;
    } else {
      if (error) *error = JERROR_WRONG_VALUE_TYPE;
      return 0;
    }
  }
  if (error) *error = JERROR_VALUE_NOT_FOUND;
  return 0;
}

/******************************************************************************/
/* array */
/******************************************************************************/

jvalue *jarray_create(void)
{
  jarray *array = (jarray *) util_malloc(sizeof(jarray));
  if (array == 0) return 0;
  array->type = JARRAY;
  array->list = jarraylist_create();
  return (jvalue *) array;
}

unsigned int jarray_size(const jvalue *value)
{
  const jarray *array;
  if (value == 0 || value->type != JARRAY) return 0;
  array = (const jarray *) value;
  return jarraylist_size(array->list);
}

void jarray_destroy(jarray *array)
{
  if (array == 0) return;
  jarraylist_destroy(array->list);
  util_free(array);
}

static void jarray_clone_value(jvalue *array, jvalue *value)
{
  if (array == 0 || value == 0) return;
  if (value->type == JNULL) {
    jarray_put_null(array);
  } if (value->type == JSTORE) {
    jarray_put_store(array);
  } if (value->type == JBOOL) {
    jbool *v = (jbool *) value;
    jarray_put_bool(array, v->value);
  } if (value->type == JINT) {
    jint *v = (jint *) value;
    jarray_put_int(array, v->value);
  } if (value->type == JINT64) {
    jint64 *v = (jint64 *) value;
    jarray_put_int64(array, v->value);
  } if (value->type == JREAL) {
    jreal *v = (jreal *) value;
    jarray_put_real(array, v->value);
  } if (value->type == JSTRING) {
    jstring *v = (jstring *) value;
    jarray_put_string(array, v->value);
  } if (value->type == JOBJECT) {
    jobject *v = (jobject *) value;
    jobject *t = jobject_clone(v);
    if (t) {
      jarray_put_object(array, (jvalue *) t);
    }
  } if (value->type == JARRAY) {
    jarray *p = jarray_clone((jarray *) value);
    if (p) {
      jarray_put_array(array, (jvalue *) p);
    }
  }
}

jarray *jarray_clone(const jarray *array)
{
  jarray *p;
  if (array == 0) return 0;
  p = (jarray *) jarray_create();
  if (p) {
    unsigned int i = 0;
    for (i = 0; i < jarray_size((const jvalue *) array); i++) {
      jvalue *v = jarray_get((const jvalue *) array, i, 0);
      jarray_clone_value((jvalue *) p, v);
    }
  }
  return p;
}

jarray* jarray_filter_clone(const jarray* array)
{
  jarray *p;
  if (array == 0) return 0;
  p = (jarray*) jarray_create();
  if (p) {
    unsigned int i = 0;
    for(i=0; i < jarray_size((const jvalue*) array);i++) {
      jvalue* v = jarray_get((const jvalue*)array,i,0);
      if (v->type != JSTORE) {
        jarray_clone_value((jvalue*)p ,v);
      }
    }
  }
  return p;
}

int jarray_insert(const jvalue *value, unsigned int index, jvalue *array_value)
{
  const jarray *array;
  if (value == 0 || array_value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array = (const jarray *) value;
  return jarraylist_insert(array->list, index, array_value);
}

jvalue *jarray_remove(const jvalue *value, unsigned int index, int *error)
{
  const jarray *array;
  if (value == 0) {
    if (error) {
      *error = JERROR_NULL_PARAM;
    }
    return NULL;
  }
  if (value->type != JARRAY) {
    if (error) {
      *error = JERROR_WRONG_PARAM_TYPE;
    }
    return NULL;
  }
  if (index >= jarray_size(value)) {
    if (error) {
      *error = JERROR_OUT_OF_INDEX;
    }
    return NULL;
  }
  array = (const jarray *) value;
  return jarraylist_remove(array->list, index);
}

int jarray_put(jvalue *value, jvalue *array_value)
{
  jarray *array;
  if (value == 0 || array_value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array = (jarray *) value;
  return jarraylist_add(array->list, array_value);
}

jvalue *jarray_get(const jvalue *value, unsigned int index, int *error)
{
  const jarray *array;
  if (value == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  if (value->type != JARRAY) {
    if (error) *error = JERROR_WRONG_PARAM_TYPE;
    return 0;
  }
  array = (const jarray *) value;
  return jarraylist_get(array->list, index);
}

int jarray_put_int(jvalue *value, int number)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jint_create(number);
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_int64(jvalue *value, long long int number)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jint64_create(number);
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_string(jvalue *value, const char *str)
{
  jvalue *array_value;
  int error;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jstring_create(str, &error);
  if (array_value == 0) return error;
  return jarray_put(value, array_value);
}

int jarray_put_bool(jvalue *value, int bvalue)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jbool_create(bvalue);
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_real(jvalue *value, double number)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jreal_create(number);
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_null(jvalue *value)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jnull_create();
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_store(jvalue *value)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = jstore_create();
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}


int jarray_put_array(jvalue *value, jvalue *array_value)
{
  if (value == 0 || array_value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  if (array_value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  return jarray_put(value, array_value);
}

int jarray_put_object(jvalue *value, jvalue *array_value)
{
  if (value == 0 || array_value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  if (array_value->type != JOBJECT) return JERROR_WRONG_PARAM_TYPE;
  return jarray_put(value, array_value);
}

int jarray_put_user(jvalue *value, void *data, juser_write write, juser_destroy destroy)
{
  jvalue *array_value;
  if (value == 0) return JERROR_NULL_PARAM;
  if (value->type != JARRAY) return JERROR_WRONG_PARAM_TYPE;
  array_value = juser_create(data, write, destroy);
  if (array_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  return jarray_put(value, array_value);
}

int jarray_put_int_list(jvalue *array, int numbers[], unsigned int size)
{
  unsigned int i;
  int error = 0;;
  if (array == 0) return JERROR_NULL_PARAM;
  for (i = 0; i < size; i++) {
    jvalue *v = jint_create(numbers[i]);
    if (v == 0) return JERROR_NOT_ENOUGH_MEMORY;
    error = jarray_put(array, v);
    if (error != 0) break;
  }
  /* TODO: need to free the memories if the error happens in the middle */
  return error;
}

int jarray_put_bool_list(jvalue *array, int values[], unsigned int size)
{
  unsigned int i;
  int error = 0;;
  if (array == 0) return JERROR_NULL_PARAM;
  for (i = 0; i < size; i++) {
    jvalue *v = jbool_create(values[i]);
    if (v == 0) return JERROR_NOT_ENOUGH_MEMORY;
    error = jarray_put(array, v);
    if (error != 0) break;
  }
  /* TODO: need to free the memories if the error happens in the middle */
  return error;
}

int jarray_put_string_list(jvalue *array, const char *strs[], unsigned int size)
{
  unsigned int i;
  int error = 0;;
  if (array == 0) return JERROR_NULL_PARAM;
  for (i = 0; i < size; i++) {
    jvalue *v = jstring_create(strs[i], &error);
    if (v == 0) return error;
    error = jarray_put(array, v);
    if (error != 0) break;
  }
  /* TODO: need to free the memories if the error happens in the middle */
  return error;
}

int jarray_put_jvalue_list(jvalue *array, jvalue *values[], unsigned int size)
{
  unsigned int i;
  int error = 0;;
  if (array == 0 || values == 0) return JERROR_NULL_PARAM;
  for (i = 0; i < size; i++) {
    if (values[i] == 0)  return JERROR_NULL_PARAM;
    error = jarray_put(array, values[i]);
    if (error != 0) break;
  }
  /* TODO: need to free the memories if the error happens in the middle */
  return error;
}

/******************************************************************************/
/* jvalue functions */
/******************************************************************************/

void jvalue_destroy(jvalue *value)
{
  if (value == 0) return;
  switch(value->type) {
    case JNONE:
      break;
    case JNULL:
    case JREAL:
    case JINT:
    case JINT64:
    case JBOOL:
    case JSTORE:
      util_free(value);
      break;
    case JUSER: {
      juser *v = (juser *) value;
      if (v->destroy) {
        v->destroy(v->value);
      }
      util_free(value);
      break;
    }
    case JSTRING: {
      jstring *v = (jstring *) value;
      util_free(v->value);
      util_free(value);
      break;
    }
    case JOBJECT:
      jobject_destroy(value);
      break;
    case JARRAY: {
      jarray_destroy((jarray *) value);
      break;
    }
  }
}

jvalue *jvalue_clone(const jvalue *value)
{
  if (value == 0) return 0;
  if (value->type == JOBJECT) {
    return (jvalue *) jobject_clone((const jobject *) value);
  } else if (value->type == JARRAY) {
    return (jvalue *) jarray_clone((const jarray *) value);
  } else if (value->type == JNULL) {
    return jnull_create();
  } else if (value->type == JSTORE) {
    return jstore_create();
  } else if (value->type == JBOOL) {
    const jbool *b = (const jbool *) value;
    return jbool_create(b->value);
  } else if (value->type == JINT) {
    const jint *i = (const jint *) value;
    return jint_create(i->value);
  } else if (value->type == JINT64) {
    const jint64 *i = (const jint64 *) value;
    return jint64_create(i->value);
  } else if (value->type == JREAL) {
    const jreal *r = (const jreal *) value;
    return jreal_create(r->value);
  } else if (value->type == JSTRING) {
    const jstring *s = (const jstring *) value;
    return jstring_create(s->value, 0);
  } else if (value->type == JUSER) {
    const juser *u = (const juser *) value;
    return juser_create(u->value, u->write, u->destroy);
  } else if (value->type == JSTORE) {
    return jstore_create();
  }
  return 0;
}

static int jvalue_compar(const void *v1, const void *v2)
{
  /* fixed the compiler warning by kiyo-chan */
  jentry* const *e1 = (jentry* const *) v1;
  jentry* const *e2 = (jentry* const *) v2;
  return util_strcmp((*e1)->key, (*e2)->key);
}

int jvalue_compare(const jvalue *value1, const jvalue *value2)
{
  if (value1 == 0 && value2 == 0) return 0;
  if (value1 == 0 || value2 == 0) return -1;
  if (value1->type == JOBJECT && value2->type == JOBJECT) {
    unsigned int size1;
    jentry **entries1 = jobject_entries(value1, &size1);
    unsigned int size2;
    jentry **entries2 = jobject_entries(value2, &size2);
    if ( size1 != 0 && size1 == size2) {
      unsigned int i;
      util_qsort(entries1, size1, sizeof(jentry *), jvalue_compar);
      util_qsort(entries2, size2, sizeof(jentry *), jvalue_compar);
      for (i = 0; i < size1; i++) {
        if (jvalue_compare(entries1[i]->value, entries2[i]->value) != 0) {
          break;
        }
      }
      /*entries1!=NULL because size1 != 0*/
      util_free(entries1);  
      entries1 = NULL;
      /*entries2!=NULL because size2 != 0*/
      util_free(entries2);  
      entries2 = NULL;
      if (i == size1) return 0;
    }
    if (entries1 != NULL) {
      util_free(entries1);  
    }
    entries1 = NULL;
    if (entries2 != NULL) {
      util_free(entries2);  
    }
    entries2 = NULL;
  } else if (value1->type == JARRAY && value2->type == JARRAY) {
    if (jarray_size(value1) == jarray_size(value2)) {
      unsigned int i = 0;
      while (1) {
        jvalue *av1 = jarray_get(value1, i, 0);
        jvalue *av2 = jarray_get(value2, i, 0);
        if (av1 == 0 || av2 == 0) break;
        if (jvalue_compare(av1, av2) != 0) {
          break;
        }
        i++;
      }
      if (i == jarray_size(value1)) return 0;
    }
  } else if (value1->type == JNULL && value2->type == JNULL) {
    return 0;
  } else if (value1->type == JSTORE && value2->type == JSTORE) {
    return 0;
  } else if (value1->type == JBOOL && value2->type == JBOOL) {
    const jbool *bv1 = (const jbool *) value1;
    const jbool *bv2 = (const jbool *) value2;
    if (bv1->value == bv2->value) return 0;
  } else if (value1->type == JINT && value2->type == JINT) {
    const jint *iv1 = (const jint *) value1;
    const jint *iv2 = (const jint *) value2;
    if (iv1->value == iv2->value) return 0;
  } else if (value1->type == JINT64 && value2->type == JINT64) {
    const jint64 *iv1 = (const jint64 *) value1;
    const jint64 *iv2 = (const jint64 *) value2;
    if (iv1->value == iv2->value) return 0;
  } else if (value1->type == JREAL && value2->type == JREAL) {
    const jreal *lv1 = (const jreal *) value1;
    const jreal *lv2 = (const jreal *) value2;
    if (util_realcompare(lv1->value, lv2->value) == 0) return 0;
  } else if (value1->type == JSTRING && value2->type == JSTRING) {
    const jstring *sv1 = (const jstring *) value1;
    const jstring *sv2 = (const jstring *) value2;
    if (util_strcmp(sv1->value, sv2->value) == 0) return 0;
  } else if (value1->type == JUSER && value2->type == JUSER) {
    return 0;
  }
  return -1;
}


/******************************************************************************/
/* jvalue functions */
/******************************************************************************/

jvalue *jint_create(int number)
{
  jint *value = (jint *) util_malloc(sizeof(jint));
  if (value) {
    value->type = JINT;
    value->value = number;
  }
  return (jvalue *) ((void *) value);
}

jvalue *jint64_create(long long int number)
{
  jint64 *value = (jint64 *) util_malloc(sizeof(jint64));
  if (value) {
    value->type = JINT64;
    value->value = number;
  }
  return (jvalue *) value;
}

jvalue *jreal_create(double number)
{
  jreal *value = (jreal *) util_malloc(sizeof(jreal));
  if (value) {
    value->type = JREAL;
    value->value = number;
  }
  return (jvalue *) value;
}

jvalue *jstring_create(const char* str, int *error)
{
  jstring *value = NULL;
  char *str_copy = util_strdup(str, MAX_VALUE_STRING_SIZE, error);
  if (str_copy == 0) return 0;
  value = (jstring *) util_malloc(sizeof(jstring));
  if (value) {
    value->type = JSTRING;
    if (str == 0) value->value = 0;
    else {
      value->value = str_copy;
      str_copy = NULL;
    }
  } 
  if (str_copy) {
    util_free(str_copy);
  }
  str_copy = NULL;
  return (jvalue *) value;
}

jvalue *jbool_create(int b)
{
  jbool *value = (jbool *) util_malloc(sizeof(jbool));
  if (value) {
    value->type = JBOOL;
    value->value = b;
  }
  return (jvalue *) ((void *) value);
}

jvalue *jnull_create(void)
{
  jnull *value = (jnull *) util_malloc(sizeof(jnull));
  if (value) {
    value->type = JNULL;
  }
  return (jvalue *) ((void *) value);
}

jvalue *jstore_create(void)
{
  jstore* value = (jstore*) util_malloc(sizeof(jstore));
  if (value) {
    value->type = JSTORE;
  }
  return (jvalue*)((void*) value);
}

jvalue *juser_create(void *data, juser_write write, juser_destroy destroy)
{
  juser *value = (juser *) util_malloc(sizeof(juser));
  if (value) {
    value->type = JUSER;
    value->value = data;
    value->write = write;
    value->destroy = destroy;
  }
  return (jvalue *) value;
}

