#include "arraylist.h"
#include "util.h"

#if defined(_MSC_VER) && _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif


#define ARRAY_EXPAND_SIZE 1024

struct jarraylist {
  int position;
  int size;
  jvalue **value;
};

static void arraycopy(jvalue **dst, int dst_pos, jvalue **src, int src_pos, int src_len)
{
  int i, j;
  if (dst != src || dst_pos < src_pos) {
    j = dst_pos;
    for (i = src_pos; i < src_len; i++) {
      dst[j++] = src[i];
    }
  } else {
    j = dst_pos + src_len - 1;
    for (i = src_pos + src_len - 1; i >= src_pos; i--) {
      dst[j--] = src[i];
    }
  }
}

static int ensure_capacity(jarraylist *list)
{
  list->size += ARRAY_EXPAND_SIZE;
  jvalue **new_value = (jvalue **) util_malloc((unsigned int) list->size * sizeof(jvalue *));
  if (new_value == 0) return JERROR_NOT_ENOUGH_MEMORY;
  arraycopy(new_value, 0, list->value, 0, list->position);
  util_free(list->value);
  list->value = new_value;
  return 0;
}

static void shift_right(jarraylist *list, int index)
{
  arraycopy(list->value, index+1, list->value, index, (list->position - index));
}

static void shift_left(jarraylist *list, int index)
{
  arraycopy(list->value, index, list->value, index+1, (list->position - 1));
}

jarraylist *jarraylist_create(void)
{
  jarraylist *list = (jarraylist *) util_malloc(sizeof(jarraylist));
  list->position = -1;
  list->size = ARRAY_EXPAND_SIZE;
  list->value = (jvalue **) util_malloc((unsigned int) list->size * sizeof(jvalue *));
  return list;
}

void jarraylist_destroy(jarraylist *list)
{
  int i;
  if (list == 0) return;
  if (list->size > 0) {
    for (i = 0; i <= list->position; i++) {
      jvalue_destroy(list->value[i]);
    }
  }
  util_free(list->value);
  util_free(list);
}

void jarraylist_clear(jarraylist *list)
{
  while (list->position >= 0) {
    list->value[list->position] = 0;
    list->position--;
  }
}

unsigned int jarraylist_size(jarraylist *list)
{
  return (unsigned int) (list->position + 1);
}

jvalue *jarraylist_set(jarraylist *list, unsigned int index, jvalue *v)
{
  if ((int) index <= list->position) {
    jvalue *old = list->value[index];
    list->value[index] = v;
    return old;
  }
  return 0;
}

jvalue *jarraylist_get(jarraylist *list, unsigned int index)
{
  if ((int) index <= list->position && list->value != 0) {
    return list->value[index];
  }
  return 0;
}

int jarraylist_add(jarraylist *list, jvalue *v)
{
  if (++list->position < list->size) {
    list->value[list->position] = v;
  } else {
    int error = ensure_capacity(list);
    if (error) return error;
    list->value[list->position] = v;
  }
  return 0;
}

int jarraylist_insert(jarraylist *list, unsigned int index, jvalue *v)
{
  if ((int) index <= list->position && ++list->position < list->size) {
    shift_right(list, (int) index);
    list->value[index] = v;
    return 0;
  }
  return JERROR_OUT_OF_INDEX;
}

jvalue *jarraylist_remove(jarraylist *list, unsigned int index)
{
  if (list->position >= (int) index) {
    jvalue *v = list->value[index];
    shift_left(list, (int) index);
    list->position--;
    return v;
  }
  return 0;
}

#if 0
int main()
{
  int i;

  arraylist *l = arraylist_create();

  for (i = 0; i < 3; i++) {
    arraylist_add(l, i);
  }

  for (i = 0; i <= l->position; i++) {
    printf("1 %d: %d\n", i, l->array[i]);
  }

  arraylist_remove(l, 0);

  for (i = 0; i <= l->position; i++) {
    printf("2 %d: %d\n", i, l->array[i]);
  }

  arraylist_remove(l, 0);

  for (i = 0; i <= l->position; i++) {
    printf("3 %d: %d\n", i, l->array[i]);
  }

  for (i = 0; i < 3; i++) {
    arraylist_add(l, i);
  }

  for (i = 0; i <= l->position; i++) {
    printf("4 %d: %d\n", i, l->array[i]);
  }

  arraylist_clear(l);

  for (i = 0; i < 1; i++) {
    arraylist_add(l, i);
  }

  for (i = 0; i <= l->position; i++) {
    printf("5 %d: %d\n", i, l->array[i]);
  }

  arraylist_insert(l, 0, -1);

  for (i = 0; i <= l->position; i++) {
    printf("6 %d: %d\n", i, l->array[i]);
  }

  arraylist_insert(l, 0, -2);

  for (i = 0; i <= l->position; i++) {
    printf("7 %d: %d\n", i, l->array[i]);
  }

  arraylist_insert(l, 0, -3);

  for (i = 0; i <= l->position; i++) {
    printf("8 %d: %d\n", i, l->array[i]);
  }

  arraylist_destroy(l);

  return 0;
}
#endif
