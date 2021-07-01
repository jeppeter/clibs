#include "hashtable.h"
#include "util.h"

#define JHASHTABLE_INITIAL_SIZE   128

typedef struct bucket bucket;
struct bucket
{
  unsigned int hash;
  unsigned int _padding;
  jentry *entry;
  bucket *next;
};

struct jhashtable
{
  bucket **buckets;
  unsigned int bucketCount;
  unsigned int size;
};

static jentry *jentry_create(const char *key, jvalue *value, int *error)
{
  jentry *entry = NULL;
  char *key_copy = NULL;
  if (key == 0 || *key == 0 || value == 0) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  /* returns 0 inf the key is too long */
  key_copy = util_strdup(key, MAX_KEY_STRING_SIZE, 0);
  if (key_copy == 0) {
    if (error) *error = JERROR_TOO_LONG_STRING;
    return 0;
  }
  entry = (jentry *) util_malloc(sizeof(jentry));
  if (entry == 0) {
    if (error) *error = JERROR_NOT_ENOUGH_MEMORY;
    if (key_copy) {
       util_free(key_copy);
    }
    key_copy = NULL;
    return 0;
  }
  entry->key = key_copy;
  entry->value = value;
  return entry;
}

static void jentry_destroy(jentry *entry)
{
  if (entry == 0) return;
  jvalue_destroy(entry->value);
  util_free(entry->key);
  util_free(entry);
}

jhashtable* jhashtable_create(void)
{
  unsigned int minimumBucketCount = JHASHTABLE_INITIAL_SIZE * 4 / 3;
  jhashtable* table = util_malloc(sizeof(jhashtable));
  if (table == 0) return 0;
  table->bucketCount = 1;
  while (table->bucketCount <= minimumBucketCount) {
    table->bucketCount <<= 1;
  }
  table->buckets = util_malloc(table->bucketCount * sizeof(bucket*));
  if (table->buckets == 0) {
    util_free(table);
    return 0;
  }
  table->size = 0;
  return table;
}

static unsigned int hashkey(const char* key)
{
  const char *q;
  unsigned int h;
  /* avoid a crash */
  if (key == 0) return 997;
  h = 5381; /* prime number */
  for (q = key; *q != 0; q++) {
    h = ((h << 5) + h) + (unsigned char) *q;
  }
  return h;
}

static unsigned int get_index(unsigned int bucketCount, unsigned int hash)
{
  return (hash & (bucketCount - 1));
}

static void jhashtable_rehash(jhashtable* table)
{
  if (table->size > (table->bucketCount * 3 / 4)) {
    unsigned int i;
    unsigned int newBucketCount = table->bucketCount << 1;
    bucket **newBuckets = util_malloc(newBucketCount * sizeof(bucket*));
    if (newBuckets == 0) return;
    for (i = 0; i < table->bucketCount; i++) {
      bucket *entry = table->buckets[i];
      while (entry != 0) {
        bucket *next = entry->next;
        unsigned int index = get_index(newBucketCount, entry->hash);
        entry->next = newBuckets[index];
        newBuckets[index] = entry;
        entry = next;
      }
    }
    util_free(table->buckets);
    table->buckets = newBuckets;
    table->bucketCount = newBucketCount;
  }
}

void jhashtable_destroy(jhashtable* table)
{
  unsigned int i;
  for (i = 0; i < table->bucketCount; i++) {
    bucket *entry = table->buckets[i];
    while (entry != 0) {
      bucket *next = entry->next;
      jentry_destroy(entry->entry);
      util_free(entry);
      entry = next;
    }
  }
  util_free(table->buckets);
  util_free(table);
}

unsigned int jhashtable_size(jhashtable* table)
{
  return table->size;
}

static bucket* createbucket(const char* key, unsigned int hash, jvalue* value, int *error)
{
  bucket *entry = util_malloc(sizeof(bucket));
  if (entry == 0) return 0;
  entry->entry = jentry_create(key, value, error);
  if (entry->entry == 0) {
    util_free(entry);
    return 0;
  }
  entry->hash = hash;
  entry->next = 0;
  return entry;
}

static int key_compare(const char* keya, unsigned int hasha, const char* keyb, unsigned int hashb)
{
  if (keya == keyb) return 0;
  if (hasha != hashb) return 1;
  return util_strcmp(keya, keyb);
}

jvalue *jhashtable_put(jhashtable* table, const char* key, jvalue* value, int *error)
{
  unsigned int hash = hashkey(key);
  unsigned int index = get_index(table->bucketCount, hash);
  bucket **p = &(table->buckets[index]);
  if (error) *error = 0;
  while (1) {
    bucket* current = *p;
    if (current == 0) {
      *p = createbucket(key, hash, value, error);
      if (*p == 0) return 0;
      table->size++;
      jhashtable_rehash(table);
      return 0;
    }
    if (key_compare(current->entry->key, current->hash, key, hash) == 0) {
      jvalue *old_value = current->entry->value;
      current->entry->value = value;
      return old_value;
    }
    p = &current->next;
  }
}

jvalue* jhashtable_get(jhashtable* table, const char* key)
{
  unsigned int hash = hashkey(key);
  unsigned int index = get_index(table->bucketCount, hash);
  bucket *entry = table->buckets[index];
  while (entry != 0) {
    if (key_compare(entry->entry->key, entry->hash, key, hash) == 0) {
      return entry->entry->value;
    }
    entry = entry->next;
  }
  return 0;
}

int jhashtable_remove(jhashtable* table, const char* key)
{
  unsigned int hash = hashkey(key);
  unsigned int index = get_index(table->bucketCount, hash);
  bucket **p = &(table->buckets[index]);
  bucket *current;
  while ((current = *p) != 0) {
    if (key_compare(current->entry->key, current->hash, key, hash) == 0) {
      jentry *entry = current->entry;
      *p = current->next;
      util_free(current);
      table->size--;
      jentry_destroy(entry);
      return 0;
    }
    p = &current->next;
  }
  return JERROR_VALUE_NOT_FOUND;
}

int jhashtable_isempty(jhashtable* table)
{
  return (table && table->size > 0) ? 1 : 0;
}

jentry **jhashtable_entries(jhashtable* table, unsigned int *size)
{
  unsigned int i, j;
  jentry **entries;
  if (table == 0 && table->size == 0) {
    if (size) *size = 0;
    return 0;
  }
  entries = (jentry **) util_malloc(table->size * sizeof(jentry *));
  for (i = 0, j = 0; i < table->bucketCount; i++) {
    bucket *entry = table->buckets[i];
    while (entry != 0) {
      bucket *next = entry->next;
      entries[j++] = entry->entry;
      entry = next;
    }
  }
  if (size) *size = j;
  return entries;
}
