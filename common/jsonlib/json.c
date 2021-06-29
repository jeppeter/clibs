/*
 * This is free and unencumbered software released into the public domain.
 */

#include "jvalue.h"
#include "jstring.h"
#include "util.h"
#include "arraylist.h"

#if defined(_MSC_VER) && _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif


/* Max number of the JSON number string */
#define MAX_VALUE_NUMBER_SIZE   64

/**
 * JSON spec:
 * Insignificant whitespace is allowed before or after any token. The
 * whitespace characters are: character tabulation (U+0009), line feed
 * (U+000A), carriage return (U+000D), and space (U+0020). Whitespace is
 * not allowed within any token, except that space is allowed in strings.
 */
#define SKIP_WHITESPACE(p)      while (*(p) == ' '  || *(p) == '\t' ||  \
                                       *(p) == '\n' || *(p) == '\r') (p)++

static const char *parse_json_number(jvalue **value, const char* src);
static const char *parse_json_value(jvalue **value, const char *key, const char *src);
static const char *parse_json_object(jvalue *table, const char *src);

static void print_jvalue(const jvalue *value, char **buf, unsigned int *bufsiz, unsigned int *pos);
static void print_jarray(const jarray *array, char **buf, unsigned int *bufsiz, unsigned int *pos);
static void print_jentry(const jentry *object, char **buf, unsigned int *bufsiz, unsigned int *pos);
static void print_jobject(const jobject *table, char **buf, unsigned int *bufsiz, unsigned int *pos);

/******************************************************************************/
/* reading */
/******************************************************************************/

/**
 * Parses the JSON string and returns either of number, true, false,
 * or null into the jvalue object.
 */
static const char *parse_json_number(jvalue **parent, const char* src)
{
  /* 0-9, a-f, A-F, true/false, null, , }, ] +/-, . */
  /* to set nl(new line) cr(carrige return) as the terminator 2*/
  const char number_characters[128] = {
    0,/*nul*/  0,/*soh*/  0,/*stx*/  0,/*etx*/  0,/*eot*/  0,/*enq*/  0,/*ack*/  0,/*bel*/
    0,/*bs */  0,/*ht */  2,/*nl */  0,/*vt */  0,/*np */  2,/*cr */  0,/*so */  0,/*si */
    0,/*dle*/  0,/*dc1*/  0,/*dc2*/  0,/*dc3*/  0,/*dc4*/  0,/*nak*/  0,/*syn*/  0,/*etb*/
    0,/*can*/  0,/*em */  0,/*sub*/  0,/*esc*/  0,/*fs */  0,/*gs */  0,/*rs */  0,/*us */
    0,/*sp */  0,/* ! */  0,/* " */  0,/* # */  0,/* $ */  0,/* % */  0,/* & */  0,/* ' */
    0,/* ( */  0,/* ) */  0,/* * */  3,/* + */  2,/* , */  3,/* - */  4,/* . */  0,/* / */
    3,/* 0 */  3,/* 1 */  3,/* 2 */  3,/* 3 */  3,/* 4 */  3,/* 5 */  3,/* 6 */  3,/* 7 */
    3,/* 8 */  3,/* 9 */  0,/* : */  0,/* ; */  0,/* < */  0,/* = */  0,/* > */  0,/* ? */
    0,/* @ */  1,/* A */  1,/* B */  1,/* C */  1,/* D */  4,/* E */  1,/* F */  0,/* G */
    0,/* H */  0,/* I */  0,/* J */  0,/* K */  1,/* L */  0,/* M */  1,/* N */  0,/* O */
    0,/* P */  0,/* Q */  1,/* R */  1,/* S */  1,/* T */  1,/* U */  0,/* V */  0,/* W */
    0,/* X */  0,/* Y */  0,/* Z */  0,/* [ */  0,/* \ */  2,/* ] */  0,/* ^ */  0,/* _ */
    0,/* ` */  1,/* a */  1,/* b */  1,/* c */  1,/* d */  4,/* e */  1,/* f */  0,/* g */
    0,/* h */  0,/* i */  0,/* j */  0,/* k */  1,/* l */  0,/* m */  1,/* n */  0,/* o */
    0,/* p */  0,/* q */  1,/* r */  1,/* s */  1,/* t */  1,/* u */  0,/* v */  0,/* w */
    0,/* x */  0,/* y */  0,/* z */  0,/* { */  0,/* | */  2,/* } */  0,/* ~ */  0,/*del*/
  };
  const char *p = src;
  char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
  unsigned int pos = 0;
  jvalue *value = 0;
  int c = (*p & 0xFF);
  if (c >= 0x7F || number_characters[c] == 0) return (p + 1);
  while (*p) {
    if (number_characters[*p & 0xFF] == 2) break;
    if (pos < MAX_VALUE_NUMBER_SIZE) tmp[pos++] = *p;
    p++;
  }
  /* empty if the size is too large */
  if (pos >= MAX_VALUE_NUMBER_SIZE) pos = 0;
  tmp[pos] = 0;
  UTIL_DEBUG("p %p src %p pos %d tmp %s",p,src,pos,tmp);
  /* empty character */
  if (p == src) {
    value = jnull_create();
  }
  /* string is larger than MAX_VALUE_NUMBER_SIZE */
  else if (pos == 0) {
    value = jint_create(0);
  } else {
    /* null value */
    if (util_strncasecmp("null", tmp, 4) == 0) {
      value = jnull_create();
    }
    /* true value */
    else if (util_strncasecmp("true", tmp, 4) == 0) {
      value = jbool_create(1);
    }
    /* false value */
    else if (util_strncasecmp("false", tmp, 5) == 0) {
      value = jbool_create(0);
    }
    /* number value */
    else {
      const char *pp = tmp;
      int type = JINT;
      UTIL_DEBUG(" ");
      /* number could be 0, 1-9, ., e, E, +, - */
      while (*pp) {
        if (number_characters[*pp & 0xFF] >= 3) {
          if (number_characters[*pp & 0xFF] == 4) type = JREAL;
        } else {
          UTIL_DEBUG("*pp %c 0x%02x",*pp,(unsigned char)*pp);
          /* not a number character */
          type = JNONE;
          break;
        }
        pp++;
      }
      /* not a number */
      if (type == JNONE) {
        value = jnull_create();
      }
      /* real number */
      else if (type == JREAL) {
        int error;
        double real_number = util_strtoreal(tmp, &error);
        if (error) return 0;
        value = jreal_create(real_number);
      }
      /* int or int64 */
      else {
        int error;
        long long int int_number = util_strtoint(tmp, &error);
        UTIL_DEBUG("tmp %s int_number %lld",tmp,int_number);
        if (error) return 0;
        /* 2147483647 is the max of the signed 32 bit integer */
        if (int_number > 2147483647) {
          value = jint64_create(int_number);
          UTIL_DEBUG("value %lld",value->_integer64.value);
        } else {
          value = jint_create((int) int_number);
          UTIL_DEBUG("value %d",value->_integer.value);
        }

      }
    }
  }
  *parent = value;
  return p;
}

/**
 * Parses the JSON string and returns a json value into the jvalue
 * object.  jvalue can be any one of the JSON values, object, array,
 * string, number, true, false, and null.
 */
static const char *parse_json_value(jvalue **parent, const char *key, const char *src)
{
  const char *p = src;
  jvalue *value = 0;
  SKIP_WHITESPACE(p);
  /* array */
  if (*p == '[') {
    jvalue *array = jarray_create();
    /* advance the pointer to next */
    if (p) p++;
    while (p && *p != 0 && *p != ']') {
      /* advance the pointer to next */
      p = parse_json_value(&array, key, p);
      if (p) {
        SKIP_WHITESPACE(p);
        if (*p == ',') p++;
        SKIP_WHITESPACE(p);
      }
    }
    if (p && (*p == ']')) p++; /* increment to point the next */
    value = array;
  }
  /* object */
  else if (*p == '{') {
    jvalue *table = jobject_create();
    p = parse_json_object(table, p);
    value = table;
  }
  /* string */
  else if (*p == '"') {
    char *string_value = 0;
    p = jstrtostr(&string_value, p, MAX_VALUE_STRING_SIZE);
    value = jstring_create(string_value, 0);
    util_free(string_value);
  }
  /* number, true, false, null */
  else if (*p != 0) {
    jvalue *number = 0;
    p = parse_json_number(&number, p);
    value = number;
  }
  if (*parent) {
    jvalue *tmp = *parent;
    if (tmp->type == JOBJECT) {
      if (key) {
        int error;
        jobject_put(tmp, key, value, &error);
        if (error != 0) {
          jvalue_destroy(value);
        }
      } else {
        jvalue_destroy(value);
      }
    } else if (tmp->type == JARRAY) {
      if (jarray_put(tmp, value) != 0) {
        jvalue_destroy(value);
      }
    } else {
      jvalue_destroy(value);
    }
  } else {
    *parent = value;
  }
  return p;
}

/**
 * Parses the JSON string and returns a list of JSON objects into
 * jvalue.
 */
const char *parse_json_object(jvalue *table, const char *src)
{
  char *key = 0;
  const char *p = src;
  if (table->type != JOBJECT) return p;
  while (p && *p) {
    SKIP_WHITESPACE(p);
    /* json object starting bracket */
    if (*p == '{') {
      p++;
    }
    /* json object ending bracket */
    else if (*p == '}') {
      /* must be a closure of this json object */
      p++;
      break;
    }
    /* string of json object */
    else if (*p == '"') {
      /* copy from the 'p' pointer to the next double quote */
      p = jstrtostr(&key, p, MAX_KEY_STRING_SIZE);
    }
    /* separator between string and value */
    else if (*p == ':') {
      p++;
      p = parse_json_value(&table, key, p);
      if (key) {
        util_free(key);
        key = 0;
      }
    }
    /* delimiter */
    else if (*p == ',') {
      p++;
    }
    /* error */
    else {
      p++;
    }
  }
  return p;
}

/**
 * Converts the JSON string into a jvalue object.
 * TODO: jvalue *jvalue_read(const char *json, unsigned int maxsize)
 */
jvalue *jvalue_read(const char *json, unsigned int *size)
{
  jvalue *value = 0;
  const char *p = json, *pp;
  if (p == 0 || *p == 0) return 0;
  /* skip the utf-8 bom */
  if (((*p & 0xFF) == 0xEF) &&
      ((p+1) && (*(p+1) & 0xFF) == 0xBB) &&
      ((p+2) && (*(p+2) & 0xFF) == 0xBF)) {
    p += 3;
  }
  pp = parse_json_value(&value, 0, p);
  if (size) *size = (unsigned int) (pp - p);
  return value;
}

/******************************************************************************/
/* writing */
/******************************************************************************/

/**
 * Prints the jarray object into JSON
 */
static void print_jarray(const jarray *array, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  unsigned int i;
  if (array == 0) return;
  util_strexpand(buf, bufsiz, pos, "[", 1);
  for (i = 0; i < jarray_size((const jvalue *) array); i++) {
    if (i != 0) util_strexpand(buf, bufsiz, pos, ",", 1);
    print_jvalue(jarray_get((const jvalue *) array, i, 0), buf, bufsiz, pos);
  }
  util_strexpand(buf, bufsiz, pos, "]", 1);
}


/**
 * Prints the jvalue object into JSON
 */
static void print_jvalue(const jvalue *value, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  if (value == 0) return;
  if (value->type == JNULL) {
    util_strexpand(buf, bufsiz, pos, "null", 4);
  } else if (value->type == JSTRING) {
    const jstring *v = (const jstring *) value;
    char *s = (char *) v->value;
    if (s && *s) {
      char *tmp = 0;
      unsigned int len = strtojstr(&tmp, s, MAX_VALUE_STRING_SIZE);
      util_strexpand(buf, bufsiz, pos, "\"", 1);
      if (tmp) util_strexpand(buf, bufsiz, pos, tmp, len);
      util_strexpand(buf, bufsiz, pos, "\"", 1);
      util_free(tmp);
    } else {
      util_strexpand(buf, bufsiz, pos, "\"\"", 2);
    }
  } else if (value->type == JINT) {
    const jint *v = (const jint *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_inttostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JINT64) {
    const jint64 *v = (const jint64 *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_inttostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JBOOL) {
    const jbool *v = (const jbool *) value;
    if (v->value) {
      util_strexpand(buf, bufsiz, pos, "true", 4);
    } else {
      util_strexpand(buf, bufsiz, pos, "false", 5);
    }
  } else if (value->type == JUSER) {
    const juser *v = (const juser *) value;
    if (v->write) {
      char* tmp = util_malloc(MAX_VALUE_STRING_SIZE);
      if (tmp) {
        unsigned int len = v->write(v->value, tmp, MAX_VALUE_STRING_SIZE);
        util_strexpand(buf, bufsiz, pos, tmp, len);
        util_free(tmp);        
      }
    } else {
      util_strexpand(buf, bufsiz, pos, "null", 4);
    }
  } else if (value->type == JREAL) {
    const jreal *v = (const jreal *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_realtostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JOBJECT) {
    print_jobject((const jobject *) value, buf, bufsiz, pos);
  } else if (value->type == JARRAY) {
    print_jarray((const jarray *) value, buf, bufsiz, pos);
  }
}



/**
 * Prints the jentry object into JSON
 */
static void print_jentry(const jentry *object, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  char *tmp = 0;
  unsigned int length;
  if (object == 0) return;
  /* escape the key string */
  length = strtojstr(&tmp, object->key, MAX_KEY_STRING_SIZE);
  util_strexpand(buf, bufsiz, pos, "\"", 1);
  if (tmp) util_strexpand(buf, bufsiz, pos, tmp, length);
  util_strexpand(buf, bufsiz, pos, "\":", 2);
  print_jvalue(object->value, buf, bufsiz, pos);
  util_free(tmp);
}



/**
 * Prints the jvalue (a list of jentry) object into JSON
 */
static void print_jobject(const jobject *table, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  unsigned int size, i;
  jentry **objects;
  if (table == 0) return;
  /* get the whole items */
  objects = jobject_entries((const jvalue *) table, &size);
  /* opening left bracket */
  util_strexpand(buf, bufsiz, pos, "{", 1);
  for (i = 0; i < size; i++) {
    jentry *object = objects[i];
    /* comma separator between objects */
    if (i != 0) util_strexpand(buf, bufsiz, pos, ",", 1);
    print_jentry(object, buf, bufsiz, pos);
  }
  util_strexpand(buf, bufsiz, pos, "}", 1);
  util_free(objects);
}


char *jvalue_write(const jvalue *value, unsigned int *return_size)
{
  unsigned int pos;
  unsigned int size;
  char *buf;
  if (value == 0) return 0;
  /* initial buf size, buf will grow */
  size = 0;
  buf = 0;
  pos = 0;
  print_jvalue(value, &buf, &size, &pos);
  if (return_size) *return_size = pos;
  return buf;
}

/******************************************************
* these are the utf-8 mode function
******************************************************/

static void print_jvalue_raw(const jvalue *value, char **buf, unsigned int *bufsiz, unsigned int *pos);

/**
 * Prints the jentry object into JSON
 */
static void print_jentry_raw(const jentry *object, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  char *s = 0;
  unsigned int length;
  if (object == 0) return;
  /* escape the key string */
  s = object->key;
  length = util_strlen(s);
  util_strexpand(buf, bufsiz, pos, "\"", 1);
  util_strexpand(buf, bufsiz, pos, s, length);
  util_strexpand(buf, bufsiz, pos, "\":", 2);
  print_jvalue_raw(object->value, buf, bufsiz, pos);
}

/**
 * Prints the jarray object into JSON
 */
static void print_jarray_raw(const jarray *array, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  unsigned int i;
  if (array == 0) return;
  util_strexpand(buf, bufsiz, pos, "[", 1);
  for (i = 0; i < jarray_size((const jvalue *) array); i++) {
    if (i != 0) util_strexpand(buf, bufsiz, pos, ",", 1);
    print_jvalue_raw(jarray_get((const jvalue *) array, i, 0), buf, bufsiz, pos);
  }
  util_strexpand(buf, bufsiz, pos, "]", 1);
}


/**
 * Prints the jvalue (a list of jentry) object into JSON
 */
static void print_jobject_raw(const jobject *table, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  unsigned int size, i;
  jentry **objects;
  if (table == 0) return;
  /* get the whole items */
  objects = jobject_entries((const jvalue *) table, &size);
  /* opening left bracket */
  util_strexpand(buf, bufsiz, pos, "{", 1);
  for (i = 0; i < size; i++) {
    jentry *object = objects[i];
    /* comma separator between objects */
    if (i != 0) util_strexpand(buf, bufsiz, pos, ",", 1);
    print_jentry_raw(object, buf, bufsiz, pos);
  }
  util_strexpand(buf, bufsiz, pos, "}", 1);
  util_free(objects);
}


/**
 * Prints the jvalue object into JSON
 */
static void print_jvalue_raw(const jvalue *value, char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  if (value == 0) return;
  if (value->type == JNULL) {
    util_strexpand(buf, bufsiz, pos, "null", 4);
  } else if (value->type == JSTRING) {
    const jstring *v = (const jstring *) value;
    char *s = (char *) v->value;
    if (s && *s) {
      unsigned int len = util_strlen(s);
      util_strexpand(buf, bufsiz, pos, "\"", 1);
      util_strexpand(buf, bufsiz, pos, s, len);
      util_strexpand(buf, bufsiz, pos, "\"", 1);
    } else {
      util_strexpand(buf, bufsiz, pos, "\"\"", 2);
    }
  } else if (value->type == JINT) {
    const jint *v = (const jint *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_inttostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JINT64) {
    const jint64 *v = (const jint64 *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_inttostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JBOOL) {
    const jbool *v = (const jbool *) value;
    if (v->value) {
      util_strexpand(buf, bufsiz, pos, "true", 4);
    } else {
      util_strexpand(buf, bufsiz, pos, "false", 5);
    }
  } else if (value->type == JUSER) {
    const juser *v = (const juser *) value;
    if (v->write) {
      char* tmp = util_malloc(MAX_VALUE_STRING_SIZE);
      if (tmp) {
        unsigned int len = v->write(v->value, tmp, MAX_VALUE_STRING_SIZE);
        util_strexpand(buf, bufsiz, pos, tmp, len);
        util_free(tmp);        
      }
    } else {
      util_strexpand(buf, bufsiz, pos, "null", 4);
    }
  } else if (value->type == JREAL) {
    const jreal *v = (const jreal *) value;
    char tmp[MAX_VALUE_NUMBER_SIZE] = {0};
    int len = util_realtostr(tmp, sizeof(tmp), v->value);
    util_strexpand(buf, bufsiz, pos, tmp, (unsigned int) len);
  } else if (value->type == JOBJECT) {
    print_jobject_raw((const jobject *) value, buf, bufsiz, pos);
  } else if (value->type == JARRAY) {
    print_jarray_raw((const jarray *) value, buf, bufsiz, pos);
  }
}


char *jvalue_write_raw(const jvalue *value, unsigned int *return_size)
{
  unsigned int pos;
  unsigned int size;
  char *buf;
  if (value == 0) return 0;
  /* initial buf size, buf will grow */
  size = 0;
  buf = 0;
  pos = 0;
  print_jvalue_raw(value, &buf, &size, &pos);
  if (return_size) *return_size = pos;
  return buf;
}


/******************************************************************************/
/* writing pretty */
/******************************************************************************/

/* quick macro to add tabs */
#define ADD_TABS(t) { \
    int _k = 0;                                                     \
    while (_k++ < (t)) util_strexpand(buf, bufsiz, pos, "\t", 1);   \
  }

static const char *prretty_print_json_value(const char *src, char **buf, unsigned int *bufsiz, unsigned int *pos, int *ret, int tab);

static const char *pretty_print_json_object(const char *src, char **buf, unsigned int *bufsiz, unsigned int *pos, int *ret, int tab)
{
  const char *p = src;
  while (p && *p) {
    /* json object starting bracket */
    if (*p == '{') {
      p++;
      if (*ret) ADD_TABS(tab);
      util_strexpand(buf, bufsiz, pos, "{\n", 2);
    }
    /* json object ending bracket */
    else if (*p == '}') {
      /* must be a closure of this json object */
      p++;
      util_strexpand(buf, bufsiz, pos, "\n", 1);
      ADD_TABS(tab);
      util_strexpand(buf, bufsiz, pos, "}", 1);
      break;
    }
    /* string of json object */
    else if (*p == '"') {
      p++;
      ADD_TABS(tab+1);
      util_strexpand(buf, bufsiz, pos, "\"", 1);
      while (1) {
        if (*p == '\\') {
          util_strexpand(buf, bufsiz, pos, p++, 1);
        } else if (*p == '"') {
          break;
        }
        util_strexpand(buf, bufsiz, pos, p++, 1);
      }
      util_strexpand(buf, bufsiz, pos, p++, 1);
    }
    /* separator between string and value */
    else if (*p == ':') {
      p++;
      util_strexpand(buf, bufsiz, pos, " : ", 3);
      *ret = 0;
      p = prretty_print_json_value(p, buf, bufsiz, pos, ret, tab+1);
    }
    /* delimiter */
    else if (*p == ',') {
      p++;
      util_strexpand(buf, bufsiz, pos, ",\n", 2);
    }
  }
  return p;
}

static const char *pretty_print_json_number(const char *src,
                                            char **buf, unsigned int *bufsiz, unsigned int *pos)
{
  const char *p = src;
  const char delimiters[] = {',', '}', ']'};
  while (*p) {
    unsigned int i;
    for (i = 0; i < 3; i++) {
      if (*p == delimiters[i]) break;
    }
    if (i < 3) break;
    util_strexpand(buf, bufsiz, pos, p++, 1);
  }
  return p;
}

static const char *prretty_print_json_value(const char *src,
                                            char **buf, unsigned int *bufsiz, unsigned int *pos,
                                            int *ret, int tab)
{
  const char *p = src;
  /* array */
  if (*p == '[') {
    p++;
    if (*ret == 1) {
      util_strexpand(buf, bufsiz, pos, "\n", 1);
      ADD_TABS(tab);
    }
    util_strexpand(buf, bufsiz, pos, "[", 1);
    while (*p != ']') {
      *ret = 1;
      p = prretty_print_json_value(p, buf, bufsiz, pos, ret, tab+1);
      if (*p == ',') {
        p++;
        util_strexpand(buf, bufsiz, pos, ", ", 2);
      }
    }
    if (*p == ']') {
      p++;
      if (*ret == 1) {
        util_strexpand(buf, bufsiz, pos, "\n", 1);
        ADD_TABS(tab);
      }
      util_strexpand(buf, bufsiz, pos, "]", 1);
    }
    *ret = 1;
  }
  /* object */
  else if (*p == '{') {
    if (*ret == 1) util_strexpand(buf, bufsiz, pos, "\n", 1);
    p = pretty_print_json_object(p, buf, bufsiz, pos, ret, tab);
    *ret = 1;
  }
  /* string */
  else if (*p == '"') {
    p++;
    util_strexpand(buf, bufsiz, pos, "\"", 1);
    while (1) {
      if (*p == '\\') {
        util_strexpand(buf, bufsiz, pos, p++, 1);
      } else if (*p == '"') {
        break;
      }
      util_strexpand(buf, bufsiz, pos, p++, 1);
    }
    util_strexpand(buf, bufsiz, pos, p++, 1);
    *ret = 0;
  }
  /* number, true, false, null */
  else if (*p != 0) {
    p = pretty_print_json_number(p, buf, bufsiz, pos);
    *ret = 0;
  }
  return p;
}

char *jvalue_write_pretty(const jvalue *value, unsigned int *return_size)
{
  char *buf = 0;
  char *str = jvalue_write(value, 0);
  if (str) {
    unsigned int pos = 0;
    unsigned int size = 0;
    int ret = 0;
    prretty_print_json_value(str, &buf, &size, &pos, &ret, 0);
    util_free(str);
    if (return_size) *return_size = pos;
  }
  return buf;
}
