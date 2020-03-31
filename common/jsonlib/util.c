/*
 * This is free and unencumbered software released into the public domain.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>

#include "util.h"
#include "jvalue.h"

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf(s, n, format, ...) \
    _snprintf_s(s, n, _TRUNCATE, format, __VA_ARGS__)
#endif

void util_qsort(void *base, unsigned int nel, unsigned int width,
                int (*compar)(const void *, const void *))
{
  qsort(base, nel, width, compar);
}

int util_realcompare(double a, double b)
{
  /* const double d_epsilon = 2.2204460492503131e-016; */
  return (fabs(a - b) < 2.2204460492503131e-16) ? 0 : 1;
}

unsigned int util_strnlen(const char *str, unsigned int maxsize)
{
  unsigned int i = 0;
  const char *s = str;
  for (; (i < maxsize) && *s; ++s, ++i);
  return (unsigned int) (s - str);
}

char *util_strncpy(char *dst, unsigned int dsiz, const char *src, unsigned int ssiz)
{
  char *ret = dst;
  unsigned int n = (dsiz > ssiz) ? ssiz : dsiz;
  while (n > 0 && dst && src && *src) {
    *dst++ = *src++;
    n--;
  }
  while (n--) if (dst) *dst++ = 0;
  return ret;
}

int util_strcmp(const char *str1, const char *str2)
{
    int s1;
    int s2;
    if (str1 == 0 && str2 == 0) return 0;
    if (str1 == 0 || str2 == 0) return (str1 < str2) ? -1 : (str1 > str2);
    do {
      s1 = *str1++;
      s2 = *str2++;
      if (s1 == 0) break;
    } while (s1 == s2);
    return (s1 < s2) ? -1 : (s1 > s2);
}

/*
 * Copies the string to the destination at the specified position of
 * the destination.  If the size of the destination is not large
 * enough to contain the string, the size of the destination will
 * grow.  It returns the pointer of the new buffer, the size of the new
 * buffer, and the position to point the end of the buffer for the
 * next copy.  If memory is out, copy won't happen.
 */
void util_strexpand(char **buf, unsigned int *bufsiz, unsigned int *pos,
                    const char *src, unsigned int size)
{
  const unsigned int STR_SIZE = 4096; /* string expanding size */
  unsigned int i, j;
  /* grows the destination buffer */
  if ((*bufsiz - *pos) <= size) {
    char *tmp;
    unsigned int newsize = (*bufsiz + 1);
    newsize += ((size > STR_SIZE) ? (size + STR_SIZE) : STR_SIZE);
    tmp = (char *) calloc(newsize, 1);
    if (tmp) {
      util_strncpy(tmp, newsize, *buf, *pos);
      free(*buf);
      *buf = tmp;
      *bufsiz = newsize;
    } else {
      /* won't copy but returns the new position */
      *pos += size;
      return;
    }
  }
  /* the destination size is large enough to be copied */
  for (i = *pos, j = 0; j < size; i++, j++) {
    (*buf)[i] = src[j];
  }
  (*buf)[i] = 0;
  /* returns the new position */
  *pos += size;
}

/*
 * Converts the string to a double precision floating point.
 */
double util_strtoreal(const char *str, int *error)
{
  char *tmp;
  double real_number;
  if (str == NULL) {
    if (error) *error = 1;
    return 0;
  }
  /*we pretend the not error*/
  errno = 0;
  real_number = strtod(str, &tmp);
  /* can't convert, must be a garbage string */
  if (str == tmp) {
    if (error) *error = 1;
  } else {
    /* out of range, set to 0 */
    if (errno == ERANGE) {
      real_number = 0;
    }
    if (error) *error = 0;
  }
  return real_number;
}

/*
 * Converts the string to a 64 bit integer.
 */
long long int util_strtoint(const char *str, int *error)
{
  char *tmp;
  long long int int_number;
  if (str == NULL) {
    if (error) *error = 1;
    return 0;
  }
  /*we make sure not error first*/
  errno = 0;
  int_number = strtoll(str, &tmp, 0);
  /* can't convert, must be a garbage string */
  if (str == tmp) {
    if (error) *error = 1;
  } else {
    /* out of range, set to 0 we do not use errno*/
    if (errno == ERANGE) {
      int_number = 0;
    }
    if (error) *error = 0;
  }
  return int_number;
}

int util_inttostr(char *str, unsigned int size, long long int number)
{
  return snprintf(str, size, "%lld", number);
}

/*
 * Converts a double value to string in exponential format, normalizes
 * a number at the same time.
 */
int util_realtostr(char *str, unsigned int size, double number)
{
  char *e;
  char tmp[1024] = {0};
  unsigned int len = 0;
  if (str == NULL) return -1;
  /* convert into exponential number */
  snprintf(tmp, sizeof(tmp), "%.*e", 10, number);
  /* find exponent position */
  e = tmp;
  for (; *e != 0; e++) {
    if (*e == 'e') break;
  }
  if (e) {
    int power;
    char *zero = e;
    /* trim excess zeros */
    while (zero[-1] == '0') zero--;
    /* trim . if it is is the last one */
    if (*(zero-1) == '.') zero--;
    *zero = 0;
    power = (int) strtol(&e[1], 0, 10);
    if (power == 0) {
      len = (unsigned int) snprintf(str, size, "%s", tmp);
    } else if (power > 0) {
      len = (unsigned int) snprintf(str, size, "%sE+%d", tmp, power);
    } else {
      len = (unsigned int) snprintf(str, size, "%sE%d", tmp, power);
    }
  } else {
    unsigned int i;
    for (i = 0; tmp[i] != 0 && i < size; i++) {
      str[i] = tmp[i];
    }
    str[i] = 0;
    len = i;
  }
  return (int) len;
}

unsigned int util_strtohex(const char *str, int *error)
{
  char *tmp;
  int int_number;
  if (str == NULL) {
    if (error) *error = 1;
    return 0;
  }
  int_number = (int) strtol(str, &tmp, 16);
  if (str == tmp) {
    if (error) *error = 1;
  } else {
    /* out of range, set to 0 */
    if (errno == ERANGE || int_number < 0) {
      int_number = 0;
    }
    if (error) *error = 0;
  }
  return (unsigned int) int_number;
}

int util_hextostr(char *str, unsigned int size, unsigned int number)
{
  return snprintf(str, size, "\\u%04X", number);
}


/*
 * Compares two strings in case insensitive.
 */
int util_strncasecmp(const char *s1, const char *s2, unsigned int n)
{
  const unsigned char *p1 = (const unsigned char *) s1;
  const unsigned char *p2 = (const unsigned char *) s2;
  int c1, c2;
  if (p1 == p2 || n == 0) return 0;
  do {
    c1 = *p1++;
    c2 = *p2++;
    c1 = ((('A' <= c1) && (c1 <= 'Z')) ? ('a' + (c1 - 'A')) : c1);
    c2 = ((('A' <= c2) && (c2 <= 'Z')) ? ('a' + (c2 - 'A')) : c2);
    if (c1 == 0 || c1 != c2) return c1 - c2;
  } while (--n > 0);
  return c1 - c2;
}

/*
 * Creates a copy of the string but returns null when exceeds max-size.
 */
char *util_strdup(const char *str, unsigned int maxsize, int *error)
{
  char *dup;
  unsigned int len;
  if (str == NULL) {
    if (error) *error = JERROR_NULL_PARAM;
    return 0;
  }
  len = (unsigned int) util_strnlen(str, maxsize);
  if (len >= maxsize) {
    if (error) *error = JERROR_TOO_LONG_STRING;
    return 0;
  }
  dup = (char *) calloc(len + 1, 1);
  if (dup == NULL) {
  if (error) *error = 1;
    return 0;
  }
  util_strncpy(dup, (len + 1), str, len);
  dup[len] = 0;
  if (error) *error = JERROR_NOT_ENOUGH_MEMORY;
  return dup;
}

void *util_malloc(unsigned int size)
{
  return calloc(1, (size_t) size);
}

void util_free(void *ptr)
{
  free(ptr);
}

static int st_util_loglvl=-1;

void __init_util_log_level(void)
{
  char* pnum;
  int num=0;
  if (st_util_loglvl >= 0) {
    return ;
  }
  pnum = getenv("JSONLIB_LOGLEVEL");
  if (pnum != NULL) {
    num = atoi(pnum);
    if (num < 0) {
      num = 0;
    }
  }
  st_util_loglvl = num;
  return ;
}

void util_printf(int loglvl,const char* file,int lineno,const char* fmt,...)
{
  va_list ap;
  __init_util_log_level();
  if (loglvl <= st_util_loglvl) {
    va_start(ap,fmt);
    fprintf(stderr,"[%s:%d]",file,lineno);
    vfprintf(stderr,fmt,ap);
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  return;
}

int util_strlen(const char* str)
{
  char* ptr = (char*)str;
  int retlen = 0;
  while (ptr && *ptr) {
    ptr ++;
    retlen ++;
  }

  return retlen;
}