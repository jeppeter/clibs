/*
 * This is free and unencumbered software released into the public domain.
 */

#include "jstring.h"
#include "util.h"

#define UNICODE_MISSING         0xFFFD

#define BUFFER_EXPAND_SIZE      12*12*12

static int isutf8(const char *source, unsigned int length)
{
  unsigned int s = (*source & 0xFF);
  unsigned int a;
  const char *srcptr = source+length;
  switch (length) {
    default: return 0;
    case 4: if ((a = (*--srcptr) & 0xFF) < 0x80 || a > 0xBF) return 0;
    case 3: if ((a = (*--srcptr) & 0xFF) < 0x80 || a > 0xBF) return 0;
    case 2: if ((a = (*--srcptr) & 0xFF) < 0x80 || a > 0xBF) return 0;
      switch (s) {
        case 0xE0: if (a < 0xA0) return 0; break;
        case 0xED: if (a > 0x9F) return 0; break;
        case 0xF0: if (a < 0x90) return 0; break;
        case 0xF4: if (a > 0x8F) return 0; break;
        default:   if (a < 0x80) return 0;
      }
    case 1: if (s >= 0x80 && s < 0xC2) return 0;
  }
  if (s > 0xF4) return 0;
  return 1;
}

/* converts the string into utf16 and returns the number of the bytes consumed */
static const char *utf8toutf16(unsigned short *lead, unsigned short *trail, const char *src)
{
  static const char trailingBytesForUTF8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
  };
  static const unsigned int offsetsFromUTF8[6] = { 0x00000000UL, 0x00003080UL, 0x000E2080UL,
                                                   0x03C82080UL, 0xFA082080UL, 0x82082080UL };
  const char *p = src;
  unsigned int ch = 0;
  unsigned int extraBytesToRead = (unsigned int) trailingBytesForUTF8[(*p & 0xFF)];
  unsigned int i = 0;
  /* initialized before returning */
  *lead = *trail = 0;
  /* checking enough buffer to read */
  while (i < extraBytesToRead) {
    if (p[i+1] == 0) return (p + extraBytesToRead + 1);
    i++;
  }
  if (!isutf8(p, (extraBytesToRead + 1))) return (p + extraBytesToRead + 1);
  switch (extraBytesToRead) {
    case 5: ch += (*p++ & 0xFF); ch <<= 6; /* remember, illegal UTF-8 */
    case 4: ch += (*p++ & 0xFF); ch <<= 6; /* remember, illegal UTF-8 */
    case 3: ch += (*p++ & 0xFF); ch <<= 6;
    case 2: ch += (*p++ & 0xFF); ch <<= 6;
    case 1: ch += (*p++ & 0xFF); ch <<= 6;
    case 0: ch += (*p++ & 0xFF);
  }
  ch -= offsetsFromUTF8[extraBytesToRead];
  if (ch <= 0x0000FFFF) { /* character <= 0xFFFF */
    /* UTF-16 surrogate values are illegal in UTF-32 */
    if (ch >= 0xD800 && ch <= 0xDFFF) {
      *lead = UNICODE_MISSING;
    } else {
      *lead = (unsigned short) ch; /* normal case */
    }
  } else if (ch > 0x0010FFFF) {
    *lead = UNICODE_MISSING;
  } else {
    /* dst is a character in range 0xFFFF - 0x10FFFF. */
    ch -= 0x0010000UL;
    *lead = (unsigned short) ((ch >> 10) + 0xD800);
    *trail = (unsigned short) ((ch & 0x3FFUL) + 0xDC00);
  }
  return p;
}

static const char *utf8tojstr(char *dst, unsigned int size, unsigned int *pos, const char *src)
{
  const char *p = src;
  unsigned short lead, trail;
  p = utf8toutf16(&lead, &trail, p);
  if (dst && (p != src)) {
    int len;
    unsigned int dstsiz;
    char buf[8];
    if (lead) {
      len = util_hextostr(buf, sizeof(buf), lead);
      if (len <= 0) {
        /* error */
      } else {
        dstsiz = size - *pos;
        if (dstsiz > (unsigned int) len) {
          util_strncpy(&dst[*pos], dstsiz, buf, (unsigned int) len);
          *pos += (unsigned int) len;
        } else {
          *pos += (unsigned int) len;
        }
      }
    }
    if (trail) {
      len = util_hextostr(buf, sizeof(buf), trail);
      if (len <= 0) {
        /* error */
      } else {
        dstsiz = size - *pos;
        if (dstsiz > (unsigned int) len) {
          util_strncpy(&dst[*pos], dstsiz, buf, (unsigned int) len);
          *pos += (unsigned int) len;
        } else {
          *pos += (unsigned int) len;
        }
      }
    }
  }
  return p;
}

static const char *digit4tohex(unsigned int *hex, const char* src)
{
  const char *p = src;
  char buf[16] = {0};
  int i = 0;
  unsigned int u = UNICODE_MISSING;
  while (p &&
         ((*p >= '0' && *p <= '9') ||
          (*p >= 'a' && *p <= 'f') ||
          (*p >= 'A' && *p <= 'F')) &&
         (i < 4)) {
    buf[i++] = *p++;
  }
  if (i > 0) {
    int error;
    u = util_strtohex(buf, &error);
  }
  *hex = u;
  return p;
}

static const char *surrogate(unsigned int *hex, const char* src)
{
  const char *p = src;
  unsigned int u = *hex;
  /* leading surrogate */
  if (u >= 0xd800 && u <= 0xdbff) {
    unsigned int u1 = u;
    u = UNICODE_MISSING;
    if (*p++ == '\\') {
      char c = *p++;
      if (c == 'u' || c == 'U') {
        unsigned int u2;
        p = digit4tohex(&u2, p);
        /* trailing surrogate */
        if (u2 >= 0xdc00 && u2 <= 0xdfff) {
          const unsigned int SURROGATE_OFFSET = (unsigned int) (0x10000 - (0xD800 << 10) - 0xDC00);
          u = (u1 << 10) + u2 + SURROGATE_OFFSET;
        }
      }
    }
  }
  *hex = u;
  return p;
}

static void utf32toutf8(char *dst, unsigned int size, unsigned int *pos, unsigned int src)
{
  static const unsigned int firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
  unsigned short bytesToWrite = 0;
  const unsigned int byteMask = 0xBF;
  const unsigned int byteMark = 0x80;
  unsigned int ch = src;
  /* reading size from the code point */
  if (ch < 0x80) bytesToWrite = 1;
  else if (ch <  0x800) bytesToWrite = 2;
  else if (ch <  0x10000) bytesToWrite = 3;
  else if (ch <= 0x0010FFFF) bytesToWrite = 4;
  else { bytesToWrite = 3;
    ch = UNICODE_MISSING;
  }
  /* copy only there is enough space including a null terminator */
  if (bytesToWrite < (size - *pos)) {
    char *p = dst;
    p += *pos;
    p += bytesToWrite;
    switch (bytesToWrite) { /* note: everything falls through. */
      case 4: *--p = (char)((ch | byteMark) & byteMask); ch >>= 6;
      case 3: *--p = (char)((ch | byteMark) & byteMask); ch >>= 6;
      case 2: *--p = (char)((ch | byteMark) & byteMask); ch >>= 6;
      case 1: *--p = (char) (ch | firstByteMark[bytesToWrite]);
    }
  }
  /* advance the position */
  *pos += bytesToWrite;
}

/**
 * Converts \\uxxxx (utf-16) into utf-8.  The fist two characters of
 * "\\u" is already parsed and so the digit string is given.
 */
static const char *utf16toutf8(char *dst, unsigned int size, unsigned int *pos, const char* src)
{
  const char *p = src;
  unsigned int u; /* utf-32 */
  /* converts 4 digits into utf-32 */
  p = digit4tohex(&u, p);
  /* convert surrogate into utf-32 */
  p = surrogate(&u, p);
  /* convert utf-32 into utf-8 */
  if (dst) {
    utf32toutf8(dst, size, pos, u);
  }
  return p;
}

unsigned int strtojstr(char **jstr, const char *str, unsigned int n)
{
  const char *p = str;
  char *dst = 0;
  unsigned int pos = 0;
  unsigned int m = 0;
  while (1) {
    char c = *p;
    if (c == 0) {
      break;
    }
    if (pos >= n) {
      if (dst) util_free(dst);
      dst = 0;
      break;
    }
    /* one unicode character can be 12 bytes in \u unicode format */
    else if ((m - pos) <= 12) {
      unsigned int i = 0;
      char *tmp;
      m += BUFFER_EXPAND_SIZE;
      tmp = util_malloc(m);
      for (i = 0; i < pos; i++) {
        tmp[i] = dst[i];
      }
      if (dst) util_free(dst);
      dst = tmp;
    }
    if (c & 0x80) {
      p = utf8tojstr(dst, m, &pos, p);
    } else {
      if (c == '"' || c == '\\') {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = c;
      }
      else if (c == 0x2f) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = '/';
      }
      else if (c == 0x08) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = 'b';
      }
      else if (c == 0x0c) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = 'f';
      }
      else if (c == 0x0a) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = 'n';
      }
      else if (c == 0x0d) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = 'r';
      }
      else if (c == 0x09) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = 't';
      }
      else if (c >= 0x00 && c <= 0x1f) {
        if (dst && (pos < m)) dst[pos++] = '\\';
        if (dst && (pos < m)) dst[pos++] = c;
      }
      else {
        if (dst && (pos < m)) dst[pos++] = c;
      }
      p++;
    }
  }
  if (dst) dst[pos] = 0;
  *jstr = dst;
  return pos;
}

const char *jstrtostr(char **str, const char *jstr, unsigned int n)
{
  const char* p = jstr;
  unsigned int pos = 0;
  unsigned int m = BUFFER_EXPAND_SIZE;
  char *dst = (char *) util_malloc(BUFFER_EXPAND_SIZE);
  /* must be enclosed by double quotes */
  if (*p != '"') {
    if (dst) *dst = 0;
    *str = dst;
    return p;
  }
  /* empty in the double quotes, but still a minimum json string */
  if (*(p+1) == '"') {
    if (dst) *dst = 0;
    *str = dst;
    return (p+2);
  }
  /* skip the double quote */
  if (*p == '"') p++;
  while (1) {
    char c = *p++;
    if (c == 0) {
      break;
    }
    if (pos >= n) {
      if (dst) util_free(dst);
      dst = 0;
      m = 0;
    }
    /* one unicode character can be 4 bytes in utf-8 */
    else if ((m - pos) <= 4) {
      unsigned int i = 0;
      char *tmp;
      m += BUFFER_EXPAND_SIZE;
      tmp = util_malloc(m);
      for (i = 0; i < pos; i++) {
        tmp[i] = dst[i];
      }
      if (dst) util_free(dst);
      dst = tmp;
    }
    /* look for an escaped double quote not to stop */
    if (c == '\\') {
      c = *p++;
      if (c == 0) {
        break;
      }
      if (c >= 0x00 && c <= 0x1f) {
        if (dst && (pos < m)) dst[pos++] = c;
      }
      /* double quote and backslash must be escaped in json string */
      else if (c == '"' || c == '\\') {
        if (dst && (pos < m)) dst[pos++] = c;
      }
      /* known two-character escape sequence */
      else if (c == '/') {
        if (dst && (pos < m)) dst[pos++] = 0x2f;
      }
      /* known two-character escape sequence */
      else if (c == 'b') {
        if (dst && (pos < m)) dst[pos++] = 0x08;
      }
      /* known two-character escape sequence */
      else if (c == 'f') {
        if (dst && (pos < m)) dst[pos++] = 0x0c;
      }
      /* known two-character escape sequence */
      else if (c == 'n') {
        if (dst && (pos < m)) dst[pos++] = 0x0a;
      }
      /* known two-character escape sequence */
      else if (c == 'r') {
        if (dst && (pos < m)) dst[pos++] = 0x0d;
      }
      /* known two-character escape sequence */
      else if (c == 't') {
        if (dst && (pos < m)) dst[pos++] = 0x09;
      }
      /* unicode, convert into utf-8 */
      else if (c == 'u') {
        p = utf16toutf8(dst, m, &pos, p);
      }
    } else {
      /* stop on double quote */
      if (c == '"') {
        break;
      }
      if (dst && (pos < m)) dst[pos++] = c;
    }
  }
  if (dst) dst[pos] = 0;
  *str = dst;
  return p;
}
