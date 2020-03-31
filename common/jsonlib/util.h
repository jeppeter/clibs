/*
 * This is free and unencumbered software released into the public domain.
 */

#ifndef RT_UTIL_H
#define RT_UTIL_H

/**
 * @file util.h
 * @brief Utility functions, wrappers, and platform dependent.
 *
 * The utility functions maintain platform Independence.  Some
 * functions are the wrappers of the platform functions to avoid the
 * dependency, some functions use the platform dependent functions.
 *
 * The idea is that this is the only file which needs to be ported
 * when one needs to port this to a new platform.
 *
 * @author nabe@live.com
 * @see https://github.com/routeal/json-parser
 * @see http://unlicense.org
 */


/**
 * @brief Compares two strings incasesensitive
 * @param s1 the string
 * @param s2 the string
 * @param n the length of s1
 * @return 0 for equal
 */
extern int util_strncasecmp(const char *s1, const char *s2, unsigned int n);

/**
 * @brief Converts the string into a double precision floating point.
 * @param str the hex string
 * @param error error an error status
 * @return a double precision floating point
 */
extern double util_strtoreal(const char *str, int *error);

/**
 * @brief Converts the string into a 64bit integer.
 * @param str the string that contains the integer
 * @param error error an error status
 * @return a 64 bit integer
 */
extern long long int util_strtoint(const char *str, int *error);

/**
 * @brief Converts the string representing in hex into an integer.
 * @param str the string that contains the hex number
 * @param error an error status
 * @return an integer
 */
extern unsigned int util_strtohex(const char *str, int *error);

/**
 * @brief Converts the 64 bit integer into a string.
 * @return the number of characters copied into the buffer, or -1 for error
 */
extern int util_inttostr(char *str, unsigned int size, long long int number);

/**
 * @brief Converts the double precision floating point into a string of exponential format.
 * @return the number of characters copied into the buffer, or -1 for error
 */
extern int util_realtostr(char *str, unsigned int size, double number);

/**
 * @brief Converts the 64 bit integer into a string.
 * @return the number of characters copied into the buffer, or -1 for error
 */
extern int util_hextostr(char *str, unsigned int size, unsigned int number);

/**
 * @brief Copies the string from the source at the specified position of the
 * buffer.
 * The buffer grows.
 */
extern void util_strexpand(char **buf, unsigned int *bufsiz, unsigned int *pos,
                           const char *src, unsigned int size);


/**
 * @brief Copies the string.
 * @return the dentition buffer
 */
extern char *util_strncpy(char *dst, unsigned int dsiz,
                          const char *src, unsigned int ssiz);

/**
 * @brief Duplicates and return the string.
 * Returns null when the number of the string exceeds the max-size.
 * @return a pointer to the copied string
 */
extern char *util_strdup(const char *str, unsigned int maxsize, int *error);

/**
 * @brief Malloc wrapper.
 * @param size the size to allocate
 * @return a pointer to the allocated memory space
 */
extern void *util_malloc(unsigned int size);

/**
 * @brief Free wrapper.
 */
extern void util_free(void *ptr);

/**
 * @brief Strcmp wrapper.
 */
extern int util_strcmp(const char *str1, const char *str2);

/**
 * @brief Compares two double values.
 */
extern int util_realcompare(double a, double b);

/**
 * @brief Qsort wrapper.
 */
extern void util_qsort(void *base, unsigned int nel, unsigned int width,
                       int (*compar)(const void *, const void *));

extern int util_strlen(const char* str);

/**
 * @brief Strnlen wrapper.
 */
extern unsigned int util_strnlen(const char *str, unsigned int maxsize);

extern void util_printf(int loglvl,const char* file,int lineno,const char* fmt,...);

#define UTIL_ERROR_LEVEL   1
#define UTIL_WARN_LEVEL    2
#define UTIL_INFO_LEVEL    3
#define UTIL_DEBUG_LEVEL   4

#define UTIL_DEBUG(...)  util_printf(UTIL_DEBUG_LEVEL,__FILE__,__LINE__,__VA_ARGS__)

#endif
