/*
 * This is free and unencumbered software released into the public domain.
 */

#ifndef RT_JVALUE_H
#define RT_JVALUE_H

/*for common cmn_err.h*/
#include <cmn_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Error Status Codes
 * @brief Error status codes
 *
 * Generally it returns 0 on success.  On error, it returns -1 for all
 * unknown cause.  When the cause is known, the error status code is
 * returned.
 */

/**
 * @defgroup Jvalue Data Structure
 * @brief Jvalue data structures
 *
 * Jvalue data structures are the main data structures which is
 * composed from a JSON string and is parsed to a JSON string
 * respectively.
 */

/**
 * @defgroup Functions Functions
 * @brief API functions
 *
 * The API functions provides methods to manipulate the jvalue data structures.
 */

/**
 * @file jvalue.h
 * @brief JSON reader and writer
 *
 * This reads and writes JSON.  Also, this provides the data
 * structures which corresponds JSON data type.
 *
 * @see https://github.com/routeal/json-parser
 * @see http://www.json.org
 * @see http://unlicense.org
 */

/** @addtogroup Error */
/*@{*/

/**
 * Error status codes
 */
typedef enum {
  JERROR_UNKNOWN           = -1, /**< -1, unknown error */
  JERROR_NONE              = 0,  /**<  0, success */
  JERROR_VALUE_NOT_FOUND   = 1,  /**<  1, value not found */
  JERROR_NULL_PARAM        = 2,  /**<  2, null parameter */
  JERROR_WRONG_PARAM_TYPE  = 3,  /**<  3, wrong data type in parameter */
  JERROR_WRONG_VALUE_TYPE  = 4,  /**<  4, wrong value type to inquiry */
  JERROR_NOT_ENOUGH_MEMORY = 5,  /**<  5, not enough memory */
  JERROR_TOO_LONG_STRING   = 6,  /**<  6, exceeding string size  */
  JERROR_OUT_OF_INDEX      = 7   /**<  7, out of index  */
} JERROR_STATUS;

/*@}*/

/** @addtogroup Jvalue */
/*@{*/

/* \cond */
/* forwarding declaration of jhashtable, internal data structure */
typedef struct jhashtable jhashtable;
/* \endcond */

/* \cond */
/* forwarding declaration of jarraylist, internal data structure */
typedef struct jarraylist jarraylist;
/* \endcond */

/* forwarding declarations */
/** Key/value entry for jobect */
typedef struct jentry   jentry;
/** 8 bit string data */
typedef struct jstring  jstring;
/** Boolean data */
typedef struct jbool    jbool;
/** Null data */
typedef struct jnull    jnull;
/** Array data */
typedef struct jarray   jarray;
/** 64 bit double precision floating point data */
typedef struct jreal    jreal;
/** 32 bits integer */
typedef struct jint     jint;
/** 64 bits long integer */
typedef struct jint64   jint64;
/** List of key/value objects */
typedef struct jobject jobject;
/** User defined data */
typedef struct juser    juser;
/** Jvalue union */
typedef union  jvalue   jvalue;

/**
 * Data type identifier
 */
typedef enum {
  JNONE,        /**< None, not be used */
  JNULL,        /**< Null data type */
  JBOOL,        /**< Boolean data type */
  JINT,         /**< 32 bits integer type */
  JINT64,       /**< 64 bits long integer type */
  JREAL,        /**< 64 bit double precision floating point data type */
  JSTRING,      /**< String data type */
  JARRAY,       /**< Array data type */
  JOBJECT,      /**< List of key/value objects data type */
  JUSER         /**< User defined data type */
} JTYPE;

/**
 * @brief Boolean data type
 */
struct jbool {
  int type; /**< JBOOL */
  int value; /**< boolean value, 1 for true, 0 for false */
};

/**
 * @brief Null data type
 */
struct jnull {
  int type; /**< JNULL */
};

/**
 * @brief 32 bit integer data type
 */
struct jint {
  int type; /**< JINT */
  int value;  /**< 32 bit integer */
};

/**
 * @brief 64 bit integer data type
 */
struct jint64 {
  int type; /**< JINT64 */
  /* \cond */
  char _padding[4];
  /* \endcond */
  long long int value; /**< 64 bit integer */
};

/**
 * @brief 64 bit double precision floating point data type
 */
struct jreal {
  int type; /**< JREAL */
  /* \cond */
  char _padding[4];
  /* \endcond */
  double value; /**< 64 bit double precision floating point */
};

/**
 * @brief String data type
 */
struct jstring {
  int type; /**< JSTRING */
  /* \cond */
  char _padding[4];
  /* \endcond */
  char *value; /**< 8 bit characters */
};

/**
 * @brief Array data type
 * @details
 * The order of the jvalue objects in the array is significant.
 */
struct jarray {
  int type; /**< JARRAY */
  /* \cond */
  char _padding[4];
  /* \endcond */
#if 0
  unsigned int size; /**< a number of the jvalue objects in the array */
  jvalue **value; /** an array that contains the jvalue objects */
#endif
  jarraylist *list;
};

/**
 * @brief Key/Value data structure
 * @details
 * This is a key/value object and maintained by
 * jobject as an element.
 */
struct jentry {
  char *key; /**< a key string */
  jvalue *value; /**< a jvalue object */
};

/**
 * @brief List of key/value objects data type
 * @details
 * This maintains a list of jentry objects in the hashtable.
 */
struct jobject {
  int type; /**< JOBJECT */
  /* \cond */
  char _padding[4];
  /* \endcond */
  jhashtable *table; /**< hashtable */
};

/**
 * @brief a function pointer to print a user defined object
 *
 * This function will be executed during writing the user defined
 * objects into JSON.
 *
 * @param data the user defined object
 * @param buf the destination buffer to be copied and should be terminated with null
 * @param size the size of the destination buffer
 * @return the number of characters written in the destination buffer
 * without counting the terminating null character.
 */
typedef unsigned int (*juser_write) (void *data, char *buf, unsigned int size);

/**
 * @brief a function pointer to free a user defined object
 *
 * This function will be executed during destroying the object which
 * contains the user defined objects.  When this is not provided, the
 * user defined object will not destroyed.
 *
 * @param data the user defined object
 */
typedef void (*juser_destroy) (void *data);

/**
 * @brief User defined data type
 */
struct juser {
  int type; /**< JUSER */
  /* \cond */
  char _padding[4];
  /* \endcond */
  void *value; /**< an user defined data object */
  juser_write write; /**< a function pointer to print this in JSON format */
  juser_destroy destroy;  /**< a function pointer to destroy this object */
};

/**
 * @brief jvalue union data structure
 * @details
 * jvalue represents any of data types in the union member.  The
 * 'type' member indicates which data type currently represented.
 */
union jvalue {
  int     type;         /**< type identifier */
  jnull   _null;        /**< null data object */
  jbool   _bool;        /**< boolean data object */
  jint    _integer;     /**< 32 bit integer object */
  jint64  _integer64;   /**< 64 bit integer object */
  jreal   _real;        /**< 64 bit double precision floating point object */
  jstring _string;      /**< 8 bit character string object */
  jarray  _array;       /**< array object */
  jobject _object;      /**< key/value object */
  juser   _user;        /**< user defined object */
};

/*@}*/

/** @addtogroup Functions */
/*@{*/

/**
 * @def MAX_KEY_STRING_SIZE
 * Max size for a key string.
 */
#define MAX_KEY_STRING_SIZE     (1 << 16)

/**
 * @def MAX_VALUE_STRING_SIZE
 * Max size for a value string.
 */
#define MAX_VALUE_STRING_SIZE   (1 << 26)

/******************************************************************************/
/* primitive creators */
/******************************************************************************/

/**
 * @brief Creates a jint object and returns it as a jvalue pointer.
 * @param number a 32 bit integer
 * @return a jvalue pointer to the jint object, or null for not enough memory
 */
WINLIB_API jvalue *jint_create(int number);

/**
 * @brief Creates a jint64 object and returns it as a jvalue pointer.
 * @param number a 64 bit integer
 * @return a jvalue pointer to the jint64 object, or null for not enough memory
 */
WINLIB_API jvalue *jint64_create(long long int number);

/**
 * @brief Creates a jreal object and returns it as a jvalue pointer.
 * @param number a 64 bit double precision floating point.
 * @return a jvalue pointer to the jreal object, or null for not enough memory
 */
WINLIB_API jvalue *jreal_create(double number);

/**
 * @brief Creates a jstring object and returns it as a jvalue pointer.
 * @param str a string
 * @param error an error status
 *  - 0 for success
 *  - 5 for not enough memory
 *  - 6 for too long string to store
 * @return a jvalue pointer to the jstring object, or null for not enough memory
 */
WINLIB_API jvalue *jstring_create(const char* str, int *error);

/**
 * @brief Creates a jbool object and returns it as a jvalue pointer.
 * @param bvalue a boolean value, 1 for true, 0 for false.
 * @return a jvalue pointer to the jbool object, or null for not enough memory
 */
WINLIB_API jvalue *jbool_create(int bvalue);

/**
 * @brief Creates a jnull object and returns it as a jvalue pointer.
 * @return a jvalue pointer to the jnull object, or null for not enough memory
 */
WINLIB_API jvalue *jnull_create(void);

/**
 * @brief Creates a juser object and returns it as a jvalue pointer.
 * @details
 * The user defined object is stored as a void object.  When it is
 * written to a JSON string, the specified juser_write function is
 * invoked to print a JSON representation of the user defined object.
 * @param data the user defined object
 * @param write a function pointer to write this object into JSON
 * @param destroy a function pointer to destroy this object
 * @return a jvalue pointer to the juser object, or null for not enough memory
 * @sa juser_write
 */
WINLIB_API jvalue *juser_create(void *data, juser_write write, juser_destroy destroy);

/******************************************************************************/
/* jvalue */
/******************************************************************************/

/**
 * @brief Converts the JSON string into a jvalue object.
 * @details
 * The supported encoding is UTF-8 only.
 * The returned object
 * must be destroyed by jvalue_destroy().
 * @todo allows to set a max size to read, and returns an error if failed to read
 * @param json the JSON string
 * @param size the number of the characters to be read
 * @return a pointer to the jvalue object
 * @sa jvalue_destroy
 */
WINLIB_API jvalue *jvalue_read(const char *json, unsigned int *size);

/**
 * @brief Converts the jvalue object into a JSON string.
 * @details
 * The returned string must be freed by free().
 * @todo allows to set a max size to write
 * @param value the jvalue object
 * @param size the number of the characters to be written
 * @return a string in JSON format
 */
WINLIB_API char *jvalue_write(const jvalue *value, unsigned int *size);

/**
 * @brief Converts the jvalue object into a JSON string with indentation
 * @details
 * For indentation, tabs are used.  Internally, the jvalue is written
 * to a JSON string by jvalue_write(), and then the output is parsed for
 * indentation.  The performance needs to be improved.
 * @todo allows to set a max size to write and a string for indentation
 * @param value a pointer to the jvalue object
 * @param size the number of the characters to be written
 * @return a string in JSON format with indentation
 */
WINLIB_API char *jvalue_write_pretty(const jvalue *value, unsigned int *size);

/**
 * @brief Destroys the jvalue object.
 * @details
 * This destroys the all objects recursively in the jvalue object.
 * @param value a pointer to the jvalue object
 */
WINLIB_API void jvalue_destroy(jvalue *value);

/**
 * @brief Clones the jvalue object.
 * @details
 * This clones the all objects recursively in the jvalue object.
 * @param value a pointer to the jvalue object
 * @return a pointer to the new jvalue object or null if not enough memory
 */
WINLIB_API jvalue *jvalue_clone(const jvalue *value);

/**
 * @brief Compares two json values semantically
 * @param value1 a pointer to the jvalue object
 * @param value2 a pointer to the jvalue object
 * @todo returns an error to indicate a location of the difference
 * @return 0 for same, -1 for not same
 */
WINLIB_API int jvalue_compare(const jvalue *value1, const jvalue *value2);


/******************************************************************************/
/* jobject */
/******************************************************************************/

/**
 * @brief Creates a jobject object and returns it as a jvalue pointer.
 * @details
 * jobject implements a hashtable.  This hashtable does not allow a
 * null value of both key and value.  A key must be a string in UTF-8.
 * The number of the tables in the hashtable will grow when it exceeds 3/4
 * of the current size.
 * @return a jvalue pointer to the jvalue object, or null for not enough memory
 * @sa jvalue_destroy
 */
WINLIB_API jvalue *jobject_create(void);

/**
 * @brief Returns 1 if this object is empty, returns 0 if this object has the values.
 * @param object the jobject object casting to jvalue
 * @return 1 for empty, 0 for not empty.
 */
WINLIB_API int jobject_isempty(const jvalue *object);

/**
 * @brief Returns the number of the keys in this jobject.
 * @param object the jobject object casting to jvalue
 * @return the number of the keys in the jobject
 */
WINLIB_API int jobject_size(const jvalue *object);

/**
 * @brief Returns an array view of the values in this jobject.
 * @details The returned array is dynamically allocated for a
 * container of the values and needs to be freed.  The values
 * themselves in the array share the same memories in the hashtable so
 * they should not be freed.
 * @param object the jobject object casting to jvalue
 * @param size the number of the values in the array to be returned
 * @return the array of the jentry data objects
 */
WINLIB_API jentry **jobject_entries(const jvalue *object, unsigned int *size);

/**
 * @brief Returns void
 * @details This just free the memory allocated in jobject_entries
 * @param pppentries pointer to address stored return value of jobject_entries
 *        it must be stored NULL or return value from jobject_entries
 * @return will be set *pppentries = NULL
 */
WINLIB_API void jentries_destroy(jentry*** pppentries);

/**
 * @brief Removes the entry value for the key from the jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @return
 * an error status
 * - 0 for success
 * - 1 for value not found
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 */
WINLIB_API int jobject_remove(jvalue *object, const char* key);

/**
 * @brief Maps the specified key to the specified value in this jobject.
 * @details  Neither the key nor the value can be null.
 * If the key is already used, the old value for the key
 * is replaced with the new value.  The old value is destroyed by jvalue_destroy().
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param value a pointer to the jvalue object
 * @param error an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 * @return 0 for success when the key is not found, or the old value
 * when the key is found and the value is replaced.
 */
WINLIB_API jvalue *jobject_put(jvalue *object, const char* key, jvalue *value, int *error);

/**
 * @brief Maps the specified key to the specified null value in this jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_null(jvalue *object, const char* key);

/**
 * @brief Maps the specified key to the specified boolean value in this jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param bvalue a boolean value, 1 for true, 0 for false
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_bool(jvalue *object, const char* key, int bvalue);

/**
 * @brief Maps the specified key to the specified 32bit integer value in this jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param number a 32 bit integer
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_int(jvalue *object, const char* key, int number);

/**
 * @brief Maps the specified key to the specified 64bit integer value in this jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param number a 64 bit integer
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_int64(jvalue *object, const char* key, long long int number);

/**
 * @brief Maps the specified key to the specified 64bit double precision floating
 * value in this jobject.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param number a 64 bit double precision floating point
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_real(jvalue *object, const char* key, double number);

/**
 * @brief Maps the specified key to the specified string in this jobject.
 * @details
 * This string is duplicated and stored, so it can be freed right
 * after this function returned.  Also, this string will be treated as a
 * UTF-8 string when this is written to a JSON string.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param string a string
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_string(jvalue *object, const char* key, const char *string);

/**
 * @brief Maps the specified key to the specified jarray in this jobject.
 * @details
 * A null array value is not allowed.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param value a pointer to the jvalue object which is cast-ed from
 * jarray.  This will be destroyed when the parent object is destroyed.
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_array(jvalue *object, const char* key, jvalue *value);

/**
 * @brief Maps the specified key to the specified jobject in this jobject.
 * @details
 * A null value is not allowed.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param value a pointer to the jvalue object which is cast-ed from
 * jobject.  This will be destroyed when this object is destroyed.
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jobject_put_object(jvalue *object, const char* key, jvalue *value);

/**
 * @brief Maps the specified key to the specified user defined object in this jobject.
 * @details
 * The user defined object is stored as a void object.  When it is
 * written to a JSON string, the specified juser_write function is
 * invoked to print a JSON representation of the user defined object.
 * A null data will not be allowed.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param data a pointer to the user defined object
 * @param write a function pointer to write this object into JSON
 * @param destroy a function pointer to destroy this object
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 * @sa juser_write
 */
WINLIB_API int jobject_put_user(jvalue *object, const char* key, void *data, juser_write write, juser_destroy destroy);

/**
 * @brief Returns the jvalue object mapped for the specified key.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @return a pointer to the jvalue object to which the specified key is mapped, or
 * null if no mapping for the key is found
 */
WINLIB_API jvalue *jobject_get(const jvalue *object, const char* key);

/**
 * @brief Returns 0 if the null value is mapped with the specified
 * key, otherwise returns an error status.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 */
WINLIB_API int jobject_get_null(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the boolean value to which the specified key is mapped.
 * @param object the jobject object that is cast to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return the boolean value, 1 for true, 0 for false
 */
WINLIB_API int jobject_get_bool(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the 32 bit integer to which the specified key is mapped.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return the 32 bit integer
 */
WINLIB_API int jobject_get_int(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the 64 bit integer to which the specified key is mapped.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return the 64 bit integer
 */
WINLIB_API long long int jobject_get_int64(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the 64 bit double precision floating point to which the specified key is mapped.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return the 64 bit double precision floating point
 */
WINLIB_API double jobject_get_real(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the string value to which the specified key is mapped, or
 * null if this map contains no mapping for the key.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return the string
 */
WINLIB_API const char *jobject_get_string(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the jarray value to which the specified key is mapped, or
 * null if this map contains no mapping for the key.
 * @param object the jobject object casting to jvalue
 * @param key the key string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return a pointer to the jvalue object which can cast to jarray,
 * or null if this map contains no mapping for the key
 */
WINLIB_API jarray *jobject_get_array(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the jobject value to which the specified key is
 * mapped, or null if this map contains no mapping for the key.
 * @param object the jobject object casting to jvalue
 * @param key the string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return a pointer to the jvalue object which can cast to jobject,
 * or null if this map contains no mapping for the key
 */
WINLIB_API jobject *jobject_get_object(const jvalue *object, const char* key, int *error);

/**
 * @brief Returns the user defined data to which the specified key is
 * mapped, or null if this map contains no mapping for the key.
 * @param object the jobject object casting to jvalue
 * @param key the string
 * @param error an error status
 *  - 0 for success
 *  - 1 for value not found in the object
 *  - 2 for null parameter
 *  - 3 for wrong data type in parameter
 *  - 4 for wrong value type to inquiry
 * @return a pointer to the user defined data or null if not found
 */
WINLIB_API void *jobject_get_user(const jvalue *object, const char* key, int *error);

/******************************************************************************/
/* jarray */
/******************************************************************************/

/**
 * @brief Creates a jarray object and return it as a jvalue pointer.
 * @details
 * This must be destroyed with jvalue_destroy().
 * @return a pointer to the jarray object, or null for not enough memory
 */
WINLIB_API jvalue *jarray_create(void);

/**
 * @brief Returns the number of the objects in the array.
 * @param array the array object casting to jvalue
 * @return the number of the objects in the array
 */
WINLIB_API unsigned int jarray_size(const jvalue *array);

/**
 * @brief Adds the jvalue object in the end of the array.
 * @param array the array object casting to jvalue
 * @param value a pointer to the jvalue object
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put(jvalue *array, jvalue *value);

/**
 * @brief Returns the position of the the jvalue object in the array.
 * @param array the array object casting to jvalue
 * @param index the position in the array
 * @param error an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 * @return the jvalue object
 */
WINLIB_API jvalue *jarray_get(const jvalue *array, unsigned int index, int *error);

/**
 * @brief Inserts the the jvalue object into the position of the array.
 * @param array the array object casting to jvalue
 * @param index the position in the array
 * @param value the jvalue object
 * @return
 * an error status
 * - 5 for not enough memory
 */
WINLIB_API int jarray_insert(const jvalue *array, unsigned int index, jvalue *value);

/**
 * @brief Removes the position of the the jvalue object from the array.
 * @param array the array object casting to jvalue
 * @param index the position in the array
 * @param error an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 7 for out of index
 * @return the jvalue object which is removed
 */
WINLIB_API jvalue *jarray_remove(const jvalue *array, unsigned int index, int *error);

/**
 * @brief Adds the 32 bit integer in the end of the array.
 * @param array the array object casting to jvalue
 * @param number a 32 bit integer
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_int(jvalue *array, int number);

/**
 * @brief Adds the 64 bit integer in the end of the array.
 * @param array the array object casting to jvalue
 * @param number a 64 bit integer
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_int64(jvalue *array, long long int number);

/**
 * @brief Adds the string in the end of the array.
 * @details
 * This string is duplicated and stored, so it can be freed right
 * after this function returned.  Also, this string will be treated as a
 * UTF-8 string when this is written to a JSON string.
 * @param array the array object casting to jvalue
 * @param string a string
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_string(jvalue *array, const char *string);

/**
 * @brief Adds the boolean value in the end of the array.
 * @param array the array object casting to jvalue
 * @param bvalue a boolean value, 1 for true, 0 for false
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_bool(jvalue *array, int bvalue);

/**
 * @brief Adds the 64 bit double precision floating point in the end of the array.
 * @param array the array object casting to jvalue
 * @param number a 64 bit double precision floating point
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_real(jvalue *array, double number);

/**
 * @brief Adds the null value in the end of the array.
 * @param array the array object casting to jvalue
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_null(jvalue *array);

/**
 * @brief Adds the jarray object in the end of the array.
 * @details
 * A null array value is not allowed.
 * @param array the array object casting to jvalue
 * @param value a pointer to the jvalue object which is cast-ed from jarray
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_array(jvalue *array, jvalue *value);

/**
 * @brief Adds the jobject object in the end of the array.
 * @details
 * A null object value is not allowed.
 * @param array the array object casting to jvalue
 * @param value a pointer to the jvalue object which is cast-ed from jobject
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_object(jvalue *array, jvalue *value);

/**
 * @brief Adds the user defined object in the end of the array.
 * @details
 * The user defined object is stored as a void object.  When it is
 * written to a JSON string, the specified juser_write function is
 * invoked to print a JSON representation of the user defined object.
 * A null data will not be allowed.
 * @param array the array object casting to jvalue
 * @param data a pointer to the user defined object
 * @param write a function pointer to write this object into JSON
 * @param destroy a function pointer to destroy this object
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 3 for wrong data type in parameter
 * - 5 for not enough memory
 * @sa juser_write
 */
WINLIB_API int jarray_put_user(jvalue *array, void *data, juser_write write, juser_destroy destroy);

/**
 * @brief Adds an array of 32 bit integers
 * @param array the array object casting to jvalue
 * @param numbers the array of the 32 bit integers
 * @param size the number of the 32 bit integers in the array
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_int_list(jvalue *array, int numbers[], unsigned int size);

/**
 * @brief Adds an array of boolean values
 * @param array the array object casting to jvalue
 * @param values the number of the boolean values in the array
 * @param size the number of the boolean values in the array
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_bool_list(jvalue *array, int values[], unsigned int size);

/**
 * @brief Adds an array of strings
 * @param array the array object casting to jvalue
 * @param strs the array of the strings
 * @param size the number of the strings in the array
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_string_list(jvalue *array, const char *strs[], unsigned int size);

/**
 * @brief Adds an array of jvalue objects
 * @param array the array object casting to jvalue
 * @param values the array of the jvalue objects
 * @param size the number of the jvalue objects in the array
 * @return
 * an error status
 * - 0 for success
 * - 2 for null parameters
 * - 5 for not enough memory
 */
WINLIB_API int jarray_put_jvalue_list(jvalue *array, jvalue *values[], unsigned int size);

/*@}*/

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif
