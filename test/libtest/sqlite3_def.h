#ifndef __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__
#define __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__


#define SQLITE_OPEN_READONLY         0x00000001  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_READWRITE        0x00000002  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_CREATE           0x00000004  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_DELETEONCLOSE    0x00000008  /* VFS only */
#define SQLITE_OPEN_EXCLUSIVE        0x00000010  /* VFS only */
#define SQLITE_OPEN_AUTOPROXY        0x00000020  /* VFS only */
#define SQLITE_OPEN_URI              0x00000040  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_MEMORY           0x00000080  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_MAIN_DB          0x00000100  /* VFS only */
#define SQLITE_OPEN_TEMP_DB          0x00000200  /* VFS only */
#define SQLITE_OPEN_TRANSIENT_DB     0x00000400  /* VFS only */
#define SQLITE_OPEN_MAIN_JOURNAL     0x00000800  /* VFS only */
#define SQLITE_OPEN_TEMP_JOURNAL     0x00001000  /* VFS only */
#define SQLITE_OPEN_SUBJOURNAL       0x00002000  /* VFS only */
#define SQLITE_OPEN_SUPER_JOURNAL    0x00004000  /* VFS only */
#define SQLITE_OPEN_NOMUTEX          0x00008000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_FULLMUTEX        0x00010000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_SHAREDCACHE      0x00020000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_PRIVATECACHE     0x00040000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_WAL              0x00080000  /* VFS only */
#define SQLITE_OPEN_NOFOLLOW         0x01000000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_EXRESCODE        0x02000000  /* Extended result codes */


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


typedef struct sqlite3 sqlite3;

#define SQLITE_OK           0   /* Successful result */

typedef int (*sqlite3_open_v2_func_t)(const char *filename,   /* Database filename (UTF-8) */sqlite3 **ppDb,         /* OUT: SQLite db handle */int flags,              /* Flags */const char *zVfs        /* Name of VFS module to use */);
typedef int (*sqlite3_exec_func_t)(sqlite3* db,                                  /* An open database */const char *sql,                           /* SQL to be evaluated */int (*callback)(void*,int,char**,char**),  /* Callback function */void *,                                    /* 1st argument to callback */char **errmsg                              /* Error msg written here */);
typedef int (*sqlite3_close_func_t)(sqlite3*);
typedef void (*sqlite3_free_func_t)(char*);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__ */
