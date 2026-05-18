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


typedef void (*sqlite3_destructor_type)(void*);
#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

typedef long long int sqlite3_int64;

#define SQLITE_OK           0   /* Successful result */
/* beginning-of-error-codes */
#define SQLITE_ERROR        1   /* Generic error */
#define SQLITE_INTERNAL     2   /* Internal logic error in SQLite */
#define SQLITE_PERM         3   /* Access permission denied */
#define SQLITE_ABORT        4   /* Callback routine requested an abort */
#define SQLITE_BUSY         5   /* The database file is locked */
#define SQLITE_LOCKED       6   /* A table in the database is locked */
#define SQLITE_NOMEM        7   /* A malloc() failed */
#define SQLITE_READONLY     8   /* Attempt to write a readonly database */
#define SQLITE_INTERRUPT    9   /* Operation terminated by sqlite3_interrupt()*/
#define SQLITE_IOERR       10   /* Some kind of disk I/O error occurred */
#define SQLITE_CORRUPT     11   /* The database disk image is malformed */
#define SQLITE_NOTFOUND    12   /* Unknown opcode in sqlite3_file_control() */
#define SQLITE_FULL        13   /* Insertion failed because database is full */
#define SQLITE_CANTOPEN    14   /* Unable to open the database file */
#define SQLITE_PROTOCOL    15   /* Database lock protocol error */
#define SQLITE_EMPTY       16   /* Internal use only */
#define SQLITE_SCHEMA      17   /* The database schema changed */
#define SQLITE_TOOBIG      18   /* String or BLOB exceeds size limit */
#define SQLITE_CONSTRAINT  19   /* Abort due to constraint violation */
#define SQLITE_MISMATCH    20   /* Data type mismatch */
#define SQLITE_MISUSE      21   /* Library used incorrectly */
#define SQLITE_NOLFS       22   /* Uses OS features not supported on host */
#define SQLITE_AUTH        23   /* Authorization denied */
#define SQLITE_FORMAT      24   /* Not used */
#define SQLITE_RANGE       25   /* 2nd parameter to sqlite3_bind out of range */
#define SQLITE_NOTADB      26   /* File opened that is not a database file */
#define SQLITE_NOTICE      27   /* Notifications from sqlite3_log() */
#define SQLITE_WARNING     28   /* Warnings from sqlite3_log() */
#define SQLITE_ROW         100  /* sqlite3_step() has another row ready */
#define SQLITE_DONE        101  /* sqlite3_step() has finished executing */
/* end-of-error-codes */

typedef int (*sqlite3_open_v2_func_t)(const char *filename,   /* Database filename (UTF-8) */sqlite3 **ppDb,         /* OUT: SQLite db handle */int flags,              /* Flags */const char *zVfs        /* Name of VFS module to use */);
typedef int (*sqlite3_exec_func_t)(sqlite3* db,                                  /* An open database */const char *sql,                           /* SQL to be evaluated */int (*callback)(void*,int,char**,char**),  /* Callback function */void *,                                    /* 1st argument to callback */char **errmsg                              /* Error msg written here */);
typedef int (*sqlite3_close_func_t)(sqlite3*);
typedef void (*sqlite3_free_func_t)(char*);
typedef int (*sqlite3_prepare_v3_func_t)(sqlite3 *db,            /* Database handle */const char *zSql,       /* SQL statement, UTF-8 encoded */int nByte,              /* Maximum length of zSql in bytes. */unsigned int prepFlags, /* Zero or more SQLITE_PREPARE_ flags */sqlite3_stmt **ppStmt,  /* OUT: Statement handle */const char **pzTail     /* OUT: Pointer to unused portion of zSql */);
typedef int (*sqlite3_bind_blob_func_t)(sqlite3_stmt*, int, const void*, int n, void(*)(void*));
typedef int (*sqlite3_bind_blob64_func_t)(sqlite3_stmt*, int, const void*, int n, void(*)(void*));
typedef int (*sqlite3_bind_double_func_t)(sqlite3_stmt*, int, double);
typedef int (*sqlite3_bind_int_func_t)(sqlite3_stmt*, int, int);
typedef int (*sqlite3_bind_int64_func_t)(sqlite3_stmt*, int, sqlite3_int64);
typedef int (*sqlite3_bind_null_func_t)(sqlite3_stmt*, int);
typedef int (*sqlite3_bind_text_func_t)(sqlite3_stmt*,int,const char*,int,void(*)(void*));

typedef int (*sqlite3_step_func_t)(sqlite3_stmt*);
typedef int (*sqlite3_finalize_func_t)(sqlite3_stmt*);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__ */
