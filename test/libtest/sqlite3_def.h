#ifndef __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__
#define __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


typedef struct sqlite3 sqlite3;

#define SQLITE_OK           0   /* Successful result */

int (*sqlite3_open_v2_func_t)(const char *filename,   /* Database filename (UTF-8) */sqlite3 **ppDb,         /* OUT: SQLite db handle */int flags,              /* Flags */const char *zVfs        /* Name of VFS module to use */);
int (*sqlite3_exec_func_t)(sqlite3* db,                                  /* An open database */const char *sql,                           /* SQL to be evaluated */int (*callback)(void*,int,char**,char**),  /* Callback function */void *,                                    /* 1st argument to callback */char **errmsg                              /* Error msg written here */);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __SQLITE3_DEF_H_20B19F60B670B0C53E7AC8B0700B5A9A__ */
