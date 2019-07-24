#include <win_types.h>
#include <win_map.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

typedef struct __map_buffer_t {
    HANDLE m_hfile;
    HANDLE m_maphd;
    void* m_mapbuf;
    uint64_t m_size;
    char* m_name;
} map_buffer_t, *pmap_buffer_t;


void __free_map_buffer(pmap_buffer_t *ppmap)
{
    BOOL bret;
    int ret;
    if (ppmap && *ppmap) {
        pmap_buffer_t pmap = *ppmap;
        if (pmap->m_mapbuf) {
            bret = UnmapViewOfFile(pmap->m_mapbuf);
            if (!bret) {
                GETERRNO(ret);
                ERROR_INFO("unmap [%s] error[%d]", pmap->m_name ? pmap->m_name : "NULL", ret);
            }
            pmap->m_mapbuf = NULL;
        }

        if (pmap->m_maphd != NULL) {
            CloseHandle(pmap->m_maphd);
            pmap->m_maphd = NULL;
        }
        pmap->m_size = 0;

        if (pmap->m_hfile != NULL) {
            CloseHandle(pmap->m_hfile);
            pmap->m_hfile = NULL;
        }

        if (pmap->m_name) {
            free(pmap->m_name);
        }
        pmap->m_name = NULL;
        free(pmap);
        *ppmap = NULL;
    }
}

int __get_map_access(int flag, DWORD *prwflag)
{
    DWORD rwflag = 0;
    int ret;

    if ((flag & MAP_FILE_FLAGS) != flag) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("flag [0x%x] not valid", flag);
        goto fail;
    }

    if (flag & MAP_FILE_READ) {
        rwflag |= FILE_MAP_READ;
    }

    if (flag  & MAP_FILE_EXEC) {
        rwflag |= FILE_MAP_EXECUTE;
    }

    if (flag & MAP_FILE_WRITE) {
        rwflag |= FILE_MAP_WRITE;
    }

    if (prwflag) {
        *prwflag = rwflag;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_map_prot(int flag, DWORD *pprot)
{
    DWORD prot = 0;
    int ret;
    switch ((flag & MAP_FILE_FLAGS)) {
    case (MAP_FILE_READ|MAP_FILE_WRITE):
    case (MAP_FILE_WRITE):
        prot |= PAGE_READWRITE;
        prot |= SEC_COMMIT;
        break;
    case (MAP_FILE_WRITE|MAP_FILE_READ|MAP_FILE_EXEC):
        prot |= PAGE_EXECUTE_READWRITE;
        prot |= SEC_COMMIT;
        break;
    case (MAP_FILE_READ|MAP_FILE_EXEC):
        prot |= PAGE_EXECUTE_READ;
        break;
    case (MAP_FILE_READ):
        prot |= PAGE_READONLY;
        break;
    default:
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("flag [0x%x] not valid", flag);
        goto fail;
    }

    if (pprot) {
        *pprot = prot;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __map_buffer(pmap_buffer_t pmap, int flag, uint64_t size)
{
    DWORD rwflag = 0;
    DWORD prot = 0;
    int ret;

    ret = __get_map_access(flag, &rwflag);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_map_prot(flag, &prot);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pmap->m_mapbuf = MapViewOfFile(INVALID_HANDLE_VALUE, rwflag, 0, (DWORD)((size >> 32) & 0xffffffff ), (DWORD)(size & 0xffffffff));
    if (pmap->m_mapbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("map view [%s] with [%d:0x%x] error[%d]", pmap->m_name, size, size, ret);
        goto fail;
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __map_memory_name(pmap_buffer_t pmap, int flag,int size)
{
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    int ret;
    DWORD prot = 0;
    DWORD rwflag = 0;
    if (pmap->m_name != NULL) {
        ret = AnsiToTchar(pmap->m_name, &ptname, &tnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    ret = __get_map_access(flag, &rwflag);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_map_prot(flag, &prot);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (ptname != NULL) {
        pmap->m_maphd = OpenFileMapping(rwflag, FALSE, ptname);
    }

    if (pmap->m_maphd == NULL) {
        pmap->m_maphd = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, prot, 0, size, ptname);
    }
    if (pmap->m_maphd == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open or create map [%s] error[%d]", pmap->m_name ? pmap->m_name : "NULL", ret);
        goto fail;
    }


    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}

pmap_buffer_t __alloc_map_buffer(char* name)
{
    pmap_buffer_t pmap = NULL;
    int ret;

    pmap = (pmap_buffer_t)malloc(sizeof(*pmap));
    if (pmap == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pmap, 0, sizeof(*pmap));
    if (name != NULL) {
        pmap->m_name = strdup(name);
        if (pmap->m_name == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }


    return pmap;
fail:
    __free_map_buffer(&pmap);
    SETERRNO(ret);
    return NULL;
}

int map_buffer(char* name, int flag, int size, void** ppmap)
{
    pmap_buffer_t pmap = NULL;
    int ret;
    if (ppmap == NULL || *ppmap != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pmap = __alloc_map_buffer(name);
    if (pmap == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __map_memory_name(pmap, flag,size);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __map_buffer(pmap, flag, (uint64_t)size);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pmap->m_size = size;


    *ppmap = pmap;
    return 0;
fail:
    __free_map_buffer(&pmap);
    SETERRNO(ret);
    return ret;
}

int write_buffer(void* pmap1, uint64_t offset, void* pbuf, int size)
{
    int ret;
    pmap_buffer_t pmap = (pmap_buffer_t) pmap1;
    int wsize = size;
    char* pinbuf = NULL;
    if (pmap == NULL || pmap->m_mapbuf == NULL || pbuf == NULL ||
            offset > pmap->m_size) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pinbuf = (char*) pmap->m_mapbuf;
    if ((offset + size) > pmap->m_size) {
        wsize = (int)(pmap->m_size - offset);
    }
    memcpy(&(pinbuf[offset]), pbuf, wsize);
    return wsize;
}


int read_buffer(void* pmap1, uint64_t offset, void* pbuf, int size)
{
    int ret;
    pmap_buffer_t pmap = (pmap_buffer_t) pmap1;
    int rsize = size;
    char* poutbuf = NULL;
    if (pmap == NULL || pmap->m_mapbuf == NULL || pbuf == NULL ||
            offset > pmap->m_size) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    poutbuf = (char*) pmap->m_mapbuf;
    if ((offset + size) > pmap->m_size) {
        rsize = (int)(pmap->m_size - offset);
    }
    memcpy( pbuf, &(poutbuf[offset]), rsize);
    return rsize;
}


void unmap_buffer(void** ppmap)
{
    pmap_buffer_t pmap;
    if (ppmap && *ppmap) {
        pmap = (pmap_buffer_t) * ppmap;
        __free_map_buffer(&pmap);
        *ppmap = NULL;
    }
    return ;
}
