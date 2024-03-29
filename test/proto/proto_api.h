#ifndef __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__
#define __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#include <win_types.h>

#pragma pack(push)
#pragma pack(1)
typedef struct __pipe_hdr_t {
    uint32_t m_cmd;
    uint32_t m_datalen;
} pipe_hdr_t, *ppipe_hdr_t;
#pragma pack(pop)


#define   EXECUTE_COMMAND                    0x1321
#define   NETSHARE_MOUNT                     0x1322
#define   CHG_USER_PASS                      0x1323
#define   WTS_DETACH_RUN                     0x1324
#define   PROCESS_NUM_CMD                    0x1325
#define   ADDPRN_CMD                         0x1326
#define   DELPRN_CMD                         0x1327
#define   SAVEPRN_CMD                        0x1328
#define   RESTOREPRN_CMD                     0x1329
#define   BACK_CMD_RUN                       0x132a
#define   MAP_MEM_CMD                        0x132b
#define   UNMAP_MEM_CMD                      0x132c


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__ */
