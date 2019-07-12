#ifndef __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__
#define __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#include <win_types.h>

#pragma pack(push)
#pragma pack(1)
typedef struct __pipe_hdr_t {
    uint32_t m_datalen;
    uint32_t m_cmd;
} pipe_hdr_t, *ppipe_hdr_t;
#pragma pack(pop)


#define   EXECUTE_COMMAND                    0x1321


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __PROTO_API_H_0C331E7299A6752082D1A1420A7F6EA9__ */
