#ifndef __CMN_FILEOP_H_895CBF6C498E8416D45DE184C681702D__
#define __CMN_FILEOP_H_895CBF6C498E8416D45DE184C681702D__


#if defined(_WIN32) || defined(_WIN64)
/* this is the windows compiler */
#include <win_fileop.h>


#elif defined(__GNUC__)
/* this is for the unix gcc*/
#include <ux_fileop.h>

#else
#error "not supported comilers"
#endif


#endif /* __CMN_FILEOP_H_895CBF6C498E8416D45DE184C681702D__ */
