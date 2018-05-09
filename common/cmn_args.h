#ifndef __CMN_ARGS_H_1349D5A635FA927582A5A41017424E71__
#define __CMN_ARGS_H_1349D5A635FA927582A5A41017424E71__

#include <cmn_err.h>

#if defined(_WIN32) || defined(_WIN64)
/* this is the windows compiler */
#include <win_args.h>


#elif defined(__GNUC__)
/* this is for the unix gcc*/
#include <ux_args.h>

#else
#error "not supported comilers"
#endif


#endif /* __CMN_ARGS_H_1349D5A635FA927582A5A41017424E71__ */
