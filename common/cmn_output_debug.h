#ifndef __CMN_OUTPUT_DEBUG_H_38C17CBEA5D5F7928DB6D77D857F74BA__
#define __CMN_OUTPUT_DEBUG_H_38C17CBEA5D5F7928DB6D77D857F74BA__

#if defined(_WIN32) || defined(_WIN64)
/* this is the windows compiler */
#include <win_output_debug.h>


#elif defined(__GNUC__)
/* this is for the unix gcc*/
#include <ux_output_debug.h>

#else
#error "not supported comilers"
#endif

#endif /* __CMN_OUTPUT_DEBUG_H_38C17CBEA5D5F7928DB6D77D857F74BA__ */
