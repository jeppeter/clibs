#ifndef __CMN_STROP_H_7C6FF4D5EDC37E01A8BCA0AEAD4DEBAD__
#define __CMN_STROP_H_7C6FF4D5EDC37E01A8BCA0AEAD4DEBAD__

#include <cmn_err.h>

#if defined(_WIN32) || defined(_WIN64)
/* this is the windows compiler */
#include <win_strop.h>


#elif defined(__GNUC__)
/* this is for the unix gcc*/
#include <ux_strop.h>

#else
#error "not supported comilers"
#endif


#endif /* __CMN_STROP_H_7C6FF4D5EDC37E01A8BCA0AEAD4DEBAD__ */
