/* Time functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_UTILS_TIME_H__
#define NEOPG_UTILS_TIME_H__

#include <neopg/common.h>
#include <time.h>

namespace NeoPG {

/**
   A replacement for timegm.
*/
time_t NEOPG_DLL timegm(struct tm *tm);

}  // namespace NeoPG

#endif
