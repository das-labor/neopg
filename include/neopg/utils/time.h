/* Time functions
   Copyright 2017 Marcus Brinkmann

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_TIME_H__
#define NEOPG_TIME_H__

#include <time.h>

#define NEOPG_DLL __attribute__((visibility("default")))

namespace NeoPG {

/**
   A replacement for timegm.
*/
time_t NEOPG_DLL timegm(struct tm *tm);

}  // namespace NeoPG

#endif
