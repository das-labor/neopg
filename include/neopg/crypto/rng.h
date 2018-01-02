/* Random numbers
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <botan/rng.h>

#include <neopg/common.h>

namespace NeoPG {
namespace Crypto {

NEOPG_DLL Botan::RandomNumberGenerator* rng(void);

}  // Namespace CLI
}  // Namespace NeoPG
