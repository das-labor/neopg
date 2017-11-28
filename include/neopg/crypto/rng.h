/* Random numbers
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <botan/rng.h>

namespace NeoPG {
namespace Crypto {

Botan::RandomNumberGenerator* rng(void);

}  // Namespace CLI
}  // Namespace NeoPG
