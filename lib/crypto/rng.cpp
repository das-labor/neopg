/* Random numbers
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>
#include <neopg/crypto/rng.h>

namespace NeoPG {
namespace Crypto {

thread_local Botan::RandomNumberGenerator* rng{new Botan::AutoSeeded_RNG};

}  // Namespace CLI
}  // Namespace NeoPG
