/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <botan/hash.h>
#include <botan/hex.h>
#include <neopg/cli/hash_command.h>

namespace NeoPG {
namespace CLI {

void ListHashCommand::run() {
  const std::string group = "Write packet";
  std::cout << "Any Botan-compatible algorithm specifier can be used:\n\n";
#if defined(BOTAN_HAS_SHA1)
  std::cout << "SHA-160, SHA-1, SHA1\n";
#endif

#if defined(BOTAN_HAS_SHA2_32)
  std::cout << "SHA-224, SHA-256\n";
#endif

#if defined(BOTAN_HAS_SHA2_64)
  std::cout << "SHA-384, SHA-512, SHA-512-256\n";
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
  std::cout << "RIPEMD-160\n";
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
  std::cout << "Whirlpool\n";
#endif

#if defined(BOTAN_HAS_MD5)
  std::cout << "MD5\n";
#endif

#if defined(BOTAN_HAS_MD4)
  std::cout << "MD4\n";
#endif

#if defined(BOTAN_HAS_GOST_34_11)
  std::cout << "GOST-R-34.11-94, GOST-34.11\n";
#endif

#if defined(BOTAN_HAS_ADLER32)
  std::cout << "Adler32\n";
#endif

#if defined(BOTAN_HAS_CRC24)
  std::cout << "CRC24\n";
#endif

#if defined(BOTAN_HAS_CRC32)
  std::cout << "CRC32\n";
#endif

#if defined(BOTAN_HAS_TIGER)
  std::cout << "Tiger(len, passes) where len is 16, 20 or 24 and passes is at "
               "least 4\n";
#endif

#if defined(BOTAN_HAS_SKEIN_512)
  std::cout << "Skein-512(bits) where bits is at most 512 and divisible by 8\n";
#endif

#if defined(BOTAN_HAS_BLAKE2B)
  std::cout << "Blake2b(bits) where bits is at most 512 and divisible by 8\n";
#endif

#if defined(BOTAN_HAS_KECCAK)
  std::cout << "Keccak-1600(bits) where bits is 224, 256, 384 or 512\n";
#endif

#if defined(BOTAN_HAS_SHA3)
  std::cout << "SHA-3(bits) where bits is 224, 256, 384 or 512\n";
#endif

#if defined(BOTAN_HAS_SHAKE)
  std::cout
      << "SHAKE-128(bits), SHAKE-256(bits) where bits is divisible by 8\n";
#endif

#if defined(BOTAN_HAS_STREEBOG)
  std::cout << "Streebog-256, Streebog-512\n";
#endif

#if defined(BOTAN_HAS_SM3)
  std::cout << "SM3\n";
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
  std::cout << "Whirlpool\n";
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
  std::cout << "Parallel(hashes, ...)\n";
#endif

#if defined(BOTAN_HAS_COMB4P)
  std::cout << "Comb4P(hash1, hash2) with two distinct hashes\n";
#endif
}

void HashCommand::run() {
  if (!m_cmd.get_subcommands().empty()) return;

  std::vector<uint8_t> buf(2048);

#ifdef __WIN32__
  _setmode(_fileno(stdin), _O_BINARY);
#endif

  std::unique_ptr<Botan::HashFunction> hash(
      Botan::HashFunction::create_or_throw(m_algo));
  while (std::cin.good()) {
    std::cin.read(reinterpret_cast<char*>(buf.data()), buf.size());
    hash->update(buf.data(), std::cin.gcount());
  }
  while (!std::cin.eof())
    ;
  std::vector<uint8_t> result = hash->final_stdvec();
  if (m_raw)
    std::cout.write((char*)result.data(), result.size());
  else
    std::cout << Botan::hex_encode(result, false) << "\n";
}

}  // Namespace CLI
}  // Namespace NeoPG
