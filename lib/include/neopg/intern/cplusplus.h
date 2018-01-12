// Language support
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

namespace NeoPG {

// Allow byte literals such as 0xff_b.
constexpr std::uint8_t operator"" _b(unsigned long long v) {
  return static_cast<std::uint8_t>(v);
}

}  // namespace NeoPG
