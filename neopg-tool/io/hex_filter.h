// Botan hex filter
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for hex input format.

#pragma once

#include <botan/filter.h>

namespace NeoPG {

/// Represent a hex input filter.
class HexFilter : public Botan::Filter {};

}  // namespace NeoPG
