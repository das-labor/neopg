// PEGTL support
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

// Protect our use of PEGTL from other library users.
#define TAO_PEGTL_NAMESPACE neopg_pegtl
#include <tao/pegtl.hpp>

namespace pegtl = tao::TAO_PEGTL_NAMESPACE;
