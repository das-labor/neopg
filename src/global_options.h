// global_options.h
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <iostream>

#include <CLI11.hpp>
#include <rang.hpp>

namespace rang {
std::istream& operator>>(std::istream& in, rang::control& when) {
  std::string label;
  in >> label;
  if (label == "always")
    when = rang::control::Force;
  else if (label == "never")
    when = rang::control::Off;
  else if (label == "auto")
    when = rang::control::Auto;
  else {
    // We are not pushing back what we couldn't parse.  Seems to be OK.
    in.setstate(std::ios_base::failbit);
  }
  return in;
}

std::ostream& operator<<(std::ostream& in, const rang::control& when) {
  switch (when) {
    case rang::control::Force:
      return in << "always";
    case rang::control::Off:
      return in << "never";
    default:
      return in << "auto";
  }
}
}  // namespace rang

class GlobalOptions {
 public:
  rang::control color{rang::control::Auto};
};
