// PEGTL support
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser_error.h>
#include <neopg/parser_input.h>
#include <neopg/parser_position.h>

#include <string>
#include <vector>

// Protect our use of PEGTL from other library users.
#define TAO_PEGTL_NAMESPACE neopg_pegtl
#include <tao/pegtl.hpp>

namespace pegtl = tao::TAO_PEGTL_NAMESPACE;

namespace NeoPG {

class ParserInput::Impl {
 public:
  pegtl::memory_input<> m_input;
  Impl(const char* data, size_t length, const std::string& source)
      : m_input{data, length, source} {}
};

class ParserInput::Mark::Impl {
 public:
  pegtl::internal::marker<pegtl::internal::iterator,
                          pegtl::rewind_mode::REQUIRED>
      m_mark;
  Impl(ParserInput& in)
      : m_mark{in.m_impl->m_input.mark<pegtl::rewind_mode::REQUIRED>()} {}
};

template <typename Input>
ParserError parser_error(const std::string& msg, const Input& in) {
  const pegtl::position in_pos = in.position();
  ParserPosition pos(in_pos.source, in_pos.byte);
  return ParserError(msg, pos);
}

}  // namespace NeoPG

namespace tao {
namespace TAO_PEGTL_NAMESPACE {
// Custom rule to match as many octets as are indicated by length.
template <uint32_t max_length>
struct rep_max_any {
  using analyze_t = analysis::generic<analysis::rule_type::OPT>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input,
            typename... States>
  static bool match(Input& in, States&&... st) {
    uint32_t length = in.size(max_length);
    if (length > max_length) length = max_length;
    in.bump(length);
    return true;
  }
};

// With C++17, we can derive the parameter T this way:
// template <auto value>
// struct bind {};
// template <typename T, std::vector<uint8_t> T::*Field>
// struct bind<Field> {
// template <typename Input>
// static void apply(const Input& in, T& pkt) {

template <typename T, typename R, R T::*Field>
struct bind {};

template <typename T, std::vector<uint8_t> T::*Field>
struct bind<T, std::vector<uint8_t>, Field> {
  template <typename Input>
  static void apply(const Input& in, T& pkt) {
    auto src = in.begin();
    auto ptr = reinterpret_cast<const uint8_t*>(src);
    static_assert(sizeof(*src) == sizeof(*ptr), "can't do pointer arithmetic");
    (pkt.*Field).assign(ptr, ptr + in.size());
  }
};

template <typename T, std::string T::*Field>
struct bind<T, std::string, Field> {
  template <typename Input>
  static void apply(const Input& in, T& pkt) {
    (pkt.*Field).assign(in.begin(), in.end());
  }
};

}  // namespace TAO_PEGTL_NAMESPACE
}  // namespace tao
