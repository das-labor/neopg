/* OpenPGP functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

// Protect our use of PEGTL from other library users.
#define TAOCPP_PEGTL_NAMESPACE neopg_pegtl

#include <cstdint>
#include <tao/pegtl.hpp>

using namespace tao::neopg_pegtl;

namespace NeoPG {
namespace Parser {
namespace OpenPGP {

struct packet : one<(char)0x80> {};

struct packets : until<eof, packet> {};

struct grammar : packets {};

struct state {
  std::vector<std::string> packets;
};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<packet> {
  template <typename Input>
  static void apply(const Input& in, state& st) {
    st.packets.push_back(in.string());
  }
};

#if 0

// To avoid many forward declarations, the grammer is written bottom-up.

/* To handle old packet tags, which encode the length type, we special case on
  each combination of
struct old_packet_length_one : bytes<1>;
struct old_packet_length_two : bytes<2>;
struct old_packet_length_four : bytes<4>;
/* Not supported.  */
struct old_packet_length_na : failure;

template <uint8_t TAG>
struct old_packet_header_with_tag
    : sor<seq<one<0x80 | (TAG << 2) | 0x00>, old_packet_length_one>,
          seq<one<0x80 | (TAG << 2) | 0x01>, old_packet_length_two>,
          seq<one<0x80 | (TAG << 2) | 0x02>, old_packet_length_four>,
          seq<one<0x80 | (TAG << 2) | 0x03>, old_packet_length_na> > {};

template <uint8_t TAG>
struct new_packet_header_with_tag
    : seq<one<0x80 | 0x40 | TAG>, new_packet_length>;

/* For most tags, we only support new packet headers.  */
template <uint8_t TAG>
struct packet_header_with_tag : new_packet_header_with_tag<TAG>;

/* For tags 0-15, we allow old packet headers.  */

struct packet_header_with_tag<0>
    : sor<new_packet_header_with_tag<0>, old_packet_header_with_tag<0> > {};

struct packet_header_with_tag<1>
    : sor<new_packet_header_with_tag<1>, old_packet_header_with_tag<1> > {};

struct packet_header_with_tag<2>
    : sor<new_packet_header_with_tag<2>, old_packet_header_with_tag<2> > {};

struct packet_header_with_tag<3>
    : sor<new_packet_header_with_tag<3>, old_packet_header_with_tag<3> > {};

struct packet_header_with_tag<4>
    : sor<new_packet_header_with_tag<4>, old_packet_header_with_tag<4> > {};

struct packet_header_with_tag<5>
    : sor<new_packet_header_with_tag<5>, old_packet_header_with_tag<5> > {};

struct packet_header_with_tag<6>
    : sor<new_packet_header_with_tag<6>, old_packet_header_with_tag<6> > {};

struct packet_header_with_tag<7>
    : sor<new_packet_header_with_tag<7>, old_packet_header_with_tag<7> > {};

struct packet_header_with_tag<8>
    : sor<new_packet_header_with_tag<8>, old_packet_header_with_tag<8> > {};

struct packet_header_with_tag<9>
    : sor<new_packet_header_with_tag<9>, old_packet_header_with_tag<9> > {};

struct packet_header_with_tag<10>
    : sor<new_packet_header_with_tag<10>, old_packet_header_with_tag<10> > {};

struct packet_header_with_tag<11>
    : sor<new_packet_header_with_tag<11>, old_packet_header_with_tag<11> > {};

struct packet_header_with_tag<12>
    : sor<new_packet_header_with_tag<12>, old_packet_header_with_tag<12> > {};

struct packet_header_with_tag<13>
    : sor<new_packet_header_with_tag<13>, old_packet_header_with_tag<13> > {};

struct packet_header_with_tag<14>
    : sor<new_packet_header_with_tag<14>, old_packet_header_with_tag<14> > {};

struct packet_header_with_tag<15>
    : sor<new_packet_header_with_tag<15>, old_packet_header_with_tag<15> > {};

/* Note that most of these variants can not match because they
   match earlier for supported packet types.  */
struct old_packet_header
    : sor<old_packet_header_with_tag<0>, old_packet_header_with_tag<1>,
          old_packet_header_with_tag<2>, old_packet_header_with_tag<3>,
          old_packet_header_with_tag<4>, old_packet_header_with_tag<5>,
          old_packet_header_with_tag<6>, old_packet_header_with_tag<7>,
          old_packet_header_with_tag<8>, old_packet_header_with_tag<9>,
          old_packet_header_with_tag<10>, old_packet_header_with_tag<11>,
          old_packet_header_with_tag<12>,
          // uid_packet: old_packet_header_with_tag<13>,
          old_packet_header_with_tag<14>, old_packet_header_with_tag<15> > {};

// New packet length.
struct new_packet_length_one : range<0x00, 0xbf> {};
struct new_packet_length_two : seq<range<0xc0, 0xdf>, any> {};
struct new_packet_length_partial : range<0xe0, 0xfe> {};
struct new_packet_length_five : seq<one<0xff>, rep<4, any> > {};
struct new_packet_length : seq<star<new_packet_length_partial, packet_body>,
                               sor<new_packet_length_one, new_packet_length_two,
                                   new_packet_length_five> > {};
struct new_packet_tag : range<0x80 | 0x40 | 0x00, 0x80 | 0x40 | 0x3f> {};
struct new_packet_header : seq<new_packet_tag, new_packet_length> {};

struct packet_header : sor<new_packet_header, old_packet_header> {};

/* FIXME */
struct packet_body : success {};

/* The length of the body from the header is captured in a state
     variable.  */
struct unknown_packet : seq<packet_header, packet_body> {};

struct uid_packet : seq<packet_header_with_tag<13>, packet_body> {};

/* A weak attempt to fail early with better diagnostics.  */
struct verify_packet_tag : at<range<0x80, 0xff> > {};

struct packet : seq<verify_packet_tag, sor<uid_packet, unknown_packet> > {};

#endif

#if 0

   template< typename Rule >
   struct action
      : nothing< Rule >
   {};

   template<>
     struct action< integer >
     {
     template< typename Input >
	static void apply( const Input& in, std::string& v )
      {
         v = in.string();
      }
   };

   struct long_literal_id
     : plus< not_one< '[' > > {};

   struct long_literal_mark
   {
     template< apply_mode A,
       rewind_mode M,
       template< typename... > class Action,
       template< typename... > class Control,
       typename Input >
       static bool match( Input& in,
			  const std::string& id,
			  const std::string& )
     {
       if( in.size( id.size() ) >= id.size() ) {
	 if( std::memcmp( in.current(), id.data(), id.size() ) == 0 ) {
	   in.bump( id.size() );
	   return true;
	 }
       }
       return false;
     }
   };

    template<>
     struct action< long_literal_id >
     {
       template< typename Input >
	 static void apply( const Input& in,
			    std::string& id,
			    const std::string& )
	 {
	   id = in.string();
	 }
     };

   template<> struct action< long_literal_body >
     {
       template< typename Input >
	 static void apply( const Input& in,
			    const std::string&,
			    std::string& body )
	 {
	   body += in.string();
	 }
     };

    struct Tag {
      Tag(char tag_) { tag = (uint8_t) tag_; }
      void verify() {
	if (get_bit (tag, 7))
	  throw PARSE_ERR_INVALID_TAG;
	if (is_old_format() && old_format_length_type == LENGTH_NA)
	  throw PARSE_ERR_INDETERMINATE_LENGTH;
      }
      bool is_old_format() {
	return get_bit(tag, 6) == 0;
      }
      tag_type_t old_format_tag() {
	return (tag_type_t) get_bits(tag, 2, 5);
      }
      tag_type_t new_format_tag() {
	return (tag_type_t) get_bits(tag, 0, 5);
      }
      uint32_t old_format_length_type() {
	return (length_type_t) get_bits(tag, 0, 1);
      }
      uint8_t tag;
    };
  }
#endif
}  // namespace OpenPGP
}  // namespace Parser
}  // namespace NeoPG
