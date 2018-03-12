// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/intern/cplusplus.h>

#include <neopg/openpgp.h>

#include <functional>

// Protect our use of PEGTL from other library users.
#define TAOCPP_PEGTL_NAMESPACE neopg_pegtl
#include <tao/pegtl.hpp>
using namespace tao::neopg_pegtl;

using namespace NeoPG;

namespace openpgp {

/* A new rule to match individual bits.  */
template <uint8_t Mask, uint8_t From, uint8_t To = 0>
struct mask_cmp {
  static const uint8_t from = From;
  static const uint8_t to = To ? To : From;

  template <typename Input>
  static bool match(Input& in) {
    if (!in.empty()) {
      uint8_t val = in.peek_byte() & Mask;
      if (val >= from && val <= to) {
        in.bump(1);
        return true;
      }
    }
    return false;
  }
};

// A range rule suitable for binary data.
template <uint8_t From, uint8_t To>
struct bin_range {
  template <typename Input>
  static bool match(Input& in) {
    if (!in.empty()) {
      uint8_t val = in.peek_byte();
      if (val >= From && val <= To) {
        in.bump(1);
        return true;
      }
    }
    return false;
  }
};

/* The OpenPGP parser is stateful (TLV), so the state, grammar and actions are
   tightly coupled.  */
struct state {
  PacketType packet_type;
  std::unique_ptr<PacketHeader> header;
  size_t packet_len;

  // This indicates that we have a partial packet frame.
  bool partial;

  // This indicates that we have started a partial packet.
  bool started;
};

/* A new (stateful) rule to match packet data. */
struct packet_body_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, state& state, RawPacketSink& sink) {
    if (in.size(state.packet_len) >= state.packet_len) {
      in.bump(state.packet_len);
      return true;
    }
    return false;
  }
};

// For old packets of indeterminate length, we first return identically-sized
// "partial" data packets and then finish with a final data packet (even if it
// is of 0 length). This works identical to new partial packet data, but we can
// not use the same rule as the length is unknown.

// We do not discard the input buffer here, as we come here after back-tracking
// from packet_body, and we want to preserve the data.
struct packet_body_rest : until<eof> {};

struct packet_body : seq<discard, packet_body_data> {};

struct old_packet_length_one : bytes<1> {};
struct old_packet_length_two : bytes<2> {};
struct old_packet_length_four : bytes<4> {};
struct old_packet_length_na : success {};  // Action sets default buffer size.

struct old_packet_tag : any {};

struct is_old_packet_with_length_one : at<mask_cmp<0x03, 0x00>> {};
struct is_old_packet_with_length_two : at<mask_cmp<0x03, 0x01>> {};
struct is_old_packet_with_length_four : at<mask_cmp<0x03, 0x02>> {};
struct is_old_packet_with_length_na : at<mask_cmp<0x03, 0x03>> {};

struct old_packet_with_length_one
    : seq<is_old_packet_with_length_one, old_packet_tag, old_packet_length_one,
          packet_body> {};
struct old_packet_with_length_two
    : seq<is_old_packet_with_length_two, old_packet_tag, old_packet_length_two,
          packet_body> {};
struct old_packet_with_length_four
    : seq<is_old_packet_with_length_four, old_packet_tag,
          old_packet_length_four, packet_body> {};
struct old_packet_with_length_na
    : seq<is_old_packet_with_length_na, old_packet_tag, old_packet_length_na,
          star<packet_body>, packet_body_rest> {};

// Old packets have bit 6 clear.
struct is_old_packet : at<mask_cmp<0x40, 0x00>> {};

// For old packets, the length type is encoded in the tag.  We differentiate
// before consuming the tag.
struct old_packet
    : seq<is_old_packet,
          sor<old_packet_with_length_one, old_packet_with_length_two,
              old_packet_with_length_four, old_packet_with_length_na>> {};

struct new_packet_length_one : bin_range<0x00, 0xbf> {};
struct new_packet_length_two : seq<bin_range<0xc0, 0xdf>, any> {};
struct new_packet_length_partial : bin_range<0xe0, 0xfe> {};
struct new_packet_length_five : seq<one<(char)0xff>, bytes<4>> {};

struct new_packet_data_partial : seq<new_packet_length_partial, packet_body> {};

struct new_packet_data_definite
    : seq<sor<new_packet_length_one, new_packet_length_two,
              new_packet_length_five>,
          packet_body> {};

// New packet data always ends with a definite length part, optionally preceeded
// by an arbitrary number of partial data parts.
struct new_packet_data
    : seq<star<new_packet_data_partial>, new_packet_data_definite> {};

// A new packet tag has the packet type in bit 0-5 (see action).
struct new_packet_tag : any {};

// A new packet tag has bit 6 set.
struct is_new_packet : at<mask_cmp<0x40, 0x40>> {};

// A new packet consists of a tag and one or more length and data parts.
struct new_packet : seq<is_new_packet, new_packet_tag, new_packet_data> {};

// Every packet starts with a tag that has bit 7 set.
struct is_packet : at<mask_cmp<0x80, 0x80>> {};

// A packet is either in the new or old format.
struct packet : seq<discard, is_packet, sor<new_packet, old_packet>> {};

// OpenPGP consists of a sequence of packets.
struct grammar : until<eof, packet> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<old_packet_tag> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)((str[0] >> 2) & 0xf);
    state.packet_type = (PacketType)val0;
  }
};

template <>
struct action<old_packet_length_one> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    state.packet_len = (uint8_t)(str[0]);
    state.header = NeoPG::make_unique<OldPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::OneOctet);
  }
};

template <>
struct action<old_packet_length_two> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[0];
    auto val1 = (uint8_t)str[1];
    state.packet_len = (val0 << 8) + val1;
    state.header = NeoPG::make_unique<OldPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::TwoOctet);
  }
};

template <>
struct action<old_packet_length_four> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[0];
    auto val1 = (uint8_t)str[1];
    auto val2 = (uint8_t)str[2];
    auto val3 = (uint8_t)str[3];
    state.packet_len = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
    state.header = NeoPG::make_unique<OldPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::FourOctet);
  }
};

template <>
struct action<old_packet_length_na> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[0];
    state.packet_len = 8192;  // FIXME
    state.header = NeoPG::make_unique<OldPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::Indeterminate);
    // Simulate a partial packet (we finish differently with packet_body_rest).
    state.partial = true;
  }
};

// Extract packet type from new packet tag.
template <>
struct action<new_packet_tag> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (str[0] & 0x3f);
    state.packet_type = (PacketType)val0;
  }
};

template <>
struct action<new_packet_length_one> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    state.packet_len = (uint8_t)(str[0]);
    state.header = NeoPG::make_unique<NewPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::OneOctet);
    state.partial = false;
  }
};

template <>
struct action<new_packet_length_two> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[0];
    auto val1 = (uint8_t)str[1];
    state.packet_len = ((val0 - 0xc0) << 8) + val1 + 192;
    state.header = NeoPG::make_unique<NewPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::TwoOctet);
    state.partial = false;
  }
};

template <>
struct action<new_packet_length_five> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[1];
    auto val1 = (uint8_t)str[2];
    auto val2 = (uint8_t)str[3];
    auto val3 = (uint8_t)str[4];
    state.packet_len = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
    state.header = NeoPG::make_unique<NewPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::FiveOctet);
    state.partial = false;
  }
};

template <>
struct action<new_packet_length_partial> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    auto val0 = (uint8_t)str[0];
    state.packet_len = 1 << (val0 & 0x1f);
    // FIXME: Not necessary if started == true. Would save one allocation.
    state.header = NeoPG::make_unique<NewPacketHeader>(
        state.packet_type, state.packet_len, PacketLengthType::Partial);
    state.partial = true;
  }
};

template <>
struct action<is_packet> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    std::string str = in.string();
    state.packet_type = PacketType::Reserved;
    state.header.reset(nullptr);
    state.partial = false;
    state.started = false;
  }
};

template <>
struct action<packet_body_data> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    const char* data = in.begin();
    size_t length = state.packet_len;

    if (!state.started) {
      if (!state.partial) {
        sink.next_packet(std::move(state.header), data, length);
      } else {
        sink.start_packet(std::move(state.header));
        sink.continue_packet(data, length);
      }
      state.started = true;
    } else {
      if (state.partial)
        sink.continue_packet(data, length);
      else {
        // FIXME: Use the one from header (requires dynamic cast which may be
        // 0).
        sink.finish_packet(NeoPG::make_unique<NewPacketLength>(length), data,
                           length);
      }
    }
    // auto packet = NeoPG::make_unique::make_unique<NeoPG::RawPacket>();
    // sink.next_packet(std::move(packet));
    // //sink.next_packet(NeoPG::make_unique<NeoPG::RawPacket>(state.packet_type));
  }
};

template <>
struct action<packet_body_rest> {
  template <typename Input>
  static void apply(const Input& in, state& state, RawPacketSink& sink) {
    const char* data = in.begin();
    size_t length = state.packet_len;
    sink.finish_packet(nullptr, data, length);
  }
};

}  // namespace openpgp

void RawPacketParser::process(Botan::DataSource& source) {
  using reader_t =
      std::function<std::size_t(char* buffer, const std::size_t length)>;

  auto reader = [this, &source](char* buffer,
                                const std::size_t length) mutable {
    return source.read(reinterpret_cast<uint8_t*>(buffer), length);
  };
  buffer_input<reader_t> input("reader", MAX_PARSER_BUFFER, reader);

  openpgp::state state;
  parse<openpgp::grammar, openpgp::action>(input, state, m_sink);
}

void RawPacketParser::process(std::istream& source) {
  Botan::DataSource_Stream in{source};
  process(in);
}

void RawPacketParser::process(const std::string& source) {
  std::stringstream in{source};
  process(in);
}
