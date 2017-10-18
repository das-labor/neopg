/* Stream functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_UTILS_STREAM_H__
#define NEOPG_UTILS_STREAM_H__

#include <neopg/common.h>
#include <iostream>
#include <streambuf>

namespace NeoPG {

class CountingStreamBuf : public std::streambuf {
 public:
  CountingStreamBuf(){};
  uint32_t bytes_written() { return m_bytes_written; }

 protected:
  std::streamsize xsputn(const char_type* s, std::streamsize n) override {
    m_bytes_written += n;
    return n;
  };

  int_type overflow(int_type ch) override {
    m_bytes_written++;
    return 1;
  }

 private:
  uint32_t m_bytes_written = 0;
};

class CountingStream : public std::ostream {
 public:
  CountingStream() : std::ios(0), std::ostream(&m_counting_stream_buf) {}
  uint32_t bytes_written() { return m_counting_stream_buf.bytes_written(); }

 private:
  CountingStreamBuf m_counting_stream_buf;
};

}  // namespace NeoPG

#endif
