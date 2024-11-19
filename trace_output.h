#ifndef __EXTENSION_TRACE_OUTPUT_H
#define __EXTENSION_TRACE_OUTPUT_H

#include "debug_tracer.h"
#include <iostream>
#include <memory>
#include <string>

class trace_file_output_t : public trace_output_t {
public:
#ifdef GZIP_OUTPUT
  using ostream_t = ogzstream;
  constexpr static const char *OUTPUT_EXT = ".gz";
#else
  using ostream_t = std::ofstream;
  constexpr static const char *OUTPUT_EXT = ".txt";
#endif

  explicit trace_file_output_t(const std::string &output_basename);

  ~trace_file_output_t() override = default;

  void issue_insn(const insn_record_t &insn) override;

private:
  ostream_t m_out_stream;
  disassembler_t m_disassembler;
};


#endif //__EXTENSION_TRACE_OUTPUT_H
