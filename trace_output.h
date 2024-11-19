#ifndef __EXTENSION_TRACE_OUTPUT_H
#define __EXTENSION_TRACE_OUTPUT_H

#include "debug_tracer.h"
#include <iostream>

class trace_stream_output_t : public trace_output_t {
public:
  explicit trace_stream_output_t(std::ostream &output_stream) : m_out_stream(output_stream) {};

  ~trace_stream_output_t() override = default;

  void issue_insn(const insn_record_t &insn) override { output_insn_record(insn); };

private:
  void output_insn_record(const insn_record_t &insn);

  std::ostream &m_out_stream;
  disassembler_t m_disassembler;
};

#endif //__EXTENSION_TRACE_OUTPUT_H
