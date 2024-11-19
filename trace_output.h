#ifndef __EXTENSION_TRACE_OUTPUT_H
#define __EXTENSION_TRACE_OUTPUT_H

#include "debug_tracer.h"
#include <cstdio>
class trace_stream_output_t : public trace_output_t {
public:
  explicit trace_stream_output_t(FILE *fp_output) : m_fp_output(fp_output) {};

  ~trace_stream_output_t() override = default;

  void issue_insn(const insn_record_t &insn) override { output_insn_record(insn); };

private:
  void output_insn_record(const insn_record_t &insn);
  FILE *m_fp_output;
  disassembler_t m_disassembler;
};

#endif //__EXTENSION_TRACE_OUTPUT_H
