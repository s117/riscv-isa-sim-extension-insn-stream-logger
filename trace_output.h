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

class trace_last_n_wrapper_t : public trace_output_t {
public:
  trace_last_n_wrapper_t(size_t n, std::unique_ptr<trace_output_t> wrapped_output);

  ~trace_last_n_wrapper_t() override;

  void issue_insn(const insn_record_t &insn) override;

private:
  void insn_rec_circ_buf_push(const insn_record_t &insn_rec);

  insn_record_t *insn_rec_circ_buf_pop();

  inline size_t next_idx(size_t i) {
    // return (i + 1) % m_sz_buf;
    auto nidx = i + 1;
    return (nidx == m_sz_buf) ? 0 : nidx;
  };

  std::vector<insn_record_t> m_insn_rec_circ_buf;
  size_t m_sz_buf;
  size_t m_tail; // wr at tail
  size_t m_head; // rd at head
  bool m_empty;

  std::unique_ptr<trace_output_t> m_wrapped_output;
};


#endif //__EXTENSION_TRACE_OUTPUT_H
