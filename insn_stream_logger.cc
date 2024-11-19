#include "insn_stream_logger.h"
#include "trace_output.h"
#include <iostream>
#include <memory>

/**
 * Fast skipping <SKIP_AMOUNT> instructions prior to tracing.
 */
constexpr static size_t SKIP_AMOUNT = 0;
/**
 * If set to 0, the entire trace will be kept.
 * Otherwise, only keep the trace of LAST_N instruction before the simulation stop.
 */
constexpr static size_t LAST_N = 0;

REGISTER_EXTENSION(insn_stream_logger, []() { return new insn_stream_logger(); })

void insn_stream_logger::set_processor(processor_t *_p) {
  extension_t::set_processor(_p);
  auto core_id = p->get_id();
  std::string trace_basename = std::string("trace_proc_") + std::to_string(core_id);
  auto new_trace_sink = std::unique_ptr<trace_output_t>(new trace_file_output_t(trace_basename));
  if (LAST_N) {
    new_trace_sink = std::unique_ptr<trace_output_t>(new trace_last_n_wrapper_t(LAST_N, std::move(new_trace_sink)));
  }
  p->get_dbg_tracer()->register_trace_output(std::move(new_trace_sink));
}

void insn_stream_logger::reset() {
  extension_t::reset();
  p->get_dbg_tracer()->enable_trace(SKIP_AMOUNT);
}

void insn_stream_logger::set_debug(bool value) {
}
