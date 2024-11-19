#include "insn_stream_logger.h"
#include "trace_output.h"
#include <cstdio>

REGISTER_EXTENSION(insn_stream_logger, []() { return new insn_stream_logger(); })

void insn_stream_logger::reset() {
  extension_t::reset();
  p->get_dbg_tracer()->enable_trace(0);
}

void insn_stream_logger::set_debug(bool value) {
}

void insn_stream_logger::set_processor(processor_t *_p) {
  extension_t::set_processor(_p);
  p->get_dbg_tracer()->register_trace_output(new trace_stream_output_t(stdout));
}
