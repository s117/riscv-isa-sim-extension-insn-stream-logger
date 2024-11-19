# riscv-isa-sim plugin to log the dynamic instruction stream
set(
        insn_stream_logger_hdrs
        insn_stream_logger.h
        trace_output.h
)

set(
        insn_stream_logger_srcs
        insn_stream_logger.cc
        trace_output.cc
)

add_library(
        insn_stream_logger SHARED
        ${insn_stream_logger_hdrs}
        ${insn_stream_logger_srcs}
)
target_link_libraries(insn_stream_logger fesvr-interface)
target_link_libraries(insn_stream_logger riscv-interface)
target_compile_definitions(insn_stream_logger PRIVATE GZIP_OUTPUT)
