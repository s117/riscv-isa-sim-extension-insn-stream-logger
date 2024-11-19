# riscv-isa-sim plugin to log the dynamic instruction stream

if (NOT ENABLE_DBG_TRACE)
    message(FATAL_ERROR "Instruction tracing support is required for this extension. Enabling it by adding flag '-DENABLE_DBG_TRACE=1' to the cmake command.")
endif ()

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
