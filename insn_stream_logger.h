#ifndef __EXTENSION_INSN_STREAM_LOGGER
#define __EXTENSION_INSN_STREAM_LOGGER
#include "extension.h"

class insn_stream_logger : public extension_t {
public:
  const char *name() override { return "insn_stream_logger"; }

  std::vector<insn_desc_t> get_instructions() override { return {}; };
  std::vector<disasm_insn_t *> get_disasms() override { return {}; };
  void set_processor(processor_t *_p) override;
  void reset() override;
  void set_debug(bool value) override;
  ~insn_stream_logger() override = default;
};
#endif