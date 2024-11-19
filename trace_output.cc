#include "trace_output.h"
#include <cinttypes>
#include <cassert>

void trace_stream_output_t::output_insn_record(const insn_record_t &insn_rec) {
  if (insn_rec.valid) {
    auto insn = insn_rec.insn;
    auto insn_pc = insn_rec.pc;

    fprintf(m_fp_output, "S/%" PRIu64 " C/%" PRIu64 " I/%" PRIu64 " PC/0x%016" PRIx64 " (0x%08" PRIx64 ") %s\n",
            insn_rec.seqno, insn_rec.cycle, insn_rec.instret, insn_pc, insn.bits() & 0xffffffff,
            m_disassembler.disassemble(insn).c_str());
    if (!insn_rec.good) {
      fprintf(m_fp_output, "%s", "\tINV_FETCH\t0x00000001\n");
    }
    for (size_t rs_idx = 0; rs_idx < MAX_RSRC; ++rs_idx)
      if (insn_rec.rs_rec[rs_idx].valid)
        fprintf(
          m_fp_output, "\tRS%" PRIu64 "/%s\t0x%08" PRIx64 "\n",
          rs_idx, xpr_name[insn_rec.rs_rec[rs_idx].n],
          insn_rec.rs_rec[rs_idx].val.xval);

    for (auto &rd: insn_rec.rd_rec)
      if (rd.valid && rd.n != 0)
        fprintf(
          m_fp_output, "\tRD/%s\t0x%08" PRIx64 "\n",
          xpr_name[rd.n], rd.val.xval);

    if (insn.opcode() == OP_LOAD || insn.opcode() == OP_STORE) {
      assert(insn_rec.mem_rec.valid);
      fprintf(m_fp_output, "\tADDR\t0x%08" PRIx64 "\n", insn_rec.mem_rec.vaddr);
    }
    else if (insn.opcode() == OP_BRANCH || insn.opcode() == OP_JAL || insn.opcode() == OP_JALR) {
      reg_t taken_target = 0;
      switch (insn.opcode()) {
        case OP_BRANCH:
          taken_target = insn_pc + insn.sb_imm();
          break;
        case OP_JAL:
          taken_target = insn_pc + insn.uj_imm();
          break;
        case OP_JALR:
          assert(insn_rec.rs_rec[0].valid);
          taken_target = ((insn_rec.rs_rec[0].val.xval + insn.i_imm()) & ~reg_t(1));
          break;
        default:
          assert(0);
      }
      fprintf(m_fp_output, "\tTAKEN_PC\t0x%08" PRIx64 "\n", taken_target);
    }

    if (insn_rec.exception) {
      fprintf(m_fp_output, "\tEXCEPTION\t0x%016" PRIx64 "\n", 1l);
      fprintf(m_fp_output, "\tEVEC\t0x%016" PRIx64 "\n", insn_rec.post_exe_state.evec);
      fprintf(m_fp_output, "\tECAUSE\t0x%016" PRIx64 "\n", insn_rec.post_exe_state.cause);
      fprintf(m_fp_output, "\tEPC\t0x%016" PRIx64 "\n", insn_rec.post_exe_state.epc);
      fprintf(m_fp_output, "\tSR\t0x%08" PRIx32 "\n", insn_rec.post_exe_state.sr);
    }
    fprintf(m_fp_output, "%s", "\n");
  }
}
