#include "trace_output.h"
#include <cassert>
#include <iomanip>

trace_file_output_t::trace_file_output_t(const std::string &output_basename) {
  auto output_fullname = output_basename + OUTPUT_EXT;
  m_out_stream.open(output_fullname.c_str());
  assert(m_out_stream.good());
}

void trace_file_output_t::issue_insn(const insn_record_t &insn_rec) {
  if (insn_rec.valid) {
    auto insn = insn_rec.insn;
    auto insn_pc = insn_rec.pc;
    m_out_stream << std::setfill('0');

    m_out_stream << std::dec
                 << "S/" << insn_rec.seqno
                 << " C/" << insn_rec.cycle
                 << " I/" << insn_rec.instret
                 << std::hex
                 << " PC/0x" << std::setw(16) << insn_pc
                 << " (0x" << std::setw(8) << (insn.bits() & 0xffffffff) << ") "
                 << m_disassembler.disassemble(insn)
                 << std::endl;

    if (!insn_rec.good) {
      m_out_stream << "\tINV_FETCH\t0x00000001" << std::endl;
    }

    for (size_t rs_idx = 0; rs_idx < MAX_RSRC; ++rs_idx)
      if (insn_rec.rs_rec[rs_idx].valid) {
        m_out_stream << std::dec
                     << "\tRS" << rs_idx
                     << "/"
                     << xpr_name[insn_rec.rs_rec[rs_idx].n]
                     << std::hex
                     << "\t0x" << std::setw(8) << insn_rec.rs_rec[rs_idx].val.xval
                     << std::endl;
      }

    for (auto &rd: insn_rec.rd_rec)
      if (rd.valid && rd.n != 0) {
        m_out_stream << "\tRD/" << xpr_name[rd.n]
                     << std::hex
                     << "\t0x" << std::setw(8) << rd.val.xval
                     << std::endl;
      }

    if (insn.opcode() == OP_LOAD || insn.opcode() == OP_STORE) {
      assert(insn_rec.mem_rec.valid);
      m_out_stream << std::hex
                   << "\tADDR\t0x" << std::setw(8) << insn_rec.mem_rec.vaddr
                   << std::endl;
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
      m_out_stream << std::hex
                   << "\tTAKEN_PC\t0x" << std::setw(8) << taken_target
                   << std::endl;
    }

    if (insn_rec.exception) {
      m_out_stream << std::hex
                   << "\tEXCEPTION\t0x" << std::setw(16) << 1l << std::endl
                   << "\tEVEC\t0x" << std::setw(16) << insn_rec.post_exe_state.evec << std::endl
                   << "\tECAUSE\t0x" << std::setw(16) << insn_rec.post_exe_state.cause << std::endl
                   << "\tEPC\t0x" << std::setw(16) << insn_rec.post_exe_state.epc << std::endl
                   << "\tSR\t0x" << std::setw(8) << insn_rec.post_exe_state.sr << std::endl;
    }

    m_out_stream << std::endl;
  }
}


trace_last_n_wrapper_t::trace_last_n_wrapper_t(size_t n, std::unique_ptr<trace_output_t> wrapped_output)
    : m_insn_rec_circ_buf(n),
      m_sz_buf(n),
      m_tail(0),
      m_head(0),
      m_empty(true),
      m_wrapped_output(std::move(wrapped_output)) {}

trace_last_n_wrapper_t::~trace_last_n_wrapper_t() {
  for (
    insn_record_t *p = insn_rec_circ_buf_pop();
    p != nullptr;
    p = insn_rec_circ_buf_pop()) {
    m_wrapped_output->issue_insn(*p);
  }
}

void trace_last_n_wrapper_t::issue_insn(const insn_record_t &insn) {
  insn_rec_circ_buf_push(insn);
}

void trace_last_n_wrapper_t::insn_rec_circ_buf_push(const insn_record_t &insn_rec) {
  m_insn_rec_circ_buf[m_tail] = insn_rec;

  if (likely(m_tail == m_head)) {
    if (unlikely(m_empty)) {
      m_tail = next_idx(m_tail);
      m_empty = false;
    }
    else {
      m_head = m_tail = next_idx(m_tail);
    }
  }
  else {
    m_tail = next_idx(m_tail);
  }
}

insn_record_t *trace_last_n_wrapper_t::insn_rec_circ_buf_pop() {
  insn_record_t *ret_ptr = nullptr;

  if (!m_empty) {
    ret_ptr = &m_insn_rec_circ_buf[m_head];
    m_head = next_idx(m_head);
    if (m_head == m_tail)
      m_empty = true;
  }

  return ret_ptr;
}
