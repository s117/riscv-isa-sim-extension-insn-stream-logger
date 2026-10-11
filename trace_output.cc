#include "trace_output.h"
#include <cassert>

trace_file_output_t::trace_file_output_t(const std::string &output_basename) {
  auto output_fullname = output_basename + OUTPUT_EXT;
  m_out_stream.open(output_fullname.c_str());
  assert(m_out_stream.good());
}

// The record is formatted by hand into a reusable buffer, as iostream formatting was a large part of the run time.

static void put_str(std::string &buf, const char *s) {
  buf.append(s);
}

static void put_dec(std::string &buf, uint64_t val) {
  char digits[20];
  size_t n = 0;
  do {
    digits[n++] = char('0' + val % 10);
    val /= 10;
  } while (val);
  while (n)
    buf.push_back(digits[--n]);
}

// Lowercase hex, zero-padded to at least width digits (never truncated)
static void put_hex(std::string &buf, uint64_t val, size_t width) {
  static const char hex_digits[] = "0123456789abcdef";
  char digits[16];
  size_t n = 0;
  do {
    digits[n++] = hex_digits[val & 0xf];
    val >>= 4;
  } while (val);
  for (size_t i = n; i < width; ++i)
    buf.push_back('0');
  while (n)
    buf.push_back(digits[--n]);
}

void trace_file_output_t::issue_insn(const insn_record_t &insn_rec) {
  if (insn_rec.valid) {
    auto insn = insn_rec.insn;
    auto insn_pc = insn_rec.pc;
    std::string &buf = m_buf;
    buf.clear();

    put_str(buf, "S/");
    put_dec(buf, insn_rec.seqno);
    put_str(buf, " C/");
    put_dec(buf, insn_rec.cycle);
    put_str(buf, " I/");
    put_dec(buf, insn_rec.instret);
    put_str(buf, " PC/0x");
    put_hex(buf, insn_pc, 16);
    put_str(buf, " (0x");
    put_hex(buf, insn.bits() & 0xffffffff, 8);
    put_str(buf, ") ");
    buf.append(m_disassembler.disassemble(insn));
    buf.push_back('\n');

    if (!insn_rec.good) {
      put_str(buf, "\tINV_FETCH\t0x00000001\n");
    }

    for (size_t rs_idx = 0; rs_idx < MAX_RSRC; ++rs_idx)
      if (insn_rec.rs_rec[rs_idx].valid) {
        put_str(buf, "\tRS");
        put_dec(buf, rs_idx);
        put_str(buf, "/");
        put_str(buf, xpr_name[insn_rec.rs_rec[rs_idx].n]);
        put_str(buf, "\t0x");
        put_hex(buf, insn_rec.rs_rec[rs_idx].val.xval, 8);
        buf.push_back('\n');
      }

    for (auto &rd: insn_rec.rd_rec)
      if (rd.valid && rd.n != 0) {
        put_str(buf, "\tRD/");
        put_str(buf, xpr_name[rd.n]);
        put_str(buf, "\t0x");
        put_hex(buf, rd.val.xval, 8);
        buf.push_back('\n');
      }

    if (insn.opcode() == OP_LOAD || insn.opcode() == OP_STORE) {
      assert(insn_rec.mem_rec.valid);
      put_str(buf, "\tADDR\t0x");
      put_hex(buf, insn_rec.mem_rec.vaddr, 8);
      buf.push_back('\n');
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
      put_str(buf, "\tTAKEN_PC\t0x");
      put_hex(buf, taken_target, 8);
      buf.push_back('\n');
    }

    if (insn_rec.exception) {
      put_str(buf, "\tEXCEPTION\t0x");
      put_hex(buf, 1, 16);
      put_str(buf, "\n\tEVEC\t0x");
      put_hex(buf, insn_rec.post_exe_state.evec, 16);
      put_str(buf, "\n\tECAUSE\t0x");
      put_hex(buf, insn_rec.post_exe_state.cause, 16);
      put_str(buf, "\n\tEPC\t0x");
      put_hex(buf, insn_rec.post_exe_state.epc, 16);
      put_str(buf, "\n\tSR\t0x");
      put_hex(buf, insn_rec.post_exe_state.sr, 8);
      buf.push_back('\n');
    }

    buf.push_back('\n');
    m_out_stream.write(buf.data(), buf.size());
  }
}
