#ifndef __EXTENSION_TRACE_OUTPUT_H
#define __EXTENSION_TRACE_OUTPUT_H

#include "debug_tracer.h"
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <zlib.h>

/**
 * Writes the trace text to a file from a thread of its own, which also compresses it (gzip, zlib's default level)
 * with GZIP_OUTPUT. Compression used to take most of the time of a traced run. The text is collected into chunks, and
 * at most MAX_QUEUED full chunks wait for the thread: when it falls behind, write() waits.
 */
class trace_file_writer_t {
public:
  explicit trace_file_writer_t(const std::string &path);

  // Writes what is left and closes the file.
  ~trace_file_writer_t();

  void write(const char *data, size_t len) {
    m_chunk.insert(m_chunk.end(), data, data + len);
    if (m_chunk.size() >= CHUNK_SIZE) submit_chunk();
  }

private:
  constexpr static size_t CHUNK_SIZE = 1 << 20;
  constexpr static size_t MAX_QUEUED = 8;

  // Hand the current chunk to the writer thread, and start a new one.
  void submit_chunk();

  void writer_main();

  void write_to_file(const std::vector<char> &chunk);

  std::string m_path;
#ifdef GZIP_OUTPUT
  gzFile m_file;
#else
  FILE *m_file;
#endif
  bool m_write_failed = false; // written by the writer thread, read after it has finished

  std::vector<char> m_chunk; // being filled

  std::mutex m_mutex;
  std::condition_variable m_cv_queued; // a chunk was queued, or m_done was set
  std::condition_variable m_cv_space; // a queued chunk was written
  std::deque<std::vector<char>> m_queue; // full chunks, in order
  std::vector<std::vector<char>> m_spare; // written chunks, for reuse
  bool m_done = false;

  std::thread m_thread;
};

class trace_file_output_t : public trace_output_t {
public:
#ifdef GZIP_OUTPUT
  constexpr static const char *OUTPUT_EXT = ".gz";
#else
  constexpr static const char *OUTPUT_EXT = ".txt";
#endif

  explicit trace_file_output_t(const std::string &output_basename);

  ~trace_file_output_t() override = default;

  void issue_insn(const insn_record_t &insn) override;

private:
  trace_file_writer_t m_writer;
  disassembler_t m_disassembler;
  std::string m_buf; // the record being formatted
};


#endif //__EXTENSION_TRACE_OUTPUT_H
