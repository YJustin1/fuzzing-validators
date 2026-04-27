#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "candidate.hpp"
#include "validators.hpp"

namespace fuzzing {

[[noreturn]] inline void oracle_fail(const Candidate& c, const std::string& reason) {
  std::cerr << "FAIL: validator accepted unsafe value\n";
  std::cerr << "reason=" << reason << " offset=" << c.offset << " length=" << c.length << "\n";
  // Abort so coverage-guided fuzzers record this as a crash.
  std::abort();
}

inline void sink_use(const Candidate& c) {
  std::vector<uint8_t> buffer(kBufferSize, 0);
  const int64_t begin = static_cast<int64_t>(c.offset);
  const int64_t end = begin + static_cast<int64_t>(c.length);

  if (begin < 0 || end < begin || end > static_cast<int64_t>(buffer.size())) {
    oracle_fail(c, "range_out_of_bounds");
  }

  std::memset(buffer.data() + c.offset, 0xAB, static_cast<std::size_t>(c.length));
}

// Indexed use-site: trusted code uses offset as an array index.
inline void sink_indexed_read(const Candidate& c) {
  static constexpr std::size_t kTableSize = 16;
  static const int32_t table[kTableSize] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  };

  if (c.offset < 0 || c.offset >= static_cast<int32_t>(kTableSize)) {
    oracle_fail(c, "index_out_of_bounds");
  }

  volatile int32_t sink_value = table[c.offset];
  (void)sink_value;
}

// Small indexed sink matching host.cpp's 4-element host_array. Used by
// the unchecked_indexed / clamped_indexed targets to stay faithful to
// the sandbox_array_index_* tests.
inline void sink_indexed_read_small(const Candidate& c) {
  static constexpr std::size_t kSmallTableSize = 4;
  static const int32_t table[kSmallTableSize] = { 100, 200, 300, 400 };

  if (c.offset < 0 || c.offset >= static_cast<int32_t>(kSmallTableSize)) {
    oracle_fail(c, "small_index_out_of_bounds");
  }

  volatile int32_t sink_value = table[c.offset];
  (void)sink_value;
}

// Division use-site: attacker-controlled offset is the denominator.
// Mirrors host.cpp::basic_div_by_zero2.
inline void sink_divide(const Candidate& c) {
  if (c.offset == 0) {
    oracle_fail(c, "divide_by_zero");
  }
  volatile int32_t sink_value = 3 / c.offset;
  (void)sink_value;
}

using SinkFn = void (*)(const Candidate&);

}  // namespace fuzzing
