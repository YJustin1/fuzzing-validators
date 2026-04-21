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
  std::exit(2);
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

}  // namespace fuzzing
