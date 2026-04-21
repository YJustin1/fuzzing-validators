#pragma once

#include <cstddef>
#include <cstdint>

#include "candidate.hpp"

namespace fuzzing {

constexpr std::size_t kBufferSize = 128;

inline bool bad_validator(const Candidate& c) {
  return c.offset >= 0 && c.offset < static_cast<int32_t>(kBufferSize);
}

inline bool good_validator(const Candidate& c) {
  if (c.offset < 0 || c.length < 0) return false;
  if (c.offset > static_cast<int32_t>(kBufferSize)) return false;
  if (c.length > static_cast<int32_t>(kBufferSize)) return false;
  const int64_t end = static_cast<int64_t>(c.offset) + static_cast<int64_t>(c.length);
  return end >= 0 && end <= static_cast<int64_t>(kBufferSize);
}

}  // namespace fuzzing
