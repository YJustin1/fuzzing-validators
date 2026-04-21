#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "candidate.hpp"

namespace fuzzing {

inline Candidate candidate_from_bytes(const uint8_t* data, std::size_t size) {
  Candidate out{0, 0};
  if (data == nullptr || size == 0) {
    return out;
  }

  // Stage 2 parser: map byte-level fuzz input into Candidate fields.
  if (size >= 4) {
    std::memcpy(&out.offset, data, 4);
  } else {
    for (std::size_t i = 0; i < size; ++i) {
      out.offset |= static_cast<int32_t>(data[i]) << (i * 8);
    }
  }

  if (size >= 8) {
    std::memcpy(&out.length, data + 4, 4);
  } else if (size > 4) {
    const std::size_t remaining = size - 4;
    for (std::size_t i = 0; i < remaining; ++i) {
      out.length |= static_cast<int32_t>(data[4 + i]) << (i * 8);
    }
  } else {
    // Keep pressure on parser even for short inputs.
    out.length = static_cast<int32_t>(size) * 17;
  }

  return out;
}

inline Candidate candidate_from_bytes(const std::vector<uint8_t>& bytes) {
  return candidate_from_bytes(bytes.data(), bytes.size());
}

}  // namespace fuzzing
