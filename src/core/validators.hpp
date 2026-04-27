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

// Insufficient for index sinks: checks only length, ignores offset bounds.
inline bool length_only_validator(const Candidate& c) {
  return c.length >= 0 && c.length < static_cast<int32_t>(kBufferSize);
}

// Mirrors UNSAFE_unverified(): no validation at all. Used to model sandbox
// output consumed with no checks (e.g. unguarded small-index reads).
inline bool unchecked_validator(const Candidate& /*c*/) {
  return true;
}

// Guards a division sink. Accepts only non-zero offsets (guarded divide).
inline bool nonzero_validator(const Candidate& c) {
  return c.offset != 0;
}

// Clamping transform: a copy_and_verify style check that rewrites out-of-range
// indices to a safe default rather than rejecting them. This is a
// different mitigation shape than the boolean validators above: the
// value is *modified* at the RLBox boundary so the sink never sees an
// unsafe input.
constexpr int32_t kSmallIndexMax = 4;
constexpr int32_t kSmallIndexDefault = 3;

inline Candidate clamp_small_index(Candidate c) {
  if (c.offset < 0 || c.offset >= kSmallIndexMax) {
    c.offset = kSmallIndexDefault;
  }
  return c;
}

}  // namespace fuzzing
