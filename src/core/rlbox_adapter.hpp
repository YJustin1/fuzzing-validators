#pragma once

#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol

#include <cstdint>

#include "rlbox.hpp"
#include "rlbox_noop_sandbox.hpp"

#include "candidate.hpp"

namespace fuzzing {

using rlbox::rlbox_noop_sandbox;
using RlSandbox = rlbox::rlbox_sandbox<rlbox_noop_sandbox>;

inline int32_t passthrough_i32(int32_t v) { return v; }

inline Candidate get_candidate_via_rlbox(RlSandbox& sandbox, const Candidate& seed) {
  auto tainted_offset = sandbox.invoke_sandbox_function(passthrough_i32, seed.offset);
  auto tainted_length = sandbox.invoke_sandbox_function(passthrough_i32, seed.length);

  const int32_t offset = tainted_offset.copy_and_verify([](int32_t value) { return value; });
  const int32_t length = tainted_length.copy_and_verify([](int32_t value) { return value; });
  return Candidate{offset, length};
}

}  // namespace fuzzing
