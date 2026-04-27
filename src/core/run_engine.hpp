#pragma once

#include <cstdint>
#include <random>
#include <vector>

#include "byte_parser.hpp"
#include "candidate.hpp"
#include "rlbox_adapter.hpp"
#include "sink_oracle.hpp"

namespace fuzzing {

using ValidatorFn = bool (*)(const Candidate&);

inline void run_stage1(std::uint64_t iterations, ValidatorFn validator) {
  std::mt19937_64 rng{0xC0FFEEULL};
  RlSandbox sandbox;
  sandbox.create_sandbox();

  for (std::uint64_t i = 0; i < iterations; ++i) {
    const Candidate seed = random_candidate(rng);
    const Candidate c = get_candidate_via_rlbox(sandbox, seed);

    if (!validator(c)) {
      continue;
    }
    sink_use(c);
  }

  sandbox.destroy_sandbox();
}

inline int run_stage2_case(const std::vector<uint8_t>& input, ValidatorFn validator) {
  RlSandbox sandbox;
  sandbox.create_sandbox();

  const Candidate parsed = candidate_from_bytes(input);
  const Candidate c = get_candidate_via_rlbox(sandbox, parsed);

  if (validator(c)) {
    sink_use(c);
  }

  sandbox.destroy_sandbox();
  return 0;
}

inline int run_stage2_case_with_sink(const std::vector<uint8_t>& input,
                                     ValidatorFn validator,
                                     SinkFn sink) {
  RlSandbox sandbox;
  sandbox.create_sandbox();

  const Candidate parsed = candidate_from_bytes(input);
  const Candidate c = get_candidate_via_rlbox(sandbox, parsed);

  if (validator(c)) {
    sink(c);
  }

  sandbox.destroy_sandbox();
  return 0;
}

inline int run_stage2_case_with_sink(const uint8_t* data, std::size_t size,
                                     ValidatorFn validator,
                                     SinkFn sink) {
  RlSandbox sandbox;
  sandbox.create_sandbox();

  const Candidate parsed = candidate_from_bytes(data, size);
  const Candidate c = get_candidate_via_rlbox(sandbox, parsed);

  if (validator(c)) {
    sink(c);
  }

  sandbox.destroy_sandbox();
  return 0;
}

// Clamping-boundary pipeline: models the copy_and_verify pattern that
// rewrites out-of-range values to a safe default instead of rejecting
// them. The clamp runs after the RLBox unwrap but before the validator,
// mirroring the clamp-at-boundary pattern used by stage2_afl_clamped_indexed.
using ClampFn = Candidate (*)(Candidate);

inline int run_stage2_case_with_clamp(const uint8_t* data, std::size_t size,
                                      ClampFn clamp,
                                      ValidatorFn validator,
                                      SinkFn sink) {
  RlSandbox sandbox;
  sandbox.create_sandbox();

  const Candidate parsed = candidate_from_bytes(data, size);
  Candidate c = get_candidate_via_rlbox(sandbox, parsed);
  c = clamp(c);

  if (validator(c)) {
    sink(c);
  }

  sandbox.destroy_sandbox();
  return 0;
}

inline int run_stage2_case_with_clamp(const std::vector<uint8_t>& input,
                                      ClampFn clamp,
                                      ValidatorFn validator,
                                      SinkFn sink) {
  return run_stage2_case_with_clamp(input.data(), input.size(),
                                    clamp, validator, sink);
}

}  // namespace fuzzing
