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

}  // namespace fuzzing
