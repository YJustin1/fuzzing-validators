#pragma once

#include <cstdint>
#include <random>

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

}  // namespace fuzzing
