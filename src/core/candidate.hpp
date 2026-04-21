#pragma once

#include <cstdint>
#include <random>

namespace fuzzing {

struct Candidate {
  int32_t offset;
  int32_t length;
};

inline Candidate random_candidate(std::mt19937_64& rng) {
  static std::uniform_int_distribution<int32_t> dist(-1024, 1024);
  return Candidate{dist(rng), dist(rng)};
}

}  // namespace fuzzing
