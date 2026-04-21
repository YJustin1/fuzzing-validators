#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kBufferSize = 128;

struct Candidate {
  int32_t offset;
  int32_t length;
};

// Deliberately weak: checks only offset bounds, ignores length and signed math risk.
bool bad_validator(const Candidate& c) {
  return c.offset >= 0 && c.offset < static_cast<int32_t>(kBufferSize);
}

// Stronger validator: verifies full [offset, offset+length) range and overflow.
bool good_validator(const Candidate& c) {
  if (c.offset < 0 || c.length < 0) return false;
  if (c.offset > static_cast<int32_t>(kBufferSize)) return false;
  if (c.length > static_cast<int32_t>(kBufferSize)) return false;
  const int64_t end = static_cast<int64_t>(c.offset) + static_cast<int64_t>(c.length);
  return end >= 0 && end <= static_cast<int64_t>(kBufferSize);
}

[[noreturn]] void oracle_fail(const Candidate& c, const std::string& reason) {
  std::cerr << "FAIL: validator accepted unsafe value\n";
  std::cerr << "reason=" << reason << " offset=" << c.offset << " length=" << c.length << "\n";
  std::exit(2);
}

void sink_use(const Candidate& c) {
  std::vector<uint8_t> buffer(kBufferSize, 0);
  const int64_t begin = static_cast<int64_t>(c.offset);
  const int64_t end = begin + static_cast<int64_t>(c.length);

  if (begin < 0 || end < begin || end > static_cast<int64_t>(buffer.size())) {
    oracle_fail(c, "range_out_of_bounds");
  }

  // Trusted use-site simulation: copy a trusted marker into validated region.
  std::memset(buffer.data() + c.offset, 0xAB, static_cast<std::size_t>(c.length));
}

bool validator(const Candidate& c) {
#if USE_BAD_VALIDATOR
  return bad_validator(c);
#else
  return good_validator(c);
#endif
}

Candidate random_candidate(std::mt19937_64& rng) {
  // Broader ranges increase chance of bypass cases.
  static std::uniform_int_distribution<int32_t> dist(-1024, 1024);
  return Candidate{dist(rng), dist(rng)};
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t iterations = 200000;
  if (argc >= 2) {
    iterations = std::strtoull(argv[1], nullptr, 10);
  }

  std::mt19937_64 rng{0xC0FFEEULL};

  for (std::uint64_t i = 0; i < iterations; ++i) {
    const Candidate c = random_candidate(rng);
    if (!validator(c)) continue;
    sink_use(c);
  }

#if USE_BAD_VALIDATOR
  std::cout << "No failure discovered in budget for bad validator (increase iterations).\n";
#else
  std::cout << "Good validator completed budget without oracle failure.\n";
#endif

  return 0;
}
