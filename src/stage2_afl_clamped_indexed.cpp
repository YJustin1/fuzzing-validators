// Clamp invalid indices before use (sanitize instead of reject).
// A clamping transform runs at the RLBox boundary: out-of-range indices
// are rewritten to a safe default (kSmallIndexDefault = 3) rather than
// rejected. Expected behavior: no crashes; this target is a calibration
// control showing our pipeline supports the "sanitize, don't reject"
// mitigation pattern.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "core/run_engine.hpp"
#include "core/sink_oracle.hpp"
#include "core/validators.hpp"

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
__AFL_FUZZ_INIT();
#endif

namespace {

std::vector<uint8_t> read_input_bytes(const std::string& file_path) {
  std::ifstream input(file_path, std::ios::binary);
  if (!input) {
    std::cerr << "Could not open input file: " << file_path << "\n";
    std::exit(1);
  }
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
  unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {
    const int len = __AFL_FUZZ_TESTCASE_LEN;
    fuzzing::run_stage2_case_with_clamp(buf, static_cast<std::size_t>(len),
                                        fuzzing::clamp_small_index,
                                        fuzzing::unchecked_validator,
                                        fuzzing::sink_indexed_read_small);
  }
  return 0;
#else
  if (argc < 2) {
    std::cerr << "Usage: stage2_afl_clamped_indexed <input_file>\n";
    return 1;
  }
  const std::vector<uint8_t> bytes = read_input_bytes(argv[1]);
  return fuzzing::run_stage2_case_with_clamp(bytes,
                                             fuzzing::clamp_small_index,
                                             fuzzing::unchecked_validator,
                                             fuzzing::sink_indexed_read_small);
#endif
}
