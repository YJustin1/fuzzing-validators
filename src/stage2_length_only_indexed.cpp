// File-input reproducer for the length_only_validator + sink_indexed_read
// pairing. Use this to replay crashes discovered by
// stage2_afl_length_only_indexed.

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
  if (argc < 2) {
    std::cerr << "Usage: stage2_length_only_indexed <input_file>\n";
    return 1;
  }
  const std::vector<uint8_t> bytes = read_input_bytes(argv[1]);
  return fuzzing::run_stage2_case_with_sink(bytes,
                                            fuzzing::length_only_validator,
                                            fuzzing::sink_indexed_read);
}
