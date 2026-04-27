// Smoke-test driver for the host_examples cases we can exercise without
// a full RLBox sandbox. See src/core/host_examples.hpp for the full
// rationale; the short version is that those functions fall
// into three categories:
//
//   (A) Smoke-test, constant-behavior cases   -> handled here
//   (B) Arg-driven cases                      -> handled here (fixed arg)
//   (C) RLBox-specific cases                  -> handled by
//       stage2_afl_unchecked_indexed / stage2_afl_clamped_indexed
//
// Invoke with one case name and an optional numeric argument:
//
//   smoke_host_examples trivial_array_read
//   smoke_host_examples basic_div_by_zero_guarded 7
//   smoke_host_examples basic_oob_read_from_arg 99
//
// Exit status semantics:
//   - 0   -> the case ran to completion without trapping.
//   - !=0 -> unknown case (exit 2) or bad usage (exit 1).
// A crash is reported by the OS terminating the process (SIGSEGV,
// SIGFPE, STATUS_ACCESS_VIOLATION, STATUS_INTEGER_DIVIDE_BY_ZERO, ...);
// scripts/smoke_test.py interprets those as "crash". We deliberately
// ignore the ported functions' return values - many of them return a
// computed value (to prevent optimization), which would otherwise be
// misread as a non-zero exit status.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "core/host_examples.hpp"

namespace {

int parse_int_arg(const char* s) {
  return static_cast<int>(std::strtol(s, nullptr, 0));
}

uint32_t parse_uint_arg(const char* s) {
  return static_cast<uint32_t>(std::strtoul(s, nullptr, 0));
}

int dispatch(const std::string& name, int argc, char** argv) {
  using namespace host_examples;

  // Each branch returns void to emphasize that the ported function's
  // return value is intentionally discarded - it's data, not status.
  // If control flow reaches the bottom of the branch, the case ran
  // cleanly; we exit 0. If the case trapped, the OS already killed us.

  // ---- (A) Smoke-test, constant-behavior cases ----
  // No inputs; outcome is fixed per build. Good for catching
  // regressions in safe paths and sanity-checking that
  // null-deref / div-by-zero still trap on this platform.
  if (name == "trivial_array_read")         { (void)trivial_array_read();         return 0; }
  if (name == "repeated_array_read")        { (void)repeated_array_read();        return 0; }
  if (name == "trivial_array_read_2d")      { (void)trivial_array_read_2d();      return 0; }
  if (name == "trivial_struct_read")        { (void)trivial_struct_read();        return 0; }
  if (name == "trivial_struct_read_nested") { (void)trivial_struct_read_nested(); return 0; }
  if (name == "basic_null_read")            { (void)basic_null_read();            return 0; }
  if (name == "basic_null_write")           { (void)basic_null_write();           return 0; }
  if (name == "basic_div_by_zero")          { (void)basic_div_by_zero();          return 0; }
  if (name == "basic_oob_read")             { (void)basic_oob_read();             return 0; }
  if (name == "basic_oob_write")            { (void)basic_oob_write();            return 0; }

  // ---- (B) Arg-driven cases (single scalar input) ----
  // A value read from argv forces the smoke_test.py-expected behavior.
  // Could be promoted to AFL targets later, but the smoke runner
  // is sufficient since behavior is a simple function of the arg.
  if (name == "basic_div_by_zero_guarded") {
    const int denominator = (argc >= 3) ? parse_int_arg(argv[2]) : 0;
    (void)basic_div_by_zero_guarded(denominator);
    return 0;
  }
  if (name == "basic_null_write2") {
    // Smoke runner always invokes this with a null pointer, matching
    // the smoke_test expectation. A non-null arg is not currently
    // reachable via the CLI.
    (void)basic_null_write2(nullptr);
    return 0;
  }
  if (name == "basic_div_by_zero2") {
    const int denominator = (argc >= 3) ? parse_int_arg(argv[2]) : 0;
    (void)basic_div_by_zero2(denominator);
    return 0;
  }
  if (name == "basic_oob_read_from_arg") {
    const uint32_t index = (argc >= 3) ? parse_uint_arg(argv[2]) : 99u;
    (void)basic_oob_read_from_arg(index);
    return 0;
  }

  // ---- (C) RLBox-specific cases ----
  // NOT handled here. sandbox_array_index_unchecked_unsafe,
  // sandbox_array_index_unchecked_safe,
  // sandbox_primitive_array_index_unchecked_unsafe, and
  // sandbox_array_index_checked are driven by the dedicated AFL
  // harnesses stage2_afl_unchecked_indexed and
  // stage2_afl_clamped_indexed.

  std::cerr << "unknown case: " << name << "\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: smoke_host_examples <case_name> [numeric_arg]\n";
    return 1;
  }
  return dispatch(argv[1], argc, argv);
}
