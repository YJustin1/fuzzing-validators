#!/usr/bin/env python3
"""Smoke-test the host_examples cases we can exercise without RLBox.

Those functions fall into three categories; this script only drives
categories (A) and (B). Category (C) (full RLBox index path) is fuzzed by
the AFL harnesses stage2_afl_unchecked_indexed /
stage2_afl_clamped_indexed.

  (A) Smoke-test, constant-behavior cases - no inputs, fixed outcome.
  (B) Arg-driven cases - single scalar input, pinned to the value that
      triggers the expected outcome in the tables below.
  (C) RLBox-specific cases - handled by AFL, NOT this script.

Expectations encoded below: "Ok" maps to a normal
exit, "Err" maps to an abnormal exit (nonzero, signal, or SEH).

Limitations:
- Stack-array OOB reads/writes are undefined behavior that may or may
  not produce a runtime fault without sanitizers. The "asan-only" rows
  below will often miss on plain MSVC Debug builds.
- For reliable coverage of OOB cases, pass --binary pointing at a
  sanitizer-instrumented build (cmake -DENABLE_SANITIZERS=ON ...).

Usage:
  python scripts/smoke_test.py
  python scripts/smoke_test.py --binary build-asan/smoke_host_examples
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---- Category (A): smoke-test, constant-behavior cases (no inputs) ----
# Expected Ok (clean exit).
CASES_A_OK = [
    ("trivial_array_read", None),
    ("repeated_array_read", None),
    ("trivial_array_read_2d", None),
    ("trivial_struct_read", None),
    ("trivial_struct_read_nested", None),
]
# Expected Err (crash/signal); reliably trap on every supported platform.
CASES_A_CRASH_RELIABLE = [
    ("basic_null_read", None),
    ("basic_null_write", None),
    ("basic_div_by_zero", None),
]
# Expected Err (crash); stack-OOB UB that only reliably traps
# under ASan/UBSan.
CASES_A_CRASH_ASAN_ONLY = [
    ("basic_oob_read", None),
    ("basic_oob_write", None),
]

# ---- Category (B): arg-driven cases (single scalar input) ----
# A fixed argument picks the expected outcome for that row.
CASES_B_OK = [
    ("basic_div_by_zero_guarded", "0"),
    ("basic_div_by_zero_guarded", "7"),
]
CASES_B_CRASH_RELIABLE = [
    ("basic_null_write2", None),     # pinned to nullptr inside the driver
    ("basic_div_by_zero2", "0"),
]
CASES_B_CRASH_ASAN_ONLY = [
    ("basic_oob_read_from_arg", "99"),
]


@dataclass
class Result:
    case: str
    arg: Optional[str]
    expected: str
    observed: str
    passed: bool
    exit_code: int
    category: str  # "A" (constant) or "B" (arg-driven)
    asan_only: bool = False


def find_binary() -> Optional[Path]:
    candidates = [
        Path("build-vs/Debug/smoke_host_examples.exe"),
        Path("build-vs/Release/smoke_host_examples.exe"),
        Path("build-asan/smoke_host_examples.exe"),
        Path("build-asan/smoke_host_examples"),
        Path("build/smoke_host_examples"),
        Path("build/smoke_host_examples.exe"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def run_case(binary: Path, case: str, arg: Optional[str], timeout_s: int = 10) -> tuple[int, str]:
    cmd = [str(binary), case]
    if arg is not None:
        cmd.append(arg)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return (124, "timeout")
    code = r.returncode
    # On POSIX a signal produces returncode = -signal. We want "crash"
    # to mean "anything other than clean zero exit", so normalize.
    if code == 0:
        return (0, "ok")
    return (code, "crash")


def evaluate(cases, expected: str, binary: Path, category: str,
             asan_only: bool = False) -> list[Result]:
    results = []
    for case, arg in cases:
        exit_code, observed = run_case(binary, case, arg)
        passed = (observed == expected)
        results.append(Result(case, arg, expected, observed, passed,
                              exit_code, category, asan_only))
    return results


def print_table(results: list[Result]) -> None:
    width = max(len(f"{r.case}({r.arg})" if r.arg else r.case) for r in results)
    width = max(width, 40)
    header = (f"{'cat':<4}{'case':<{width}}  {'expect':<8}  {'got':<8}  "
              f"{'code':>6}  {'verdict':<7}  notes")
    print(header)
    print("-" * len(header))
    for r in results:
        label = f"{r.case}({r.arg})" if r.arg else r.case
        verdict = "PASS" if r.passed else "FAIL"
        note = "(asan-only: may FAIL without sanitizers)" if (r.asan_only and not r.passed) else ""
        print(f"{r.category:<4}{label:<{width}}  {r.expected:<8}  {r.observed:<8}  "
              f"{r.exit_code:>6}  {verdict:<7}  {note}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, default=None, help="path to smoke_host_examples executable")
    args = ap.parse_args()

    binary = args.binary or find_binary()
    if binary is None or not binary.exists():
        print("smoke_host_examples not found. Build first with:\n"
              "  cmake --build build-vs --config Debug", file=sys.stderr)
        return 1

    print(f"[smoke] using binary: {binary}")
    print(f"[smoke] platform     : {platform.system()} {platform.release()}")
    print()

    a_ok      = evaluate(CASES_A_OK,                "ok",    binary, "A")
    a_crash   = evaluate(CASES_A_CRASH_RELIABLE,    "crash", binary, "A")
    a_asan    = evaluate(CASES_A_CRASH_ASAN_ONLY,   "crash", binary, "A", asan_only=True)
    b_ok      = evaluate(CASES_B_OK,                "ok",    binary, "B")
    b_crash   = evaluate(CASES_B_CRASH_RELIABLE,    "crash", binary, "B")
    b_asan    = evaluate(CASES_B_CRASH_ASAN_ONLY,   "crash", binary, "B", asan_only=True)

    all_results = a_ok + a_crash + a_asan + b_ok + b_crash + b_asan
    print_table(all_results)

    reliable_results = a_ok + a_crash + b_ok + b_crash
    asan_results = a_asan + b_asan
    reliable_failures = [r for r in reliable_results if not r.passed]

    print()
    print("Category legend:  A = constant-behavior   B = arg-driven   "
          "(C = RLBox-specific, fuzzed via AFL)")
    if reliable_failures:
        print(f"[smoke] FAILED: {len(reliable_failures)} of {len(reliable_results)} "
              f"reliable cases did not match expectations.")
        return 1
    print(f"[smoke] PASSED: {len(reliable_results)} / {len(reliable_results)} "
          f"reliable cases match expectations.")
    asan_passed = sum(1 for r in asan_results if r.passed)
    print(f"[smoke] asan-only: {asan_passed} / {len(asan_results)} crashed as expected "
          f"(missing crashes here are expected without ENABLE_SANITIZERS=ON).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
