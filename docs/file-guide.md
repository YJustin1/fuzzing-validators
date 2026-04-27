# File Guide (Current Stage 1 Layout)

This guide explains what each source file does in the current RLBox validator-testing prototype.

## Big Picture

Stage 1 models this pipeline:

`input generator -> RLBox boundary crossing -> validator -> sink -> oracle`

If the validator accepts a value and the sink detects unsafe behavior, that is a finding.

## Source Files

### Entry Points

- `src/stage1_bad_validator.cpp`
  - Executable for the known-bad validator baseline.
  - Calls `run_stage1(...)` with `bad_validator`.
  - Purpose: confirm the harness can find failures (positive control).

- `src/stage1_good_validator.cpp`
  - Executable for the known-good validator baseline.
  - Calls `run_stage1(...)` with `good_validator`.
  - Purpose: confirm the harness does not report false failures under the same budget (negative control).

- `src/stage2_bad_validator.cpp`
  - Stage 2 byte-input target for the known-bad validator.
  - Reads a raw input file and maps bytes into a `Candidate`.
  - Purpose: coverage-guided fuzz entrypoint where insufficient validation should be discoverable.

- `src/stage2_good_validator.cpp`
  - Stage 2 byte-input target for the known-good validator.
  - Same byte parsing path as bad target, but with strict validator.
  - Purpose: control target for estimating false positives under the same parser/input model.

- `src/stage2_afl_bad_validator.cpp`
  - Stage 2 AFL++ entrypoint for `bad_validator` + `sink_use`.
  - Uses AFL persistent mode (`__AFL_LOOP`) when built with `afl-clang-fast++`, falls back to `argv[1]` file input otherwise.
  - Purpose: coverage-guided discovery of values that bypass the bad validator and fail the range sink.

- `src/stage2_afl_good_validator.cpp`
  - Stage 2 AFL++ entrypoint for `good_validator` + `sink_use`.
  - Same persistent-mode / file-input dual build as the bad variant.
  - Purpose: calibration target that should stay clean under the same budget.

- `src/stage2_afl_length_only_indexed.cpp`
  - Stage 2 AFL++ entrypoint for `length_only_validator` + `sink_indexed_read`.
  - Demonstrates that validator sufficiency is sink-dependent: a validator that only constrains `length` leaves `offset` unbounded, which is unsafe when the sink indexes an array by `offset`.
  - Purpose: concrete evidence for the proposal claim that validators must be evaluated against the concrete use-site.

### Core Components

- `src/core/candidate.hpp`
  - Defines `Candidate` (`offset`, `length`) as the unit under test.
  - Provides `random_candidate(...)` for Stage 1 random input generation.

- `src/core/rlbox_adapter.hpp`
  - Wraps RLBox-specific logic for the noop backend.
  - Creates the RLBox sandbox type alias.
  - Sends candidate fields through `invoke_sandbox_function(...)` and unwraps with `copy_and_verify(...)`.
  - Purpose: ensure test values follow RLBox taint/unwrapping semantics before validation.

- `src/core/validators.hpp`
  - Contains validator implementations:
    - `bad_validator`: intentionally incomplete checks (only offset bounds)
    - `good_validator`: stricter bounds and overflow-safe checks
    - `length_only_validator`: constrains only `length` — sufficient for sinks that don't use `offset` as an index, unsafe otherwise
  - Purpose: calibrate harness behavior with known fail/pass validators and demonstrate sink-dependent sufficiency.

- `src/core/sink_oracle.hpp`
  - Simulates two trusted use-sites:
    - `sink_use`: range-based buffer write (uses `offset` and `length`)
    - `sink_indexed_read`: indexed array read (uses `offset` as index into a 16-entry table)
  - Exposes `SinkFn` so the run engine can pair any validator with any sink.
  - Performs oracle detection (`oracle_fail`) via `std::abort()` so AFL++ records failures as crashes.
  - Purpose: turn validator insufficiency into a concrete, reproducible failure signal under multiple use-sites.

- `src/core/run_engine.hpp`
  - Orchestrates stage pipelines:
    - `run_stage1(...)`: random generation loop used by Stage 1 executables.
    - `run_stage2_case(...)`: single byte-driven case using the default `sink_use`.
    - `run_stage2_case_with_sink(...)`: byte-driven case parameterized by validator AND sink, enabling sink-dependent studies. Overloaded for both `std::vector<uint8_t>` and raw `(buf, len)` so AFL persistent mode can call it without copying.
  - Purpose: reusable driver for Stage 1/2 experiments; the sink-parameterized overload is what makes sink-dependent sufficiency testing cheap to extend.

- `src/core/byte_parser.hpp`
  - Converts raw byte input into `Candidate` fields.
  - Purpose: Stage 2 adapter from fuzzer-produced bytes to validator test values.

## Build / Project Files

- `CMakeLists.txt`
  - Configures C++ build and optional sanitizers.
  - Adds executables:
    - `stage1_bad_validator`, `stage1_good_validator` (Stage 1 random generation)
    - `stage2_bad_validator`, `stage2_good_validator` (Stage 2 byte-driven, file input)
    - `stage2_afl_bad_validator`, `stage2_afl_good_validator`, `stage2_afl_length_only_indexed` (Stage 2 AFL persistent-mode targets)
  - Adds include paths for local source and RLBox headers (`third_party/rlbox/code/include`).

- `scripts/gen_seeds.py`
  - Generates a boundary-focused seed corpus under `seeds/` (offsets/lengths at 0, 1, 15/16/17, 127/128/129, -1, plus interior values).
  - Filters out seeds that would crash any shipped AFL target so one corpus works for all campaigns.

- `scripts/run_afl.sh`
  - Convenience wrapper that (re)builds one AFL target with `afl-clang-fast++` and runs a bounded `afl-fuzz` campaign against it. Intended to be invoked inside the `aflplusplus/aflplusplus` container.

- `docs/rlbox-contract.md`
  - Project contract and terminology for RLBox validator fuzzing.
  - Defines stage boundaries and expected artifacts.

## Why both `stage1_bad_validator` and `stage1_good_validator` exist

You need both to validate the **testing framework itself**, not just validators:

- `stage1_bad_validator` should fail quickly.
  - Demonstrates your pipeline can detect insufficient validation.
- `stage1_good_validator` should stay clean.
  - Demonstrates your pipeline is not trivially flagging everything as unsafe.

Together, they provide calibration evidence that findings are meaningful.
