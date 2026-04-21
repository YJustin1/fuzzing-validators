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
    - `bad_validator`: intentionally incomplete checks
    - `good_validator`: stricter bounds and overflow-safe checks
  - Purpose: calibrate harness behavior with known fail/pass validators.

- `src/core/sink_oracle.hpp`
  - Simulates trusted use-site behavior (`sink_use`).
  - Performs oracle detection (`oracle_fail`) when accepted values are unsafe for use.
  - Purpose: turn validator insufficiency into a concrete, reproducible failure signal.

- `src/core/run_engine.hpp`
  - Orchestrates the Stage 1 loop:
    1. generate random seed candidate
    2. pass through RLBox adapter
    3. run selected validator
    4. execute sink if accepted
    5. fail via oracle when unsafe
  - Purpose: reusable driver for Stage 1 experiments and future stage evolution.

## Build / Project Files

- `CMakeLists.txt`
  - Configures C++ build and optional sanitizers.
  - Adds two binaries:
    - `stage1_bad_validator`
    - `stage1_good_validator`
  - Adds include paths for local source and RLBox headers (`third_party/rlbox/code/include`).

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
