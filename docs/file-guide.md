# File Guide

What each artifact does in this RLBox validator-testing prototype.

## Big Picture

Stage 1 random-input harness and Stage 2 AFL/file-input pipelines share:

`bytes -> RLBox boundary crossing -> validator -> sink -> oracle`

If the validator accepts a value and the sink detects unsafe behavior, that is a finding worth recording as an AFL crash.

## Entry Points — Stage 1 & Stage 2

### Stage 1 random generation

- `src/stage1_bad_validator.cpp` — calls `run_stage1(...)` with `bad_validator` (positive control).
- `src/stage1_good_validator.cpp` — calls `run_stage1(...)` with `good_validator` (negative control).

### Stage 2 file-input reproducers (non-AFL)

Byte file → `candidate_from_bytes` → RLBox path → validator + sink. Used to replay AFL crashes without the fork server.

- `src/stage2_bad_validator.cpp`, `src/stage2_good_validator.cpp` — `sink_use`.
- `src/stage2_length_only_indexed.cpp` — `length_only_validator` + `sink_indexed_read`.
- `src/stage2_unchecked_indexed.cpp` — `unchecked_validator` + `sink_indexed_read_small`.
- `src/stage2_clamped_indexed.cpp` — `clamp_small_index` + `unchecked_validator` + same small sink.
- `src/stage2_div_by_zero.cpp` — `unchecked_validator` + `sink_divide`.
- `src/stage2_div_by_zero_guarded.cpp` — `nonzero_validator` + `sink_divide`.
- `src/stage2_four_sinks_one_bad.cpp` — four sink/validator stages; last is `bad_validator` + `sink_use` (see `run_engine.hpp`).
- `src/stage2_four_sinks_all_good.cpp` — same four sinks; `good_validator` on the mem path (calibration).

### Stage 2 AFL++ (`__AFL_LOOP` persistent mode)

- `src/stage2_afl_bad_validator.cpp` / `stage2_afl_good_validator.cpp` — calibration pair on `sink_use`.
- `src/stage2_afl_length_only_indexed.cpp` — weak length-only validator vs indexed sink.
- `src/stage2_afl_unchecked_indexed.cpp` vs `stage2_afl_clamped_indexed.cpp` — unchecked vs clamp mitigation on `sink_indexed_read_small`.
- `src/stage2_afl_div_by_zero.cpp` vs `stage2_afl_div_by_zero_guarded.cpp` — division oracle calibration pair.
- `src/stage2_afl_four_sinks_one_bad.cpp` vs `stage2_afl_four_sinks_all_good.cpp` — AFL entrypoints for the four-sink library chain.

### Smoke examples

- `src/core/host_examples.hpp` — illustrative safe reads and deliberate UB for smoke checks.
- `src/smoke_host_examples.cpp` — CLI driver for categories (A) constant-behavior and (B) arg-driven cases only.

## Core Components

- `src/core/candidate.hpp` — `Candidate { offset, length }`; Stage 1 random helpers.
- `src/core/byte_parser.hpp` — raw bytes → `Candidate`.
- `src/core/rlbox_adapter.hpp` — noop RLBox sandbox plumbing (`invoke_sandbox_function`, `copy_and_verify`).
- `src/core/validators.hpp` — `bad_validator`, `good_validator`, `length_only_validator`, `unchecked_validator`, `nonzero_validator`, `clamp_small_index`, `good_index_16_validator`, `good_index_4_validator`.
- `src/core/sink_oracle.hpp` — `sink_use`, `sink_indexed_read`, `sink_indexed_read_small`, `sink_divide`; `oracle_fail` aborts for AFL.
- `src/core/run_engine.hpp` — `run_stage1`, `run_stage2_case_with_sink`, `run_stage2_case_with_clamp`, `run_stage2_four_sink_chain_one_bad` / `run_stage2_four_sink_chain_all_good`.

## Scripts & corpus

- `scripts/gen_seeds.py` — filtered boundary corpus safe under every shipped AFL target.
- `scripts/run_afl.sh`, `scripts/fuzz.ps1`, `scripts/fuzz_all.ps1` — Docker / batch AFL workflows.
- `scripts/report.py`, `scripts/report.ps1` — parse `fuzzer_stats`, replay crashes, bucket oracle reasons.
- `scripts/smoke_test.py` — drives `smoke_host_examples`; expectations encoded in `CASES_*` tables in that script.
- `seeds/` — generated seeds (checked in so clones skip corpus generation).

## Build / project files

- `CMakeLists.txt` — targets listed above + optional sanitizers.
- `third_party/rlbox/` — RLBox submodule (`third_party/rlbox/code/include`).

## Contract docs

- `docs/rlbox-contract.md` — scope, stages, terminology.

## Why calibration pairs exist

You need opposite validators/sinks under similar budgets to interpret zero-crash vs many-crash outcomes — see `README.md` “Calibration Design”.
