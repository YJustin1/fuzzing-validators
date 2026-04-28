# RLBox Validator Fuzzing

Test the claim: **a value that passes an RLBox host-side validator can still cause unsafe behavior at a trusted use-site.** When that happens, the validator is insufficient for that sink.

This repository evolves a staged prototype that surfaces those insufficiencies — starting with random input generation and progressing to coverage-guided fuzzing with AFL++.

## Status

| Stage | Description | Status |
| --- | --- | --- |
| 1 | Random generation against validator + sink + oracle | implemented |
| 2 | Coverage-guided fuzzing (AFL++), persistent mode, multiple sinks, crash reporting | implemented |
| 3 | Corpus replay from real library outputs | planned |
| 4 | Integrated end-to-end: library input mutation drives validator and sink | planned |

## Pipeline

Every stage tests the same pipeline. The unit under test is a `Candidate { offset, length }` modeled as a value emitted across the RLBox sandbox boundary:

```
input source  ->  RLBox taint/copy_and_verify  ->  validator  ->  sink  ->  oracle
```

- **validator** — host-side logic that decides whether the sandbox value is safe to use. The project ships `good_validator` plus several weaker or no-op validators for calibration.
- **sink** — simulated trusted use-site. Several are shipped (e.g. `sink_use`, `sink_indexed_read`, `sink_indexed_read_small`, `sink_divide`). Different sinks stress *different* validators — sufficiency is sink-dependent.
- **oracle** — detects when an accepted value causes unsafe behavior and aborts so AFL++ records a crash.

## Quickstart

Already have Visual Studio 2022 and Docker Desktop? A short sequence gets you a campaign:

```powershell
git submodule update --init --recursive
cmake -S . -B build-vs -G "Visual Studio 17 2022" ; cmake --build build-vs --config Debug
.\scripts\fuzz.ps1 stage2_afl_bad_validator
```

See a report of what was found:

```powershell
.\scripts\report.ps1
```

For anything deeper, follow the docs below.

## Documentation

| Doc | What's in it |
| --- | --- |
| [`docs/build.md`](docs/build.md) | Build flavors (MSVC local, AFL++ in Docker, sanitizers), prerequisites, troubleshooting |
| [`docs/usage.md`](docs/usage.md) | How to run Stage 1, launch AFL campaigns, reproduce a crash, read the crash report |
| [`docs/rlbox-contract.md`](docs/rlbox-contract.md) | Project scope, pipeline definition, stage boundaries, non-goals |
| [`docs/stage2-fuzzing-explainer.md`](docs/stage2-fuzzing-explainer.md) | What Stage 2 actually fuzzes, persistent mode, sink-dependent sufficiency demo |
| [`docs/file-guide.md`](docs/file-guide.md) | What each source file does and why it exists |
| [`docs/stage2-campaign-results.md`](docs/stage2-campaign-results.md) | Most recent all-targets campaign: crashes per validator, time-to-first-crash, coverage |

## Layout

```
src/
  core/                    # candidate, parsers, validators, sinks, oracle,
                           # RLBox adapter, smoke examples (host_examples.hpp)
  stage1_*.cpp             # random-generation harnesses
  stage2_*.cpp             # byte-driven file-input reproducers
  stage2_afl_*.cpp         # AFL++ entrypoints (persistent mode, stdin fallback)
  smoke_host_examples.cpp  # smoke driver for host_examples constant/arg cases
scripts/
  gen_seeds.py             # boundary-focused seed corpus generator
  run_afl.sh               # container-side campaign runner (build + fuzz + summary)
  fuzz.ps1                 # Windows wrapper: one command from host to container
  fuzz_all.sh / fuzz_all.ps1  # batch runner: every Stage 2 target, shared budget
  report.py                # per-campaign metrics + crash bucketing by oracle reason
  report.ps1               # Windows wrapper for report.py (text or markdown)
  smoke_test.py            # drives smoke_host_examples (expectations listed in the script)
seeds/                     # AFL++ seed corpus (generated)
results/                   # e.g. stage2-campaign-results.txt (logs under results/logs/ when fuzzing)
third_party/rlbox/         # RLBox submodule
docs/                      # see table above
```

## Threat Model

- Attacker can control any value returned across the sandbox boundary.
- RLBox backend isolation is assumed to hold.
- A validator is **insufficient** if the attacker can construct a value that (a) passes validation and (b) causes unsafe behavior at the sink.

## Calibration Design

Every AFL target is paired with its opposite — a known-good and a known-bad version. A result is only meaningful when it comes with its calibration partner:

- `stage2_afl_bad_validator` should find crashes; `stage2_afl_good_validator` should not (under the same budget, against the same sink).
- `stage2_afl_length_only_indexed` should find crashes; the strong `good_validator` would be clean against the same indexed sink.
- `stage2_afl_unchecked_indexed` should find crashes; `stage2_afl_clamped_indexed` (clamping `copy_and_verify`) should not.
- `stage2_afl_div_by_zero` should find crashes; `stage2_afl_div_by_zero_guarded` should not.

Without both sides you can't tell whether a zero-crash result means the validator is sound or the harness is broken.

Latest all-targets run (7 campaigns × 300s each) is in [`docs/stage2-campaign-results.md`](docs/stage2-campaign-results.md). Reproduce with:

```powershell
.\scripts\fuzz_all.ps1 -BudgetSeconds 300
.\scripts\report.ps1 -Format markdown -Output docs/stage2-campaign-results.md `
    -OutDirs out_bad_validator,out_good_validator,out_length_only_indexed,`
             out_unchecked_indexed,out_clamped_indexed,`
             out_div_by_zero,out_div_by_zero_guarded
```

## Smoke examples

Illustrative host-side examples live in `src/core/host_examples.hpp`. `smoke_host_examples` runs them by name; `scripts/smoke_test.py` encodes expected safe vs trap outcomes for automation.

- Constant-behavior and arg-driven cases → smoke runner
- Full RLBox `Candidate` pipeline (indexing, division, etc.) → the `stage2_afl_*` harnesses, not the smoke binary
