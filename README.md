# RLBox Validator Fuzzing Prototypes

This repository bootstraps the proposal: validate RLBox-style host-side validators by checking whether values that pass validation can still cause unsafe behavior at a trusted use-site.

## Scope

- Stage 1 implemented: random generation against validator + sink + oracle.
- Stage 2-4 are outlined for incremental follow-up.
- Uses lightweight C++ harnesses to calibrate detection with:
  - known-bad validator(s) that should fail
  - known-good validator(s) that should hold

## Quick Start (Windows + clang++)

1. Build:

```powershell
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

2. Run bad validator target:

```powershell
.\build\stage1_bad_validator.exe 200000
```

3. Run good validator target:

```powershell
.\build\stage1_good_validator.exe 200000
```

## Expected Behavior

- `stage1_bad_validator` should usually discover a failing input quickly.
- `stage1_good_validator` should run cleanly under the same budget.

## Sanitizers

For stronger bug signals, compile with ASan/UBSan where toolchain support exists:

```powershell
cmake -S . -B build-asan -G "Ninja" -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-asan
```

## Next Steps

- Stage 2: AFL++ harness target for coverage-guided mutation.
- Stage 3: corpus replay from real library outputs.
- Stage 4: integrated end-to-end target where library input mutation drives validator and sink directly.
# RLBox Validator Fuzzing (C++)

This project is a C++ stage-by-stage prototype for testing RLBox-style validators.

## Threat Model

- Attacker can control values returned across the sandbox boundary.
- RLBox backend isolation is assumed to hold.
- A validator is insufficient if a value passes validation and later violates sink safety.

## Layout

- `harness/`: value model, parser, sink, oracle, and run engine
- `validators/`: one known-good and two known-bad validators
- `stages/`: stage executables (`stage1` through `stage4`)
- `scripts/`: PowerShell run scripts and report helper
- `results/`: per-stage JSON artifacts and summary

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Run All Stages

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1
```

## Per-Stage Commands

```powershell
.\build\Release\stage1.exe --runs 3 --budget-seconds 3
.\build\Release\stage2.exe --runs 3 --budget-seconds 3
.\build\Release\stage3.exe --runs 3 --budget-seconds 3 --capture-count 2000
.\build\Release\stage4.exe --runs 3 --budget-seconds 3
```

Each run writes metrics to `results/stageX/` including `ttff_seconds`, `etff`,
`ufph`, `ufc`, and `reproduction_stability`.
