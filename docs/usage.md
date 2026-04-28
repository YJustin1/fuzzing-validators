# Usage Guide

Day-to-day workflow for running harnesses, launching AFL++ campaigns, and reading results.

## Stage 1 — Random Generation

Random-input harness; used as a baseline and a smoke test of the pipeline.

```powershell
.\build-vs\Debug\stage1_bad_validator.exe 200000
.\build-vs\Debug\stage1_good_validator.exe 200000
```

The positional argument is the iteration count. Expected behavior:

- `stage1_bad_validator` discovers a failing input quickly (typically within the first few thousand iterations) and aborts with a `FAIL: validator accepted unsafe value` message on stderr.
- `stage1_good_validator` runs to completion with no failures under the same budget.

## Stage 2 — Byte-Driven File Reproducers

Stage 2 binaries accept a raw byte file and parse it into a `Candidate` struct before running through the RLBox boundary, validator, sink, and oracle. Useful for reproducing a specific crash or running a quick manual test.

```powershell
.\build-vs\Debug\stage2_bad_validator.exe .\path\to\input.bin
.\build-vs\Debug\stage2_good_validator.exe .\path\to\input.bin
.\build-vs\Debug\stage2_length_only_indexed.exe .\path\to\input.bin
.\build-vs\Debug\stage2_unchecked_indexed.exe .\path\to\input.bin
.\build-vs\Debug\stage2_clamped_indexed.exe .\path\to\input.bin
.\build-vs\Debug\stage2_div_by_zero.exe .\path\to\input.bin
.\build-vs\Debug\stage2_div_by_zero_guarded.exe .\path\to\input.bin
.\build-vs\Debug\stage2_four_sinks_one_bad.exe .\path\to\input.bin
.\build-vs\Debug\stage2_four_sinks_all_good.exe .\path\to\input.bin
```

Exit code 0 means the case was accepted + sink-safe, or rejected by the validator. Non-zero means the oracle fired (the validator accepted an unsafe value).

## Stage 2 — AFL++ Campaign (the main event)

### 1. Generate the seed corpus (once)

```powershell
python scripts\gen_seeds.py
```

This writes boundary-focused seeds to `seeds/`. Each seed is crash-safe under **every** shipped AFL target, so the same corpus bootstraps every campaign. Adding new targets with tighter "no-validator" guarantees (like `stage2_afl_unchecked_indexed`) will narrow the universal-safe set — if you see fewer seeds than before, that's why.

### 2. Launch a campaign

From Windows (one command, handles Docker + build + fuzz):

```powershell
.\scripts\fuzz.ps1 stage2_afl_bad_validator
.\scripts\fuzz.ps1 stage2_afl_good_validator  out_good     900
.\scripts\fuzz.ps1 stage2_afl_length_only_indexed out_indexed 1800
.\scripts\fuzz.ps1 stage2_afl_unchecked_indexed   out_unchecked 600
.\scripts\fuzz.ps1 stage2_afl_clamped_indexed     out_clamped   600
.\scripts\fuzz.ps1 stage2_afl_div_by_zero         out_div       300
.\scripts\fuzz.ps1 stage2_afl_div_by_zero_guarded out_div_g     300
```

Arguments: `<target>` `<out-dir (optional)>` `<budget-seconds (optional)>`. If `<out-dir>` is omitted, it's derived from the target name (e.g. `stage2_afl_bad_validator` → `out_bad_validator`). Budget defaults to 600s.

To fuzz **all 7 Stage 2 targets in one go** with a shared per-target budget:

```powershell
.\scripts\fuzz_all.ps1 -BudgetSeconds 300
```

This runs each target sequentially under `timeout`, writes per-campaign logs to `results/logs/<target>.log`, and leaves the usual `out_<suffix>/` directories on disk. It also sets `AFL_NO_UI=1` so the curses UI is replaced by plain-text logs (important when batching).

Generate the combined report afterwards:

```powershell
.\scripts\report.ps1 -Format markdown -Output docs/stage2-campaign-results.md `
    -OutDirs out_bad_validator,out_good_validator,out_length_only_indexed,`
             out_unchecked_indexed,out_clamped_indexed,`
             out_div_by_zero,out_div_by_zero_guarded
```

See [`stage2-campaign-results.md`](./stage2-campaign-results.md) for the latest committed run.

From inside the container:

```bash
bash scripts/run_afl.sh stage2_afl_bad_validator            out_bad       600
bash scripts/run_afl.sh stage2_afl_good_validator           out_good      600
bash scripts/run_afl.sh stage2_afl_length_only_indexed      out_indexed   600
bash scripts/run_afl.sh stage2_afl_unchecked_indexed        out_unchecked 600
bash scripts/run_afl.sh stage2_afl_clamped_indexed          out_clamped   600
bash scripts/run_afl.sh stage2_afl_div_by_zero              out_div       300
bash scripts/run_afl.sh stage2_afl_div_by_zero_guarded      out_div_g     300
```

### 3. What each target tests

| Target | Validator | Sink | Expected |
| --- | --- | --- | --- |
| `stage2_afl_bad_validator` | `bad_validator` (offset-bounded only) | `sink_use` (range write) | crashes found |
| `stage2_afl_good_validator` | `good_validator` (strict + overflow-safe) | `sink_use` | no crashes |
| `stage2_afl_length_only_indexed` | `length_only_validator` | `sink_indexed_read` (16-elem) | crashes found |
| `stage2_afl_unchecked_indexed` | `unchecked_validator` (no-op) | `sink_indexed_read_small` (4-elem, same size as `host_examples` small table) | crashes found |
| `stage2_afl_clamped_indexed` | clamp at the boundary + `unchecked_validator` | `sink_indexed_read_small` | no crashes |
| `stage2_afl_div_by_zero` | `unchecked_validator` | `sink_divide` | crashes found |
| `stage2_afl_div_by_zero_guarded` | `nonzero_validator` | `sink_divide` | no crashes |

The point of the whole exercise is **sink-dependent sufficiency**: `length_only_validator` is fine for some sinks but unsafe when `offset` is used as an array index; `unchecked_validator` is deliberately unsafe and `clamped_indexed` demonstrates a different mitigation pattern (sanitize instead of reject). The division pair does the same calibration on a non-bounds bug class.

Constant-behavior and arg-driven examples live in `src/core/host_examples.hpp` and are run by `smoke_host_examples` / `scripts/smoke_test.py` (expected outcomes are listed in the script). Full `Candidate`-through-RLBox indexing exercises use only the AFL harnesses above.

### 4. Watch the campaign

AFL++ prints its curses UI to the container terminal. Useful columns:

- `saved crashes` — the number you came here for.
- `stability` — should be ~100%; anything below ~95% suggests nondeterminism in the harness.
- `bitmap cvg` — proxy for how much of the program AFL explored.
- `exec speed` — with persistent mode enabled, expect hundreds to thousands per second once warmed up.

Press `Ctrl-C` to stop early; AFL writes final stats before exiting.

## Interpreting Results — the Crash Report

After (or during) a campaign, summarize results and bucket crashes by oracle reason:

```powershell
.\scripts\report.ps1 -OutDirs out_bad_validator,out_good_validator,out_length_only_indexed
```

No `-OutDirs` argument = auto-discover any `out*` directory at the project root. Use `-Format markdown` and `-Format text` to switch renderers; add `-Output <path>` to write to a file (otherwise it prints to the console).

### What you get per campaign

- Campaign metadata: run time, `execs_done`, `execs_per_sec`, `edges_found / total_edges`, `bitmap_cvg`, `stability`, `corpus_count`.
- `saved_crashes` count.
- `time-to-first-crash` and `execs-to-first-crash` — parsed from AFL crash filenames (they include `time:<ms>` and `execs:<n>`).
- Crashes bucketed by oracle reason (e.g. `range_out_of_bounds`, `index_out_of_bounds`), with the `(offset, length)` of each crash.

### Overview table

At the end of any multi-campaign run, you get a glance-friendly summary:

```text
============================================================
Overview
============================================================
target                                    crashes  reasons
stage2_afl_bad_validator                        5  range_out_of_bounds(5)
stage2_afl_good_validator                       0  -
```

### Reading it correctly

- **Budgets must be comparable.** If one campaign ran 5h and another ran 50m, raw crash counts aren't directly comparable — check `run_time` and `execs_done` in the per-target block.
- **Crashes are coverage-unique, not bug-unique.** Five crashes bucketed as `range_out_of_bounds` means five distinct *coverage paths*, not five semantically different bugs.
- **Zero crashes is only meaningful with coverage.** A 0-crash run at `bitmap_cvg: 2%` means AFL never explored; at `bitmap_cvg: 27%` it's a real calibration result.
- **Stability matters.** A 60%-stability run's crash count is less trustworthy than a 100%-stability run's.

### Why the report runs inside the container

AFL++ crash filenames contain `:`, which NTFS/PowerShell can't iterate cleanly. `scripts/report.ps1` runs `scripts/report.py` in the AFL++ container (Linux filenames). Replay uses the non-AFL `stage2_*` reproducers that `run_afl.sh` builds next to the AFL binary.

## Reproducing a Specific Crash

The file-input reproducers take a crash file directly:

```bash
# Inside the container
./build-afl/stage2_bad_validator out_bad_validator/default/crashes/id:000000,...
```

Or from Windows, using the build-vs reproducers (same logic, different compiler):

```powershell
# Copy the crash file out of the AFL output dir first if needed
.\build-vs\Debug\stage2_bad_validator.exe .\saved_crash.bin
```

Exit code will be non-zero and stderr will contain the oracle's `FAIL: validator accepted unsafe value` line with the specific `(offset, length)` that tripped it.

## Smoke Test

`smoke_host_examples` + `scripts/smoke_test.py` run the constant-behavior and arg-driven cases declared in [`src/core/host_examples.hpp`](../src/core/host_examples.hpp):

```powershell
python scripts\smoke_test.py
```

This is a parity check, not a fuzz campaign. Expect all "reliable" cases to PASS; the ASan-only rows (stack-OOB reads/writes) will typically FAIL on MSVC Debug without sanitizers — that's documented and expected. For a fair score on those rows, build with `-DENABLE_SANITIZERS=ON` on Linux and pass `--binary`.

Indexing with the full `Candidate` + RLBox pipeline is **not** in the smoke runner — use `stage2_afl_unchecked_indexed` and `stage2_afl_clamped_indexed`.

## Related Documentation

- [`docs/build.md`](./build.md) — build flavors (MSVC / AFL / sanitizers)
- [`docs/rlbox-contract.md`](./rlbox-contract.md) — project scope, pipeline definition, stage boundaries
- [`docs/stage2-fuzzing-explainer.md`](./stage2-fuzzing-explainer.md) — what Stage 2 actually fuzzes, persistent mode, sink-dependent sufficiency demo
- [`docs/file-guide.md`](./file-guide.md) — what each source file does
