#!/usr/bin/env python3
"""Per-validator crash report for Stage 2 AFL++ campaigns.

Intended to run inside the aflplusplus/aflplusplus container with the
project root mounted at /src. It reads AFL output directories, parses
fuzzer_stats, and replays each saved crash through the matching file-
input reproducer so we can bucket crashes by the oracle's failure
reason.

Usage:
  python3 scripts/report.py [out_dir ...]
  python3 scripts/report.py --format markdown --output docs/stage2-campaign-results.md

With no positional args, auto-discovers any ``out*`` directory at the
project root.
"""
from __future__ import annotations

import argparse
import io
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ORACLE_RE = re.compile(r"reason=(\S+)\s+offset=(-?\d+)\s+length=(-?\d+)")


# ---------------------------------------------------------------------
# Dataclasses for structured campaign results
# ---------------------------------------------------------------------


@dataclass
class CrashRecord:
    name: str
    reason: str
    offset: Optional[int]
    length: Optional[int]


@dataclass
class CampaignResult:
    target: str
    out_dir: Path
    stats: dict[str, str] = field(default_factory=dict)
    crash_count: int = 0
    time_to_first_s: Optional[float] = None
    time_to_last_s: Optional[float] = None
    execs_to_first: Optional[int] = None
    by_reason: dict[str, list[CrashRecord]] = field(default_factory=dict)
    replay_binary: Optional[Path] = None
    skipped_reason: Optional[str] = None


# ---------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------


def parse_stats(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def parse_crash_name(name: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for part in name.split(","):
        if ":" in part:
            k, v = part.split(":", 1)
            meta[k] = v
    return meta


# Map each AFL persistent-mode target to its plain file-input reproducer.
# The reproducer is far more reliable for replay: it takes a file path as
# argv[1], exits non-zero on abort, and prints the oracle's FAIL line to
# stderr so we can bucket by reason.
REPRO_MAP = {
    "stage2_afl_bad_validator": "stage2_bad_validator",
    "stage2_afl_good_validator": "stage2_good_validator",
    "stage2_afl_length_only_indexed": "stage2_length_only_indexed",
    "stage2_afl_unchecked_indexed": "stage2_unchecked_indexed",
    "stage2_afl_clamped_indexed": "stage2_clamped_indexed",
    "stage2_afl_div_by_zero": "stage2_div_by_zero",
    "stage2_afl_div_by_zero_guarded": "stage2_div_by_zero_guarded",
    "stage2_afl_four_sinks_one_bad": "stage2_four_sinks_one_bad",
    "stage2_afl_four_sinks_all_good": "stage2_four_sinks_all_good",
}


def infer_replay_binary(stats: dict[str, str]) -> Optional[Path]:
    cmd = stats.get("command_line", "")
    m = re.search(r"--\s+(\S+)", cmd)
    if not m:
        return None
    afl_binary = Path(m.group(1))
    afl_name = afl_binary.name
    build_dir = afl_binary.parent

    repro_name = REPRO_MAP.get(afl_name)
    if repro_name:
        candidate = build_dir / repro_name
        if candidate.exists():
            return candidate
    if afl_binary.exists():
        return afl_binary
    return None


def replay(binary: Path, crash_file: Path, timeout_s: int = 5) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """Run the reproducer / AFL binary on one crash input and extract the oracle reason."""
    try:
        is_afl = binary.name.startswith("stage2_afl_")
        if is_afl:
            with crash_file.open("rb") as fh:
                result = subprocess.run(
                    [str(binary)],
                    stdin=fh,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_s,
                )
        else:
            result = subprocess.run(
                [str(binary), str(crash_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_s,
            )
    except subprocess.TimeoutExpired:
        return ("timeout", None, None)
    except Exception as exc:  # noqa: BLE001
        return (f"replay_error:{exc.__class__.__name__}", None, None)

    text = (result.stderr or b"").decode(errors="replace") + (result.stdout or b"").decode(errors="replace")
    m = ORACLE_RE.search(text)
    if m:
        return (m.group(1), int(m.group(2)), int(m.group(3)))
    if result.returncode and result.returncode < 0:
        return (f"signal_{-result.returncode}", None, None)
    return ("no_oracle_output", None, None)


def fmt_duration(seconds_str: str) -> str:
    try:
        s = int(seconds_str)
    except (TypeError, ValueError):
        return seconds_str or "?"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def fmt_int(s: Optional[str]) -> str:
    if s is None:
        return "?"
    try:
        return f"{int(s):,}"
    except ValueError:
        return s


def discover_out_dirs(root: Path) -> list[Path]:
    candidates = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if not child.name.startswith("out"):
            continue
        if (child / "default" / "fuzzer_stats").exists() or (child / "fuzzer_stats").exists():
            candidates.append(child)
    return candidates


def find_session_dir(out_dir: Path) -> Optional[Path]:
    if (out_dir / "default" / "fuzzer_stats").exists():
        return out_dir / "default"
    if (out_dir / "fuzzer_stats").exists():
        return out_dir
    return None


# ---------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------


def collect_campaign(out_dir: Path) -> CampaignResult:
    result = CampaignResult(target=out_dir.name, out_dir=out_dir)

    session = find_session_dir(out_dir)
    if session is None:
        result.skipped_reason = "no fuzzer_stats found"
        return result

    result.stats = parse_stats(session / "fuzzer_stats")
    result.target = Path(result.stats.get("afl_banner", out_dir.name)).name

    crashes_dir = session / "crashes"
    crash_files = []
    if crashes_dir.exists():
        crash_files = [p for p in sorted(crashes_dir.iterdir())
                       if p.is_file() and not p.name.startswith("README")]
    result.crash_count = len(crash_files)

    if not crash_files:
        return result

    times, execs = [], []
    for c in crash_files:
        m = parse_crash_name(c.name)
        if "time" in m:
            try:
                times.append(int(m["time"]))
            except ValueError:
                pass
        if "execs" in m:
            try:
                execs.append(int(m["execs"]))
            except ValueError:
                pass
    if times:
        result.time_to_first_s = min(times) / 1000.0
        result.time_to_last_s = max(times) / 1000.0
    if execs:
        result.execs_to_first = min(execs)

    binary = infer_replay_binary(result.stats)
    result.replay_binary = binary

    if binary is None or not binary.exists():
        return result

    for c in crash_files:
        reason, off, ln = replay(binary, c)
        key = reason or "unknown"
        result.by_reason.setdefault(key, []).append(
            CrashRecord(name=c.name, reason=key, offset=off, length=ln)
        )

    return result


# ---------------------------------------------------------------------
# Text renderer (original layout)
# ---------------------------------------------------------------------


def render_text(results: list[CampaignResult]) -> str:
    buf = io.StringIO()
    w = buf.write

    for r in results:
        if r.skipped_reason:
            w(f"=== {r.target} ===\n")
            w(f"  ({r.skipped_reason}; skipping)\n\n")
            continue

        stats = r.stats
        w(f"=== {r.target}  ({r.out_dir}) ===\n")
        w("  Campaign:\n")
        w(f"    run_time          : {fmt_duration(stats.get('run_time', ''))}\n")
        w(f"    execs_done        : {fmt_int(stats.get('execs_done'))}\n")
        w(f"    execs_per_sec     : {stats.get('execs_per_sec', '?')}\n")
        edges = stats.get("edges_found", "?")
        total = stats.get("total_edges", "?")
        cvg = stats.get("bitmap_cvg", "?")
        w(f"    edges_found       : {edges} / {total} ({cvg})\n")
        w(f"    stability         : {stats.get('stability', '?')}\n")
        w(f"    corpus_count      : {stats.get('corpus_count', '?')}\n")
        w("  Crashes:\n")
        w(f"    saved_crashes     : {r.crash_count}\n")

        if r.crash_count == 0:
            w("\n")
            continue

        if r.time_to_first_s is not None:
            w(f"    time-to-first     : {r.time_to_first_s:.2f}s  (earliest crash)\n")
            w(f"    time-to-last      : {r.time_to_last_s:.2f}s\n")
        if r.execs_to_first is not None:
            w(f"    execs-to-first    : {r.execs_to_first:,}\n")

        if r.replay_binary is None:
            w("    (replay binary not found; skipping oracle bucketing)\n\n")
            continue

        w("    by oracle reason:\n")
        for reason, lst in sorted(r.by_reason.items(), key=lambda kv: -len(kv[1])):
            w(f"      [{len(lst):>3}] {reason}\n")
            for rec in lst[:3]:
                short = rec.name if len(rec.name) <= 48 else rec.name[:45] + "..."
                w(f"              offset={rec.offset} length={rec.length}  ({short})\n")
            if len(lst) > 3:
                w(f"              ... and {len(lst) - 3} more\n")
        w("\n")

    # Overview
    if results:
        w("=" * 60 + "\n")
        w("Overview\n")
        w("=" * 60 + "\n")
        w(f"{'target':<40} {'crashes':>8}  reasons\n")
        for r in results:
            if r.skipped_reason:
                continue
            reasons = ", ".join(
                f"{name}({len(lst)})" for name, lst in
                sorted(r.by_reason.items(), key=lambda kv: -len(kv[1]))
            )
            w(f"{r.target:<40} {r.crash_count:>8}  {reasons or '-'}\n")
    return buf.getvalue()


# ---------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------


EXPECTATION = {
    # target -> (expected_outcome, note)
    "stage2_afl_bad_validator":       ("crashes",    "weak validator rejects only offset bounds"),
    "stage2_afl_good_validator":      ("no crashes", "strict validator; calibration control"),
    "stage2_afl_length_only_indexed": ("crashes",    "length-only validator fails the indexed sink"),
    "stage2_afl_unchecked_indexed":   ("crashes",    "no validator; UNSAFE_unverified index model"),
    "stage2_afl_clamped_indexed":     ("no crashes", "clamp in copy_and_verify before indexed sink"),
    "stage2_afl_div_by_zero":         ("crashes",    "no validator on division sink"),
    "stage2_afl_div_by_zero_guarded": ("no crashes", "nonzero_validator rejects denominator==0"),
    "stage2_afl_four_sinks_one_bad":   ("crashes",    "3 good sink/val + 1 bad (mem); OOB on last"),
    "stage2_afl_four_sinks_all_good":  ("no crashes", "4 good sink/val pairs; mem uses good_validator"),
}


def render_markdown(results: list[CampaignResult]) -> str:
    buf = io.StringIO()
    w = buf.write

    w("# Stage 2 AFL++ Campaign Results\n\n")
    w("Generated by `scripts/report.py --format markdown`. Each row below ")
    w("was produced by replaying every saved crash through the matching ")
    w("non-AFL file-input reproducer (`stage2_<name>`), so the `oracle reason` ")
    w("is whatever the C++ oracle wrote to stderr on that input.\n\n")

    # ---- Headline verdict ----
    scored = [r for r in results
              if not r.skipped_reason and r.target in EXPECTATION]
    total_pairs = len(scored)
    verdicts_ok = 0
    for r in scored:
        expected, _ = EXPECTATION[r.target]
        if expected == "crashes" and r.crash_count > 0:
            verdicts_ok += 1
        elif expected == "no crashes" and r.crash_count == 0:
            verdicts_ok += 1
    if total_pairs > 0:
        w(f"**Calibration verdict: {verdicts_ok} / {total_pairs} targets matched ")
        w("expectation.** Crashing-validator targets are expected to find ")
        w("crashes within the budget; validator / mitigation controls are ")
        w("expected to find zero. Per-target budget: ")
        budgets = {r.stats.get("run_time") for r in scored if r.stats.get("run_time")}
        w(", ".join(fmt_duration(b) for b in sorted(budgets)) if budgets else "?")
        w(".\n\n")

    # ---- Headline table ----
    w("## Summary\n\n")
    w("| Target | Expected | Crashes | Time to first | Execs to first | Exec/s | Coverage | Verdict |\n")
    w("| --- | --- | ---: | ---: | ---: | ---: | ---: | :---: |\n")
    for r in results:
        if r.skipped_reason:
            w(f"| `{r.target}` | - | - | - | - | - | - | skipped ({r.skipped_reason}) |\n")
            continue
        expected, _ = EXPECTATION.get(r.target, ("-", ""))
        ttf = f"{r.time_to_first_s:.2f}s" if r.time_to_first_s is not None else "-"
        etf = f"{r.execs_to_first:,}" if r.execs_to_first is not None else "-"
        eps = r.stats.get("execs_per_sec", "?")
        cvg = r.stats.get("bitmap_cvg", "?")
        # Verdict: if we expected crashes and found >0, or expected none and found 0, it's "OK".
        if expected == "crashes":
            verdict = "OK" if r.crash_count > 0 else "MISS"
        elif expected == "no crashes":
            verdict = "OK" if r.crash_count == 0 else "FAIL"
        else:
            verdict = "-"
        w(f"| `{r.target}` | {expected} | {r.crash_count} | {ttf} | {etf} | {eps} | {cvg} | {verdict} |\n")
    w("\n")

    # ---- Crash-reason matrix ----
    all_reasons = sorted({reason for r in results for reason in r.by_reason.keys()})
    if all_reasons:
        w("## Crash reasons by target\n\n")
        w("| Target | " + " | ".join(f"`{x}`" for x in all_reasons) + " | total |\n")
        w("| --- | " + " | ".join("---:" for _ in all_reasons) + " | ---: |\n")
        for r in results:
            if r.skipped_reason:
                continue
            counts = [len(r.by_reason.get(reason, [])) for reason in all_reasons]
            if sum(counts) == 0 and r.crash_count == 0:
                continue
            row = " | ".join(str(c) if c > 0 else "-" for c in counts)
            w(f"| `{r.target}` | {row} | **{r.crash_count}** |\n")
        w("\n")

    # ---- Per-target detail ----
    w("## Per-campaign detail\n\n")
    for r in results:
        w(f"### `{r.target}`\n\n")
        if r.skipped_reason:
            w(f"*Skipped: {r.skipped_reason}*\n\n")
            continue

        expected, note = EXPECTATION.get(r.target, ("-", "-"))
        w(f"- Expectation: **{expected}** - {note}\n")

        stats = r.stats
        w(f"- Output dir: `{r.out_dir}`\n")
        w(f"- Run time: {fmt_duration(stats.get('run_time', ''))}\n")
        w(f"- Execs done: {fmt_int(stats.get('execs_done'))}  "
          f"(@ {stats.get('execs_per_sec', '?')} exec/s)\n")
        edges = stats.get("edges_found", "?")
        total = stats.get("total_edges", "?")
        cvg = stats.get("bitmap_cvg", "?")
        w(f"- Coverage: {edges} / {total} edges ({cvg})\n")
        w(f"- Stability: {stats.get('stability', '?')}\n")
        w(f"- Corpus count: {stats.get('corpus_count', '?')}\n")
        w(f"- Saved crashes: **{r.crash_count}**\n")

        if r.crash_count > 0:
            if r.time_to_first_s is not None:
                w(f"- Time to first / last crash: {r.time_to_first_s:.2f}s / {r.time_to_last_s:.2f}s\n")
            if r.execs_to_first is not None:
                w(f"- Execs to first crash: {r.execs_to_first:,}\n")

            if r.replay_binary is None:
                w("- *(replay binary not found; oracle reasons not bucketed)*\n\n")
                continue

            w("\n**Crashes by oracle reason:**\n\n")
            w("| Reason | Count | Example (offset, length) |\n")
            w("| --- | ---: | --- |\n")
            for reason, lst in sorted(r.by_reason.items(), key=lambda kv: -len(kv[1])):
                example = lst[0]
                w(f"| `{reason}` | {len(lst)} | "
                  f"({example.offset}, {example.length}) |\n")
            w("\n")
        else:
            w("\n")

    return buf.getvalue()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dirs", nargs="*", help="AFL output directories")
    ap.add_argument("--root", default=".", help="project root (default: cwd)")
    ap.add_argument("--format", choices=["text", "markdown"], default="text",
                    help="report format (default: text)")
    ap.add_argument("--output", type=Path, default=None,
                    help="write report to this file instead of stdout")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    os.chdir(root)

    if args.out_dirs:
        dirs = [Path(p) for p in args.out_dirs]
    else:
        dirs = discover_out_dirs(root)
        if not dirs:
            print("No out* directories with fuzzer_stats found.", file=sys.stderr)
            return 1

    results: list[CampaignResult] = []
    for d in dirs:
        if not d.exists():
            print(f"(skip) {d} not found", file=sys.stderr)
            continue
        results.append(collect_campaign(d))

    if args.format == "markdown":
        rendered = render_markdown(results)
    else:
        rendered = render_text(results)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"[report] wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
