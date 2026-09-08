#!/usr/bin/env python3
"""Measure fresh IDA autoanalysis time for one binary using idalib.

The script deliberately opens the input with autoanalysis paused, matching the
ida-codemode managed-worker path, and then times ``ida_auto.auto_wait()``
separately from database loading.

Examples:
    uv run python scripts/measure_autoanalysis.py tests/crackme03.elf
    uv run python scripts/measure_autoanalysis.py C:\\path\\to\\large.dll --json
    uv run python scripts/measure_autoanalysis.py ./large.bin \
        --keep-database ./measurements/large.i64
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        type=Path,
        help="Binary to load into a fresh temporary IDA database",
    )
    parser.add_argument(
        "--keep-database",
        type=Path,
        metavar="PATH",
        help=(
            "save the analyzed database at PATH instead of deleting the temporary "
            "database (PATH must not already exist)"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the final result as a single JSON object after the summary",
    )
    return parser


def _normalize_idausr() -> None:
    """Apply the same idapro IDAUSR workaround as the managed worker."""
    idausr = os.environ.get("IDAUSR")
    if not idausr:
        return
    primary = idausr.split(os.pathsep, 1)[0]
    if primary:
        os.environ["IDAUSR"] = primary


def _phase(message: str) -> None:
    print(message, flush=True)


def _seconds(value: float) -> str:
    return f"{value:.3f}s"


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    try:
        input_path = args.binary.expanduser().resolve(strict=True)
    except FileNotFoundError:
        parser.error(f"binary does not exist: {args.binary}")
    if not input_path.is_file():
        parser.error(f"binary is not a regular file: {input_path}")

    kept_database: Path | None = None
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    if args.keep_database is not None:
        kept_database = args.keep_database.expanduser().resolve()
        if kept_database.exists():
            parser.error(f"database already exists: {kept_database}")
        kept_database.parent.mkdir(parents=True, exist_ok=True)
        output_database = kept_database
    else:
        temporary_directory = tempfile.TemporaryDirectory(prefix="ida-autoanalysis-")
        output_database = Path(temporary_directory.name) / f"{input_path.name}.i64"

    _normalize_idausr()
    input_size = input_path.stat().st_size
    _phase(f"Input: {input_path}")
    _phase(f"Input size: {input_size:,} bytes")
    _phase(f"Fresh database: {output_database}")

    database: Any | None = None
    result: dict[str, Any] | None = None
    started = time.perf_counter()
    try:
        _phase("Initializing idalib...")
        initialization_started = time.perf_counter()

        # Importing ida_domain initializes idapro and makes IDAPython modules
        # available. Keep these imports here so initialization has its own
        # measurement and IDAUSR is normalized first.
        from ida_domain import Database
        from ida_domain.database import IdaCommandOptions

        ida_auto = importlib.import_module("ida_auto")
        ida_funcs = importlib.import_module("ida_funcs")

        initialization_seconds = time.perf_counter() - initialization_started
        _phase(f"idalib initialized in {_seconds(initialization_seconds)}")

        options = IdaCommandOptions(
            auto_analysis=False,
            new_database=True,
            output_database=str(output_database),
        )

        _phase("Opening a fresh database with autoanalysis paused...")
        open_started = time.perf_counter()
        database = Database.open(
            str(input_path),
            args=options,
            save_on_close=kept_database is not None,
        )
        open_seconds = time.perf_counter() - open_started
        _phase(f"Database opened in {_seconds(open_seconds)}")

        initially_complete = bool(ida_auto.auto_is_ok())
        _phase(
            "Running autoanalysis to completion..."
            if not initially_complete
            else "Autoanalysis queues were already complete; confirming completion..."
        )
        analysis_started = time.perf_counter()
        previously_enabled = bool(ida_auto.enable_auto(True))
        try:
            wait_completed = bool(ida_auto.auto_wait())
        finally:
            if not previously_enabled:
                ida_auto.enable_auto(False)
        analysis_seconds = time.perf_counter() - analysis_started
        analysis_ok = bool(ida_auto.auto_is_ok())
        total_seconds = time.perf_counter() - started
        function_count = int(ida_funcs.get_func_qty())

        result = {
            "input": str(input_path),
            "input_size_bytes": input_size,
            "database": str(output_database),
            "database_kept": kept_database is not None,
            "initially_complete": initially_complete,
            "wait_completed": wait_completed,
            "autoanalysis_ok": analysis_ok,
            "function_count": function_count,
            "idalib_initialization_seconds": initialization_seconds,
            "database_open_seconds": open_seconds,
            "autoanalysis_seconds": analysis_seconds,
            "open_and_autoanalysis_seconds": open_seconds + analysis_seconds,
            "total_seconds": total_seconds,
        }

        print()
        print("Autoanalysis measurement")
        print("------------------------")
        print(f"idalib initialization:  {_seconds(initialization_seconds)}")
        print(f"database open:          {_seconds(open_seconds)}")
        print(f"autoanalysis wait:      {_seconds(analysis_seconds)}")
        print(f"open + autoanalysis:    {_seconds(open_seconds + analysis_seconds)}")
        print(f"total measured time:    {_seconds(total_seconds)}")
        print(f"functions discovered:   {function_count:,}")
        print(f"autoanalysis complete:  {wait_completed and analysis_ok}")

        return_code = 0 if wait_completed and analysis_ok else 2
    except KeyboardInterrupt:
        print("\nMeasurement interrupted.", file=sys.stderr, flush=True)
        return_code = 130
    except Exception as error:  # noqa: BLE001 - IDA may raise arbitrary exceptions
        print(
            f"Autoanalysis measurement failed: {type(error).__name__}: {error}",
            file=sys.stderr,
            flush=True,
        )
        return_code = 1
    finally:
        if database is not None:
            try:
                database.close(save=kept_database is not None)
            except Exception as error:  # noqa: BLE001 - best-effort IDA cleanup
                print(
                    f"Failed to close the database: {type(error).__name__}: {error}",
                    file=sys.stderr,
                    flush=True,
                )
                if result is not None:
                    result["close_error"] = f"{type(error).__name__}: {error}"
                if return_code == 0:
                    return_code = 1
        if temporary_directory is not None:
            temporary_directory.cleanup()

    if args.json and result is not None:
        print(json.dumps(result, sort_keys=True), flush=True)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
