import argparse
import codeop
import json
import os
import sys

from ida_nexus import DatabaseHandle, NexusError, RemoteError, RemoteExecutor

try:
    import readline  # noqa: F401  -- enables line editing in input()
except ImportError:
    pass


def exec(
    handle: RemoteExecutor,
    code: str,
    filename: str,
    json_mode: bool,
    *,
    operation_label: str,
    flush_database: bool = False,
) -> bool:
    try:
        result = handle.execute_python(
            code,
            operation_label=operation_label,
            persist_globals=True,
            filename=filename,
            flush_database=flush_database,
        )
    except RemoteError as e:
        if stdout := e.details.get("stdout"):
            sys.stdout.write(stdout)
            sys.stdout.flush()

        if stderr := e.details.get("stderr"):
            sys.stderr.write(stderr)
            sys.stderr.flush()

        if "exit_code" in e.details:
            raise SystemExit(e.details["exit_code"])

        if traceback := e.details.get("traceback"):
            print(traceback, file=sys.stderr)
        else:
            print(f"{type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return False
    except NexusError as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return False

    if stdout := result["stdout"]:
        stream = sys.stderr if json_mode else sys.stdout
        stream.write(stdout)
        stream.flush()

    if stderr := result["stderr"]:
        sys.stderr.write(stderr)
        sys.stderr.flush()

    obj = result["result"]
    if json_mode:
        print(json.dumps(obj))
    elif obj is not None:
        print(repr(obj))
    return True


def repl(handle: RemoteExecutor, *, flush_database: bool = False) -> None:
    compiler, buf = codeop.CommandCompiler(), []
    interactive = sys.stdin.isatty()
    operation_label = "REPL: interactive" if interactive else "REPL: stdin"
    while True:
        try:
            prompt = ("... " if buf else ">>> ") if interactive else ""
            buf.append(input(prompt))
        except (EOFError, KeyboardInterrupt):
            if interactive:
                print()
            return
        try:
            if compiler("\n".join(buf), "<repl>", "single") is None:
                continue  # incomplete block
        except SyntaxError as e:
            print(f"{type(e).__name__}: {e}", file=sys.stderr)
            buf.clear()
            continue
        code, buf = "\n".join(buf), []
        if code:
            exec(
                handle,
                code,
                "<stdin>",
                json_mode=False,
                operation_label=operation_label,
                flush_database=flush_database,
            )


def _script_operation_label(filename: str) -> str:
    prefix = "REPL: script "
    available = 1024 - len(prefix)
    if len(filename) > available:
        filename = f"…{filename[-(available - 1) :]}"
    return f"{prefix}{filename}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-nexus exec",
        description="Execute Python script or command in the context of an IDA database.",
    )
    parser.add_argument(
        "path",
        help="Path to the IDB/executable to run script against.",
    )
    parser.add_argument(
        "script",
        help="Path to the Python script to run.",
        nargs="?",
    )
    parser.add_argument(
        "-c",
        metavar="cmd",
        help="Python command or snippet to execute in the database context.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output only JSON to stdout."
    )
    parser.add_argument(
        "--flush-database",
        action="store_true",
        help="flush unpacked IDB buffers before each Python execution",
    )
    args = parser.parse_args(argv)

    with DatabaseHandle.open(args.path) as handle:
        if args.c:
            code = args.c
            filename = "<string>"
            operation_label = "REPL: command"
        elif args.script:
            filename = os.path.abspath(args.script)
            with open(filename, "r") as f:
                code = f.read()
            operation_label = _script_operation_label(filename)
        else:
            repl(handle, flush_database=args.flush_database)
            return 0

        if not exec(
            handle,
            code,
            filename,
            args.json,
            operation_label=operation_label,
            flush_database=args.flush_database,
        ):
            return 1
    return 0


if __name__ == "__main__":
    main()
