import json
from pathlib import Path

from ida_nexus.cli.worker import _log_database_state


def test_worker_diagnostics_record_file_state_without_contents(tmp_path, capsys):
    path = tmp_path / "sample.i64"
    path.write_bytes(b"private database contents")
    _log_database_state("database.open_started", path, ida_version=(9, 4, 1))
    output = capsys.readouterr().out
    record = json.loads(output.removeprefix("[ida-nexus] "))
    assert record["size"] == path.stat().st_size
    assert record["modified_ns"] == path.stat().st_mtime_ns
    assert record["ida_version"] == [9, 4, 1]
    assert "private database contents" not in output


def test_worker_diagnostics_do_not_mask_a_missing_file(tmp_path, capsys):
    path = Path(tmp_path) / "missing.i64"
    _log_database_state("database.worker_failed", path, phase="opening")
    record = json.loads(capsys.readouterr().out.removeprefix("[ida-nexus] "))
    assert record["phase"] == "opening"
    assert record["stat_error"]
