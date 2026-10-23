"""Host selection and IDA command lines, without starting IDA."""

import json
import os
from pathlib import Path

import pytest

from ida_nexus import paths
from ida_nexus._launch import (
    WorkerLaunchOptions,
    ida_command,
    ida_environment,
    ida_switches,
    join_ida_switches,
    quote_ida_argument,
    script_switch,
    select_backend,
    worker_command,
)
from ida_nexus.errors import DatabaseOpenError


@pytest.fixture
def ida_home(tmp_path, monkeypatch):
    """A private IDAUSR with an ida-config.json naming a fake installation."""
    idausr = tmp_path / "idausr"
    install = tmp_path / "IDA Professional 9.5"
    idausr.mkdir()
    install.mkdir()
    (idausr / "ida-config.json").write_text(
        json.dumps({"Version": 1, "Paths": {"ida-install-dir": str(install)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("IDAUSR", str(idausr))
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.delenv("IDA_NEXUS_IDALIB_ONLY", raising=False)
    return idausr, install


def install_plugin(idausr: Path, name: str = "ida-mcp") -> None:
    plugin = idausr / "plugins" / name
    plugin.mkdir(parents=True)
    (plugin / "ida-plugin.json").write_text("{}", encoding="utf-8")


# ----------------------------------------------------------------- discovery


def test_install_dir_comes_from_idadir_or_ida_config(ida_home, monkeypatch):
    _idausr, install = ida_home
    assert paths.find_ida_install_dir() == install
    monkeypatch.setenv("IDADIR", str(install / "elsewhere"))
    assert paths.find_ida_install_dir() == install / "elsewhere"


def test_missing_or_broken_config_means_no_installation(ida_home):
    idausr, _install = ida_home
    (idausr / "ida-config.json").write_text("not json", encoding="utf-8")
    assert paths.find_ida_install_dir() is None
    (idausr / "ida-config.json").unlink()
    assert paths.find_ida_install_dir() is None
    assert paths.find_ida_executable("idat") is None


@pytest.mark.parametrize(
    "layout",
    [("idat.exe",), ("idat",), ("Contents", "MacOS", "idat")],
    ids=["windows", "linux", "macos-bundle"],
)
def test_executables_are_found_in_every_platform_layout(ida_home, layout):
    _idausr, install = ida_home
    executable = install.joinpath(*layout)
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"")
    assert paths.find_ida_executable("idat") == executable
    assert paths.find_ida_executable("ida") is None


def test_plugin_is_found_in_any_idausr_entry(ida_home, tmp_path, monkeypatch):
    idausr, _install = ida_home
    assert paths.nexus_plugin_installed() is False
    second = tmp_path / "second"
    install_plugin(second, "ida-nexus")
    monkeypatch.setenv("IDAUSR", f"{idausr}{os.pathsep}{second}")
    assert paths.nexus_plugin_installed() is True
    # The primary directory still decides where ida-config.json lives.
    assert paths.find_ida_install_dir() == tmp_path / "IDA Professional 9.5"


@pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
def test_idalib_only_accepts_the_usual_truthy_spellings(monkeypatch, value):
    monkeypatch.setenv("IDA_NEXUS_IDALIB_ONLY", value)
    assert paths.idalib_only() is True
    monkeypatch.setenv("IDA_NEXUS_IDALIB_ONLY", "0")
    assert paths.idalib_only() is False


# ------------------------------------------------------------ host selection


def test_without_the_plugin_workers_stay_in_idalib(ida_home):
    assert select_backend(gui=False) == ("idalib", None)
    with pytest.raises(DatabaseOpenError, match="hcli plugin install"):
        select_backend(gui=True)


def test_with_the_plugin_idat_is_preferred_and_ida_opens_the_gui(ida_home):
    idausr, install = ida_home
    install_plugin(idausr)
    (install / "idat").write_bytes(b"")
    (install / "ida").write_bytes(b"")
    assert select_backend(gui=False) == ("idat", str(install / "idat"))
    assert select_backend(gui=True) == ("gui", str(install / "ida"))


def test_plugin_without_executables_fails_instead_of_falling_back(ida_home):
    idausr, _install = ida_home
    install_plugin(idausr)
    with pytest.raises(DatabaseOpenError, match="IDA_NEXUS_IDALIB_ONLY"):
        select_backend(gui=False)
    with pytest.raises(DatabaseOpenError, match="not found"):
        select_backend(gui=True)


def test_idalib_only_overrides_the_plugin_and_refuses_the_gui(ida_home, monkeypatch):
    idausr, install = ida_home
    install_plugin(idausr)
    (install / "idat").write_bytes(b"")
    (install / "ida").write_bytes(b"")
    monkeypatch.setenv("IDA_NEXUS_IDALIB_ONLY", "1")
    assert select_backend(gui=False) == ("idalib", None)
    with pytest.raises(DatabaseOpenError, match="IDA_NEXUS_IDALIB_ONLY"):
        select_backend(gui=True)


# --------------------------------------------------------------- switches


def test_switches_cover_every_import_option():
    options = WorkerLaunchOptions(
        image_base=0x8000,
        new_database=True,
        compiler="gcc:sysv",
        first_pass_directives=("A=1",),
        second_pass_directives=("B=2",),
        disable_fpp=True,
        entry_point=0x8010,
        jit_debugger=True,
        log_file="ida.log",
        disable_mouse=True,
        plugin_options="x:y",
        processor="arm",
        db_compression="pack",
        run_debugger="linux",
        load_resources=True,
        file_type="ZIP",
        file_member="inner.bin",
        empty_database=True,
        windows_dir="win",
        no_segmentation=True,
        debug_flags=("ldr", "debugger", "ldr"),
    )
    assert ida_switches(options, output_database="out.i64", defer_analysis=True) == [
        "-a",
        "-b800",
        "-c",
        "-Cgcc:sysv",
        "-dA=1",
        "-DB=2",
        "-f",
        "-i8010",
        "-I1",
        "-Lida.log",
        "-M",
        "-oout.i64",
        "-Ox:y",
        "-parm",
        "-P",
        "-rlinux",
        "-R",
        "-TZIP:inner.bin",
        "-t",
        "-Wwin",
        "-x",
        "-z10010",
    ]


def test_analysis_switch_depends_on_host_and_policy():
    on = WorkerLaunchOptions(auto_analysis=True, load_resources=False)
    off = WorkerLaunchOptions(auto_analysis=False, load_resources=False)
    # Headless hosts defer analysis so the server can publish first.
    assert ida_switches(on, output_database=None, defer_analysis=True) == ["-a"]
    # The GUI analyzes in its own event loop unless analysis was turned off.
    assert ida_switches(on, output_database=None, defer_analysis=False) == []
    assert ida_switches(off, output_database=None, defer_analysis=False) == ["-a"]


def test_compression_names_match_idas_switches():
    for name, switch in (("compress", "-P+"), ("pack", "-P"), ("no_pack", "-P-")):
        options = WorkerLaunchOptions(db_compression=name, load_resources=False)
        assert ida_switches(options, output_database=None, defer_analysis=False) == [
            switch
        ]


def test_unknown_debug_flags_and_bad_values_are_rejected_early():
    with pytest.raises(ValueError, match="unknown debug flags"):
        WorkerLaunchOptions(debug_flags=("ldr", "bogus"))
    with pytest.raises(ValueError, match="16-byte"):
        WorkerLaunchOptions(image_base=0x8001)
    with pytest.raises(ValueError, match="file_member"):
        WorkerLaunchOptions(file_member="x")


# --------------------------------------------------------------- quoting


def test_quoting_follows_idas_own_splitter():
    assert quote_ida_argument("-a") == "-a"
    assert quote_ida_argument(r"-oC:\plain\x.i64") == r"-oC:\plain\x.i64"
    # ida-domain's form: the switch letter stays outside the quotes.
    assert quote_ida_argument(r"-oC:\my files\x.i64") == r'-o"C:\my files\x.i64"'
    assert quote_ida_argument("two words") == '"two words"'
    assert quote_ida_argument('say "hi" now') == r'"say \"hi\" now"'
    assert quote_ida_argument("ends with\\ ") == '"ends with\\ "'
    assert join_ida_switches(["-a", r"-LC:\log dir\ida.log", "-R"]) == (
        r'-a -L"C:\log dir\ida.log" -R'
    )


def test_script_switch_is_one_argv_element_with_quoted_tokens():
    switch = script_switch(r"C:\my tools\boot.py", ["--record-suffix", "abcdef"])
    assert switch == r'-S"C:\my tools\boot.py" --record-suffix abcdef'
    assert script_switch("/opt/nexus/boot.py", []) == "-S/opt/nexus/boot.py"


# --------------------------------------------------------------- commands


def test_worker_command_separates_lifecycle_from_ida_switches(tmp_path):
    source = tmp_path / "a.bin"
    source.write_bytes(b"x")
    command = worker_command(
        "ida-nexus",
        str(source),
        str(tmp_path / "a.bin.i64"),
        20.0,
        WorkerLaunchOptions(),
        record_suffix="abcdef",
    )
    assert command == [
        "ida-nexus",
        "worker",
        str(source),
        "--record-suffix",
        "abcdef",
        "--lease-grace",
        "20.0",
        "--managed",
        "--auto-analysis",
        "--",
        "-a",
        "-R",
    ]


def test_idat_command_is_autonomous_logged_and_managed(tmp_path):
    source = tmp_path / "a.bin"
    source.write_bytes(b"x")
    log = tmp_path / "logs" / "abcdef.log"
    command = ida_command(
        "/opt/ida/idat",
        "idat",
        str(source),
        str(tmp_path / "a.bin.i64"),
        20.0,
        WorkerLaunchOptions(),
        record_suffix="abcdef",
        log_path=log,
        bootstrap="/opt/nexus/boot.py",
    )
    assert command == [
        "/opt/ida/idat",
        "-A",
        f"-L{log}",
        (
            "-S/opt/nexus/boot.py --record-suffix abcdef --lease-grace 20.0 "
            "--managed --auto-analysis"
        ),
        "-a",
        "-R",
        str(source),
    ]


def test_gui_command_is_unmanaged_and_lets_ida_analyze(tmp_path):
    source = tmp_path / "a.bin"
    source.write_bytes(b"x")
    command = ida_command(
        "/opt/ida/ida",
        "gui",
        str(source),
        str(tmp_path / "a.bin.i64"),
        20.0,
        WorkerLaunchOptions(log_file="/tmp/mine.log"),
        record_suffix="abcdef",
        log_path=tmp_path / "unused.log",
        bootstrap="/opt/nexus/boot.py",
    )
    assert command == [
        "/opt/ida/ida",
        "-A",
        "-S/opt/nexus/boot.py --record-suffix abcdef --lease-grace 20.0 --auto-analysis",
        "-L/tmp/mine.log",
        "-R",
        str(source),
    ]


def test_existing_idb_is_reopened_without_import_switches_on_every_host(tmp_path):
    source = tmp_path / "a.bin"
    idb = tmp_path / "a.bin.i64"
    source.write_bytes(b"x")
    idb.write_bytes(b"db")
    options = WorkerLaunchOptions(processor="arm", image_base=0x1000)
    worker = worker_command(
        "ida-nexus", str(source), str(idb), 20.0, options, record_suffix="abcdef"
    )
    assert worker[2] == str(idb)
    assert worker[worker.index("--") + 1 :] == ["-a"]
    idat = ida_command(
        "idat",
        "idat",
        str(source),
        str(idb),
        20.0,
        options,
        record_suffix="abcdef",
        log_path=tmp_path / "l.log",
        bootstrap="b.py",
    )
    assert idat[-2:] == ["-a", str(idb)]


# ------------------------------------------------------------ environment


def test_ida_environment_drops_the_clients_virtualenv(tmp_path):
    venv = tmp_path / ".venv"
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = somewhere", encoding="utf-8")
    plain = tmp_path / "tools"
    plain.mkdir()
    base = {
        "VIRTUAL_ENV": str(venv),
        "PYTHONHOME": "/client/python3.11",
        "PATH": os.pathsep.join([str(scripts), str(plain), ""]),
        "IDAPYTHON_VENV_EXECUTABLE": "/ida/venv/bin/python",
        "HOME": "/home/me",
    }
    environment = ida_environment(base)
    assert "VIRTUAL_ENV" not in environment
    assert "PYTHONHOME" not in environment
    assert environment["PATH"] == os.pathsep.join([str(plain), ""])
    # IDA's own, documented venv binding is the operator's choice.
    assert environment["IDAPYTHON_VENV_EXECUTABLE"] == "/ida/venv/bin/python"
    assert environment["HOME"] == "/home/me"
    assert base["PATH"].startswith(str(scripts)), "the caller's mapping is untouched"
    assert base["PYTHONHOME"] == "/client/python3.11"
