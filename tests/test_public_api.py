import importlib.util
import tomllib
from pathlib import Path

import ida_nexus


def test_public_api_is_explicit_and_importable() -> None:
    assert ida_nexus.__all__ == sorted(ida_nexus.__all__)
    assert len(ida_nexus.__all__) == len(set(ida_nexus.__all__))
    for name in ida_nexus.__all__:
        assert getattr(ida_nexus, name) is not None


def test_wheel_includes_every_console_script_module() -> None:
    project_root = Path(__file__).parents[1]
    with (project_root / "pyproject.toml").open("rb") as file:
        config = tomllib.load(file)

    scripts = config["project"]["scripts"]
    assert scripts == {"ida-nexus": "ida_nexus.cli:main"}

    included = set(config["tool"]["hatch"]["build"]["targets"]["wheel"]["only-include"])
    for script, target in scripts.items():
        module = target.partition(":")[0]
        root_module = module.partition(".")[0]
        assert root_module in included or f"{root_module}.py" in included, (
            f"wheel omits module {module!r} required by console script {script!r}"
        )


def test_removed_public_looking_implementation_modules_are_gone() -> None:
    for module in (
        "ida_nexus_dashboard",
        "ida_nexus_exec",
        "ida_nexus_mcp",
        "ida_nexus.mcp",
        "ida_nexus.cli.dashboard",
        "ida_nexus.cli.logs",
        "ida_nexus.cli.mcp",
        "ida_nexus.client",
        "ida_nexus.database",
        "ida_nexus.http",
        "ida_nexus.registry",
        "ida_nexus.resolver",
        "ida_nexus.runtime",
        "ida_nexus.serialization",
        "ida_nexus.server",
    ):
        assert importlib.util.find_spec(module) is None
