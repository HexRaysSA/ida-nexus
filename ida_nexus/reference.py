"""MVP API reference function, needs to be improved"""

import argparse
import ast
import importlib.metadata
import importlib.util
import math
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REFERENCE_SPEC_CACHE: dict[str, Any] | None = None


def _signature_from_function_node(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    def fmt_annotation(annotation: ast.AST | None) -> str:
        return ast.unparse(annotation) if annotation is not None else ""

    def fmt_default(default: ast.AST | None) -> str:
        return f" = {ast.unparse(default)}" if default is not None else ""

    parts: list[str] = []
    posonly = list(node.args.posonlyargs)
    regular = list(node.args.args)
    positional = posonly + regular
    positional_defaults = [None] * (len(positional) - len(node.args.defaults)) + list(
        node.args.defaults
    )

    for index, arg in enumerate(positional):
        part = arg.arg
        annotation = fmt_annotation(arg.annotation)
        if annotation:
            part += f": {annotation}"
        part += fmt_default(positional_defaults[index])
        parts.append(part)
        if posonly and index == len(posonly) - 1:
            parts.append("/")

    if node.args.vararg is not None:
        part = f"*{node.args.vararg.arg}"
        annotation = fmt_annotation(node.args.vararg.annotation)
        if annotation:
            part += f": {annotation}"
        parts.append(part)
    elif node.args.kwonlyargs:
        parts.append("*")

    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        part = arg.arg
        annotation = fmt_annotation(arg.annotation)
        if annotation:
            part += f": {annotation}"
        part += fmt_default(default)
        parts.append(part)

    if node.args.kwarg is not None:
        part = f"**{node.args.kwarg.arg}"
        annotation = fmt_annotation(node.args.kwarg.annotation)
        if annotation:
            part += f": {annotation}"
        parts.append(part)

    return_annotation = fmt_annotation(node.returns)
    signature = f"({', '.join(parts)})"
    if return_annotation:
        signature += f" -> {return_annotation}"
    return signature


def _module_name_for(path: Path, package_root: Path) -> str:
    relative = path.relative_to(package_root.parent).with_suffix("")
    return ".".join(relative.parts)


def _relative_path(path: Path, source_root: Path) -> str:
    try:
        return str(path.relative_to(source_root))
    except ValueError:
        return str(path)


def _public_or_private(name: str) -> str:
    return "private" if name.startswith("_") else "public"


def _find_ida_domain_package_path() -> Path:
    spec = importlib.util.find_spec("ida_domain")
    if spec is None or spec.origin is None:
        raise FileNotFoundError("Installed ida-domain package not found")
    return Path(spec.origin).resolve().parent


def _find_ida_domain_examples_path() -> Path | None:
    """Locate the ida-domain examples directory.

    Mirrors ``ida_domain.examples_path()`` without importing the package (an
    import triggers ``_load_dependencies()`` -> ``idapro``/``ida_kernwin``, which
    are unavailable in the MCP server process). Packaged installs ship the
    examples under ``ida_domain/_examples``; editable/source checkouts fall back
    to the repository's top-level ``examples`` directory.
    """
    package_root = _find_ida_domain_package_path()
    packaged_examples = package_root / "_examples"
    if packaged_examples.is_dir():
        return packaged_examples

    checkout_examples = package_root.parent / "examples"
    if checkout_examples.is_dir():
        return checkout_examples

    return None


def get_ida_domain_version() -> str:
    return importlib.metadata.version("ida-domain")


def _build_reference_spec() -> dict[str, Any]:
    global _REFERENCE_SPEC_CACHE
    if _REFERENCE_SPEC_CACHE is not None:
        return _REFERENCE_SPEC_CACHE

    package_root = _find_ida_domain_package_path()
    source_root = package_root.parent

    entries: list[dict[str, Any]] = []

    for path in sorted(package_root.rglob("*.py")):
        if "__pycache__" in path.parts or "_examples" in path.parts:
            continue

        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        module_name = _module_name_for(path, package_root)
        module_doc = ast.get_docstring(tree) or ""
        entries.append(
            {
                "kind": "module",
                "name": module_name,
                "qualname": module_name,
                "module": module_name,
                "file": _relative_path(path, source_root),
                "line": 1,
                "doc": module_doc,
                "visibility": _public_or_private(path.stem),
            }
        )

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_info = {
                    "kind": "function",
                    "module": module_name,
                    "name": node.name,
                    "qualname": f"{module_name}.{node.name}",
                    "signature": _signature_from_function_node(node),
                    "decorators": [ast.unparse(item) for item in node.decorator_list],
                    "file": _relative_path(path, source_root),
                    "line": node.lineno,
                    "doc": ast.get_docstring(node) or "",
                    "visibility": _public_or_private(node.name),
                    "async": isinstance(node, ast.AsyncFunctionDef),
                }
                entries.append(function_info)
                continue

            if isinstance(node, ast.ClassDef):
                class_info: dict[str, Any] = {
                    "kind": "class",
                    "module": module_name,
                    "name": node.name,
                    "qualname": f"{module_name}.{node.name}",
                    "bases": [ast.unparse(base) for base in node.bases],
                    "file": _relative_path(path, source_root),
                    "line": node.lineno,
                    "doc": ast.get_docstring(node) or "",
                    "visibility": _public_or_private(node.name),
                }
                entries.append(class_info)

                for child in node.body:
                    if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    method_info = {
                        "kind": "method",
                        "module": module_name,
                        "class": node.name,
                        "name": child.name,
                        "qualname": f"{module_name}.{node.name}.{child.name}",
                        "signature": _signature_from_function_node(child),
                        "decorators": [
                            ast.unparse(item) for item in child.decorator_list
                        ],
                        "file": _relative_path(path, source_root),
                        "line": child.lineno,
                        "doc": ast.get_docstring(child) or "",
                        "visibility": _public_or_private(child.name),
                        "async": isinstance(child, ast.AsyncFunctionDef),
                    }
                    entries.append(method_info)

    examples: list[dict[str, Any]] = []
    examples_root = _find_ida_domain_examples_path()
    if examples_root is not None:
        for path in sorted(examples_root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            doc = ast.get_docstring(tree) or ""
            relative = path.relative_to(examples_root)
            examples.append(
                {
                    "path": relative.as_posix(),
                    "name": relative.with_suffix("").as_posix(),
                    "doc": doc,
                    "content": source,
                }
            )

    _REFERENCE_SPEC_CACHE = {
        "version": get_ida_domain_version(),
        "entries": entries,
        "examples": examples,
        "entry_index": _ReferenceIndex.build(
            [
                entry
                for entry in entries
                if entry.get("visibility") == "public"
                and "._docs." not in entry["qualname"]
                and "._examples." not in entry["qualname"]
            ]
        ),
        "example_index": _ReferenceIndex.build(examples),
    }
    return _REFERENCE_SPEC_CACHE


def _reference_tokens(query: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9_]+", query.casefold())
    stopwords = {
        "a",
        "an",
        "and",
        "do",
        "for",
        "from",
        "how",
        "i",
        "ida",
        "in",
        "of",
        "the",
        "to",
        "with",
    }
    return [token for token in tokens if token not in stopwords]


@dataclass
class _BM25Field:
    """Cached BM25 statistics for one field, using k1=1.2 and b=0.75."""

    frequencies: list[Counter[str]]
    length_norms: list[float]
    idf: dict[str, float]

    @classmethod
    def build(cls, texts: Sequence[str]) -> "_BM25Field":
        frequencies = [Counter(_reference_tokens(text)) for text in texts]
        document_frequency: Counter[str] = Counter()
        for frequency in frequencies:
            document_frequency.update(frequency.keys())
        count = len(frequencies)
        lengths = [sum(frequency.values()) for frequency in frequencies]
        average_length = sum(lengths) / count if count else 0
        return cls(
            frequencies=frequencies,
            length_norms=[
                1.2 * (0.25 + 0.75 * length / average_length) if average_length else 1.2
                for length in lengths
            ],
            idf={
                term: math.log1p((count - frequency + 0.5) / (frequency + 0.5))
                for term, frequency in document_frequency.items()
            },
        )

    def score(self, document: int, terms: set[str]) -> float:
        frequency = self.frequencies[document]
        norm = self.length_norms[document]
        return math.fsum(
            self.idf[term] * frequency[term] * 2.2 / (frequency[term] + norm)
            for term in terms
            if frequency[term]
        )


@dataclass
class _ReferenceIndex:
    items: list[dict[str, Any]]
    names: _BM25Field
    docs: _BM25Field

    @classmethod
    def build(cls, items: list[dict[str, Any]]) -> "_ReferenceIndex":
        return cls(
            items=items,
            names=_BM25Field.build(
                [item.get("qualname", item["name"]) for item in items]
            ),
            docs=_BM25Field.build([item.get("doc", "") for item in items]),
        )

    def search(self, query: str) -> list[dict[str, Any]]:
        terms = set(_reference_tokens(query))
        matches = []
        for index, item in enumerate(self.items):
            name = item.get("qualname", item["name"])
            # Weight symbol matches more strongly; each field has its own
            # length normalization so long docstrings cannot dilute names.
            score = 2 * self.names.score(index, terms) + self.docs.score(index, terms)
            if score > 0:
                matches.append((score, name, item))
        matches.sort(key=lambda match: (-match[0], match[1]))
        return [item for _, _, item in matches]


def _format_reference_entry(entry: dict[str, Any]) -> str:
    decorators = entry.get("decorators", [])
    prefix = "".join(f"@{decorator}\n" for decorator in decorators)
    signature = entry.get("signature", "")
    heading = f"{entry['kind']} {entry['qualname']}{signature}"
    doc = str(entry.get("doc", "")).strip()
    location = f"{entry['file']}:{entry['line']}"
    return f"{prefix}{heading}\n{doc}\nSource: {location}".strip()


def reference(query: str) -> str:
    query = query.strip()
    if not query:
        raise ValueError("reference query must not be empty")

    spec = _build_reference_spec()
    entries = spec["entry_index"].search(query)
    examples = spec["example_index"].search(query)

    sections = [
        f"IDA Domain API reference {spec['version']}",
        f"Query: {query}",
    ]
    if entries:
        sections.append(
            "API entries:\n\n"
            + "\n\n---\n\n".join(
                _format_reference_entry(entry) for entry in entries[:20]
            )
        )
    if examples:
        sections.append(
            "Examples:\n\n"
            + "\n\n---\n\n".join(
                f"Example: {example['name']} ({example['path']})\n"
                f"```python\n{example['content'].rstrip()}\n```"
                for example in examples[:1]
            )
        )
    if not entries and not examples:
        sections.append(
            "No matching public API entries or examples were found. "
            "Try a class, method, or concept such as functions, strings, imports, or xrefs."
        )
    return "\n\n".join(sections)


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-nexus reference",
        description="Look up the active ida-domain API reference.",
    )
    parser.add_argument(
        "query",
        nargs="+",
        help="Class, method, or reverse-engineering concept to look up.",
    )
    args = parser.parse_args(argv)

    print(reference(" ".join(args.query)))
    return 0
