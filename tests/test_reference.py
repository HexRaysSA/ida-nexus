"""Search regressions assert the public reference output agents actually see."""

import importlib
import json
import re
from pathlib import Path

import pytest

reference_module = importlib.import_module("ida_nexus.reference")


def result_names(query: str) -> list[str]:
    return re.findall(
        r"^(?:method|class|function|module) ([\w.]+)",
        reference_module.reference(query).split("\n\nExamples:\n\n", 1)[0],
        re.MULTILINE,
    )


# These task groups were extracted from 14 Flare-On transcript queries against
# ida-domain 0.5.1. Counts measure API-list coverage, excluding bundled examples.
TRANSCRIPT_QUERIES = json.loads(
    (Path(__file__).parent / "fixtures" / "reference_queries.json").read_text()
)


@pytest.mark.parametrize("case", TRANSCRIPT_QUERIES, ids=lambda case: case["query"])
def test_transcript_task_coverage(case: dict) -> None:
    names = result_names(case["query"])
    for limit in (5, 20):
        covered = sum(
            bool(set(group).intersection(names[:limit]))
            for group in case["target_groups"]
        )
        assert covered >= case[f"min_top{limit}"]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Names.get_at", "ida_domain.names.Names.get_at"),
        ("ida_domain.names.Names.get_at", "ida_domain.names.Names.get_at"),
        ("Xrefs.to_ea", "ida_domain.xrefs.Xrefs.to_ea"),
        ("read bytes at address", "ida_domain.bytes.Bytes.get_bytes_at"),
    ],
)
def test_installed_api_queries(query: str, expected: str) -> None:
    assert result_names(query)[0] == expected


def test_tokenization_preserves_original_identifier_boundaries() -> None:
    assert reference_module._reference_tokens(
        "IDA Xrefs.to_ea Names.get_at FooBar"
    ) == ["xrefs", "to_ea", "names", "get_at", "foobar"]


@pytest.fixture(params=["packaged", "checkout"])
def source_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    package = tmp_path / "ida_domain"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "xrefs.py").write_text(
        '''\
class Xrefs:
    """Xrefs to address. Xrefs from address.

    Example: db.xrefs.to(ea), xref.frm
    """

    def to_ea(self, ea: ea_t) -> Iterator[XrefInfo]:
        """Get all cross-references to an address."""

    def from_ea(self, ea: ea_t) -> Iterator[XrefInfo]:
        """Get all cross-references from an address."""

    def to_ea_extended(self, ea: ea_t):
        """Xrefs.to_ea Xrefs.to_ea Xrefs.to_ea"""
''',
        encoding="utf-8",
    )
    examples = (
        package / "_examples" if request.param == "packaged" else tmp_path / "examples"
    )
    examples.mkdir()
    (examples / "xrefs.py").write_text(
        '"""Xrefs usage."""\nprint("example")\n', encoding="utf-8"
    )
    monkeypatch.setattr(reference_module, "_REFERENCE_SPEC_CACHE", None)
    monkeypatch.setattr(
        reference_module, "_find_ida_domain_package_path", lambda: package
    )
    monkeypatch.setattr(reference_module, "get_ida_domain_version", lambda: "fixture")


@pytest.mark.usefixtures("source_package")
def test_source_layouts_include_signatures_and_examples() -> None:
    output = reference_module.reference("Xrefs.to_ea")
    assert "ida_domain.xrefs.Xrefs.to_ea" in result_names("Xrefs.to_ea")
    assert "to_ea(self, ea: ea_t) -> Iterator[XrefInfo]" in output
    assert "IDA Domain API reference fixture" in output
    assert "Example: xrefs (xrefs.py)" in output
    assert 'print("example")' in output


@pytest.mark.usefixtures("source_package")
def test_unmatched_word_does_not_match_identifier_substrings() -> None:
    assert "No matching public API entries" in reference_module.reference("ref")


@pytest.mark.usefixtures("source_package")
def test_empty_query_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        reference_module.reference("  ")


def test_bm25_prefers_rare_terms_and_normalizes_document_length() -> None:
    field = reference_module._BM25Field.build(
        [
            "rare common",
            "other common",
            "third common",
        ]
    )
    assert field.score(0, {"rare"}) > field.score(0, {"common"}) > 0
    assert field.score(0, {"absent"}) == 0

    field = reference_module._BM25Field.build(
        [
            "needle",
            "needle " + "irrelevant " * 100,
        ]
    )
    assert field.score(0, {"needle"}) > field.score(1, {"needle"}) > 0


def test_bm25_term_frequency_saturates() -> None:
    # Equal lengths isolate term frequency from length normalization.
    field = reference_module._BM25Field.build(
        [
            "needle filler filler filler",
            "needle needle filler filler",
            "needle needle needle needle",
        ]
    )
    once, twice, four_times = [field.score(i, {"needle"}) for i in range(3)]
    assert 0 < once < twice < four_times
    assert twice < 2 * once
    assert four_times - twice < twice - once


def test_empty_bm25_corpus_and_fields() -> None:
    assert reference_module._ReferenceIndex.build([]).search("anything") == []
    field = reference_module._BM25Field.build(["", ""])
    assert field.score(0, {"anything"}) == 0
    # Stopword-only queries have no searchable terms.
    index = reference_module._ReferenceIndex.build([{"name": "a", "doc": ""}])
    assert index.search("a") == []


@pytest.mark.usefixtures("source_package")
def test_repeated_query_terms_do_not_change_ranking() -> None:
    assert result_names("xrefs to address") == result_names("xrefs xrefs to address")
