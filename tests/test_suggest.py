"""Attribute hints for user code, checked against the installed ida-domain API."""

import dataclasses
import importlib
from typing import Any

import pytest

from ida_nexus._runtime import (
    USER_CODE_FILENAME,
    _execute_user_code,
    _format_user_traceback,
)
from ida_nexus._suggest import _OPPOSITE_WORDS, _WORD_SYNONYMS, add_attribute_hints


# Imported after ida_nexus: importing ida_domain resets sys.path, which hides
# the source checkout from later imports.
def domain(name: str) -> Any:
    return importlib.import_module(f"ida_domain{name}")


def manager(cls: type) -> Any:
    # The managers only need a database for API calls, not for dir().
    return cls(None)


def value(cls: type) -> Any:
    return cls(**{field.name: 0 for field in dataclasses.fields(cls)})


NAMESPACE = {
    "db": object.__new__(domain(".database").Database),
    "xrefs": manager(domain(".xrefs").Xrefs),
    "names": manager(domain(".names").Names),
    "imports": manager(domain(".imports").Imports),
    "functions": manager(domain(".functions").Functions),
    "instructions": manager(domain(".instructions").Instructions),
    "entries": manager(domain(".entries").Entries),
    "bytes": manager(domain(".bytes").Bytes),
    "types": manager(domain(".types").Types),
    "entry": value(domain(".entries").EntryInfo),
    "local": object.__new__(domain(".pseudocode").LocalVariable),
    "string": domain(".strings").StringItem(0x1000, 4, 0),
    "xref": value(domain(".xrefs").XrefInfo),
    "module": value(domain(".imports").ImportModuleInfo),
    "ida_domain": domain(""),
    "XrefsFlags": domain(".xrefs").XrefsFlags,
}


def failure(code: str) -> str:
    with pytest.raises(AttributeError) as raised:
        _execute_user_code(code, dict(NAMESPACE), {})
    formatted = _format_user_traceback(raised.value, USER_CODE_FILENAME)
    assert formatted is not None
    return formatted


def suggestions(code: str) -> list[str]:
    hints = failure(code).partition("Did you mean:\n")[2]
    return [
        line.strip().split("(")[0].split(":")[0]
        for line in hints.splitlines()
        if line.startswith("  ")
    ]


# Wrong names agents used in the Flare-On transcripts (E03-E24), with the API
# they needed. The first suggestion must be that API.
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("xrefs.to(0x1000)", ".to_ea"),
        ("xref.frm", ".from_ea"),
        ("names.get_name_at(0x1000)", ".get_at"),
        ("imports.get_all()", ".get_all_imports"),
        ("string.ea", ".address"),
        ("functions.get_pseudocde(None)", ".get_pseudocode"),
        ("ida_domain.Databse", "ida_domain.Database"),
    ],
)
def test_transcript_mistakes_suggest_the_needed_api(code: str, expected: str) -> None:
    assert suggestions(code)[0] == expected


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("db.minimum_address", "  .minimum_ea: ea_t\n"),
        ("db.min_ea", "  .minimum_ea: ea_t\n"),
        ("string.content", "  .contents: bytes\n"),
    ],
)
def test_properties_are_suggested_with_their_type(code: str, expected: str) -> None:
    assert expected in failure(code)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("names.getNameAt(0x1000)", ".get_at"),
        ("imports.getAllImports()", ".get_all_imports"),
        ("ida_domain.xrefs.XrefFlags", "ida_domain.xrefs.XrefsFlags"),
    ],
)
def test_camel_case_names_match_snake_case_api(code: str, expected: str) -> None:
    assert suggestions(code)[0] == expected


def test_enum_suggestions_are_limited_to_its_members() -> None:
    assert suggestions("XrefsFlags.code")[0] == ".CODE"
    formatted = failure("XrefsFlags.zzz")
    assert "\nXrefsFlags members: " in formatted
    assert ", DATA, " in formatted
    assert "bit_length" not in formatted


def test_backing_attributes_are_not_listed() -> None:
    assert "m_database" not in failure("xrefs.zzz")
    assert "m_database" not in failure("xrefs.m_databse")


def test_method_on_another_manager_points_to_its_db_path() -> None:
    assert "db.pseudocode.decompile" in suggestions("functions.decompile(None)")
    assert "db.pseudocode.decompile" in suggestions("db.decompile")


def test_generic_names_do_not_list_every_manager() -> None:
    assert suggestions("imports.get_all()") == [
        ".get_all_imports",
        ".get_all_modules",
    ]


def test_each_word_has_one_synonym_group() -> None:
    words = [word for group in _WORD_SYNONYMS for word in group]
    assert sorted(word for word in set(words) if words.count(word) > 1) == []


def test_synonym_groups_never_join_opposites() -> None:
    for group in _WORD_SYNONYMS:
        for first, second in _OPPOSITE_WORDS:
            assert not (group & first and group & second), sorted(group)


def hint_names(cls: type, name: str) -> list[str]:
    formatted = add_attribute_hints(
        AttributeError(f"no {name!r}", name=name, obj=object.__new__(cls)), ""
    )
    return [
        line.strip().split("(")[0].split(":")[0]
        for line in formatted.partition("Did you mean:\n")[2].splitlines()
        if line.startswith("  ")
    ]


# IDA abbreviations agents carry over, against the words ida-domain spells out.
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("instructions.get_mnem(None)", ".get_mnemonic"),
        ("instructions.get_disasm(None)", ".get_disassembly"),
        ("instructions.prev_insn(0x1000)", ".get_previous"),
        ("db.arch", ".architecture"),
        ("xref.src", ".from_ea"),
    ],
)
def test_abbreviations_suggest_the_spelled_out_api(code: str, expected: str) -> None:
    assert suggestions(code)[0] == expected


@pytest.mark.parametrize(
    ("module", "cls", "name", "expected"),
    [
        (".comments", "CommentInfo", "cmt", ".comment"),
        (".microcode", "MicroOperand", "is_reg", ".is_register"),
        (".microcode", "MicroBlockArray", "num_blocks", ".block_count"),
        (".microcode", "MicroInstruction", "dst", ".dest"),
        (".types", "Types", "get_struc_members", ".get_udt_members"),
    ],
)
def test_abbreviations_on_value_objects(
    module: str, cls: str, name: str, expected: str
) -> None:
    assert hint_names(getattr(domain(module), cls), name)[0] == expected


def test_abbreviated_plurals_match_spelled_out_plurals() -> None:
    pseudocode = domain(".pseudocode").PseudocodeFunction
    assert ".local_variables" in hint_names(pseudocode, "lvars")
    block = domain(".microcode").MicroBlock
    assert hint_names(block, "insns")[0] == ".instructions"


def test_converter_names_do_not_reach_destination_members() -> None:
    # "to" is the prefix of converters (``to_text``), not a destination.
    instruction = domain(".microcode").MicroInstruction
    assert ".dest" not in hint_names(instruction, "to_string")


def test_opposite_verbs_are_not_suggested() -> None:
    assert ".set_name" not in suggestions("names.get_name(0x1000)")
    assert ".get_at" not in suggestions("functions.set_at(0x1000)")


def test_leading_get_is_optional() -> None:
    assert suggestions("xrefs.get_to(0x1000)")[0] == ".to_ea"
    heads = manager(domain(".heads").Heads)
    formatted = add_attribute_hints(
        AttributeError("no 'get_item_size'", name="get_item_size", obj=heads), ""
    )
    assert formatted.startswith("Did you mean:\n  .size(")


def test_owner_noun_is_optional() -> None:
    assert suggestions("functions.get_func_name(None)")[0] == ".get_name"
    assert ".to_ea" in suggestions("xrefs.xrefs_to(0x1000)")
    assert suggestions("entries.get_entry_at(0x1000)")[0] == ".get_at"


def test_lone_word_left_after_dropping_is_not_fuzzed() -> None:
    # "read" is one edit from "head"; with "bytes" dropped nothing else is left.
    bytes_manager = manager(domain(".bytes").Bytes)
    formatted = add_attribute_hints(
        AttributeError("no 'read_bytes'", name="read_bytes", obj=bytes_manager), ""
    )
    assert "Did you mean" not in formatted
    assert ", get_bytes_at, " in formatted


def test_mutators_and_factories_are_demoted_for_reads() -> None:
    operand = object.__new__(domain(".microcode").MicroOperand)
    formatted = add_attribute_hints(
        AttributeError("no 'is_reg'", name="is_reg", obj=operand), ""
    )
    assert "  .reg(" not in formatted
    assert formatted.startswith("Did you mean:\n  .is_register: bool\n")

    instruction = object.__new__(domain(".pseudocode").PseudocodeInstruction)
    formatted = add_attribute_hints(
        AttributeError("no 'expr'", name="expr", obj=instruction), ""
    )
    assert "  .make_expr(" not in formatted


def test_mutators_are_suggested_for_mutations() -> None:
    assert suggestions("names.set(0x1000, 'x')")[0] == ".set_name"


def test_other_manager_methods_must_fit_the_arguments() -> None:
    assert not any(
        line.startswith("db.") for line in suggestions("functions.rename(None, 'x')")
    )
    assert "db.types.get_xrefs_to" not in suggestions("xrefs.get_xrefs_to(0x1000)")


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("functions.decompile(None)", "db.pseudocode.decompile"),
        ("instructions.get_disassembly_at(0x1000)", "db.bytes.get_disassembly_at"),
        ("instructions.get_next_head(0x1000)", "db.bytes.get_next_head"),
        ("names.current_ea", "db.current_ea"),
    ],
)
def test_other_manager_methods_taking_an_address_are_kept(
    code: str, expected: str
) -> None:
    assert expected in suggestions(code)


def test_unrelated_names_are_not_suggested() -> None:
    assert ".set_name" not in suggestions("names.get_name_at(0x1000)")
    assert ".compiler_information" not in suggestions("db.decompile")


def test_suggestions_show_signatures_and_field_types() -> None:
    formatted = failure("xrefs.to(0x1000)")
    assert "  .to_ea(ea: ea_t, flags: XrefsFlags = XrefsFlags.ALL) -> " in formatted
    assert "  .address: ea_t\n" in failure("string.ea")


def test_dataclass_without_a_match_lists_its_fields() -> None:
    formatted = failure("module.entries")
    assert "Did you mean" not in formatted
    assert formatted.endswith(
        "has no attribute 'entries'\nImportModuleInfo fields: index: int, name: str\n"
    )


def test_dataclass_listing_includes_its_properties() -> None:
    formatted = failure("string.text")
    assert (
        "\nStringItem fields: address: ea_t, length: int, internal_type: int\n"
        in formatted
    )
    assert "\nStringItem properties: contents: bytes, encoding: str, " in formatted
    assert ", type: StringType" in formatted


def test_manager_without_a_match_lists_its_members() -> None:
    formatted = failure("xrefs.zzz")
    assert "Did you mean" not in formatted
    assert "\nXrefs methods: add_code_ref, " in formatted
    assert ", to_ea, " in formatted


def test_large_class_without_a_match_lists_properties_and_methods() -> None:
    formatted = failure("db.zzz")
    assert "Did you mean" not in formatted
    assert "\nDatabase properties: architecture: Optional[str], " in formatted
    assert ", functions: Functions, " in formatted
    assert "\nDatabase methods: close, " in formatted
    assert ", is_valid_ea, " in formatted

    formatted = failure("functions.zzz")
    assert "\nFunctions properties: database: Database\n" in formatted
    assert "\nFunctions methods: apply_declaration, " in formatted
    assert ", get_pseudocode, " in formatted


def test_listing_is_omitted_when_a_manager_has_suggestions() -> None:
    formatted = failure("xrefs.to(0x1000)")
    assert "Xrefs methods" not in formatted
    assert "Xrefs properties" not in formatted


def test_property_with_a_setter_shows_the_getter_type() -> None:
    block = object.__new__(domain(".microcode").MicroBlock)
    formatted = add_attribute_hints(
        AttributeError("no 'block_typ'", name="block_typ", obj=block), ""
    )
    assert "  .block_type: MicroBlockType\n" in formatted
    listed = add_attribute_hints(AttributeError("no", name="zzz", obj=block), "")
    assert ", block_type: MicroBlockType, " in listed
    assert ": None" not in listed


def test_setters_are_not_suggested_on_other_managers() -> None:
    assert suggestions("names.current_ea") == ["db.current_ea"]


def test_abbreviated_words_match_their_full_form() -> None:
    assert suggestions("entry.ord")[0] == ".ordinal"


def test_run_together_words_are_split_at_member_words() -> None:
    assert suggestions("string.strtype")[0] == ".type"


def test_short_fragments_do_not_split_words() -> None:
    # "re" + "name" would otherwise lead ``rename`` to ``get_name``.
    assert ".get_name" not in suggestions("functions.rename")


def test_a_clear_weak_winner_is_suggested_with_the_listing() -> None:
    formatted = failure("db.imagebase")
    assert formatted.partition("Did you mean:\n")[2].startswith("  .base_address: ")
    assert "\nDatabase properties: " in formatted


def test_owner_nouns_unused_by_members_are_dropped() -> None:
    assert suggestions("xrefs.xrefs_to(0x1000)")[0] == ".to_ea"
    assert suggestions("xrefs.XrefsTo(0x1000)")[0] == ".to_ea"


def test_owner_nouns_used_by_members_still_count() -> None:
    # On Bytes, "byte" tells get_byte_at from get_word_at.
    assert suggestions("bytes.get_wide_byte(0x1000)")[0] == ".get_byte_at"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("db.funcs", ".functions"),
        ("local.width", ".size"),
        ("local.tinfo", ".type"),
    ],
)
def test_more_synonyms(code: str, expected: str) -> None:
    assert suggestions(code)[0] == expected


def test_type_synonyms_do_not_reach_other_type_methods() -> None:
    assert ".get_return_type" not in suggestions("types.get_tinfo(0x1000)")


def test_non_ida_domain_objects_are_left_alone() -> None:
    with pytest.raises(AttributeError) as raised:
        _execute_user_code("object().to", {}, {})
    formatted = _format_user_traceback(raised.value, USER_CODE_FILENAME)
    assert formatted is not None
    assert formatted.endswith("AttributeError: 'object' object has no attribute 'to'\n")


def test_private_names_are_left_alone() -> None:
    assert failure("xrefs._to").endswith("has no attribute '_to'\n")


def test_attribute_error_from_inside_an_existing_member_is_left_alone() -> None:
    error = AttributeError("inner failure", name="to_ea", obj=NAMESPACE["xrefs"])
    assert add_attribute_hints(error, "AttributeError: inner\n") == (
        "AttributeError: inner\n"
    )


def test_python_suggestion_is_replaced_only_when_hints_are_added() -> None:
    error = AttributeError("no 'to'", name="to", obj=NAMESPACE["xrefs"])
    python_line = "AttributeError: no 'to'. Did you mean: 'calls_to_ea'?\n"
    formatted = add_attribute_hints(error, python_line)
    assert formatted.startswith("AttributeError: no 'to'\nDid you mean:\n  .to_ea(")

    unmatched = AttributeError("no 'x'", name="x", obj=object())
    line = "AttributeError: no 'x'. Did you mean: 'y'?\n"
    assert add_attribute_hints(unmatched, line) == line


def test_hint_failures_keep_the_original_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import ida_nexus._suggest as suggest_module

    def broken(error: BaseException) -> str:
        raise RuntimeError("broken")

    monkeypatch.setattr(suggest_module, "_attribute_hints", broken)
    error = AttributeError("no 'to'", name="to", obj=NAMESPACE["xrefs"])
    assert add_attribute_hints(error, "original\n") == "original\n"
