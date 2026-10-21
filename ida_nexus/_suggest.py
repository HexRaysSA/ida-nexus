"""Suggest ida-domain names when user code accesses a missing attribute."""

import dataclasses
import enum
import inspect
import re
from types import ModuleType
from typing import Any

from .reference import _build_reference_spec

# IDA and ida-domain use different words for the same concept, so spelling
# distance alone misses these (``StringItem.ea`` is ``StringItem.address``).
# Each group lists interchangeable words of underscore-separated names; a word
# belongs to one group at most. Short abbreviations are not typo-matched, so
# their plurals are listed as words of their own.
_WORD_SYNONYMS = (
    frozenset({"ea", "address", "addr"}),
    frozenset({"frm", "from", "src", "source"}),
    frozenset({"dst", "dest", "target"}),
    frozenset({"size", "length", "len", "width"}),
    frozenset({"min", "minimum"}),
    frozenset({"max", "maximum"}),
    frozenset({"qty", "cnt", "num", "count"}),
    frozenset({"idx", "index"}),
    frozenset({"prev", "previous"}),
    frozenset({"ret", "return"}),
    frozenset({"gen", "generate"}),
    frozenset({"meta", "metadata"}),
    frozenset({"perm", "perms", "permission", "permissions"}),
    # Database and program.
    frozenset({"arch", "architecture"}),
    frozenset({"bits", "bitness"}),
    frozenset({"func", "function"}),
    frozenset({"funcs", "functions"}),
    frozenset({"refs", "xrefs", "references"}),
    frozenset({"cmt", "comment"}),
    frozenset({"cmts", "comments"}),
    frozenset({"disasm", "disassembly"}),
    frozenset({"stk", "stack"}),
    frozenset({"succs", "successors"}),
    frozenset({"preds", "predecessors"}),
    frozenset({"dll", "module"}),
    frozenset({"str", "strlit", "string"}),
    frozenset({"strs", "strings"}),
    frozenset({"text", "contents"}),
    frozenset({"kind", "type", "tinfo", "tif"}),
    # Instructions and operands. Not a bare "op", which is the ctree operator
    # kind on ``PseudocodeExpression``.
    frozenset({"insn", "instruction"}),
    frozenset({"insns", "instructions"}),
    frozenset({"mnem", "mnemonic"}),
    frozenset({"opnd", "operand"}),
    frozenset({"ops", "opnds", "operands"}),
    frozenset({"reg", "register"}),
    frozenset({"regs", "registers"}),
    frozenset({"imm", "immediate"}),
    # Types.
    frozenset({"til", "library"}),
    frozenset({"struc", "struct", "udt"}),
    frozenset({"decl", "declaration"}),
    frozenset({"decls", "declarations"}),
    frozenset({"udm", "member"}),
    frozenset({"udms", "members"}),
    # Decompiler and microcode.
    frozenset({"decompile", "decompiler", "pseudocode"}),
    frozenset({"mba", "microcode"}),
    frozenset({"expr", "expression"}),
    frozenset({"exprs", "expressions"}),
    frozenset({"lvar", "var", "variable"}),
    frozenset({"lvars", "vars", "variables"}),
    frozenset({"arg", "argument"}),
    frozenset({"args", "arguments"}),
)
# Words naming opposite actions. Names that differ by one of them are never
# what the caller meant, however close in spelling (``get_name``, ``set_name``).
_OPPOSITE_WORDS = (
    (frozenset({"get"}), frozenset({"set"})),
    (frozenset({"add", "create", "insert"}), frozenset({"remove", "delete", "del"})),
    (frozenset({"enable"}), frozenset({"disable"})),
    (frozenset({"next"}), frozenset({"previous", "prev"})),
    (frozenset({"first"}), frozenset({"last"})),
    (frozenset({"start"}), frozenset({"end"})),
    (
        frozenset({"from", "frm", "src", "source"}),
        frozenset({"to", "dst", "dest", "target"}),
    ),
    (frozenset({"min", "minimum"}), frozenset({"max", "maximum"})),
    (frozenset({"read"}), frozenset({"write"})),
    (frozenset({"load"}), frozenset({"save"})),
    (frozenset({"open"}), frozenset({"close"})),
    (frozenset({"show"}), frozenset({"hide"})),
)
# Leading verbs of methods that change the database or build new objects; a
# lookup-looking name (``is_reg``) should not lead to them (``reg(mreg, size)``).
_MUTATOR_WORDS = frozenset(
    {
        "set",
        "make",
        "create",
        "add",
        "remove",
        "delete",
        "del",
        "force",
        "apply",
        "insert",
        "optimize",
        "patch",
        "rename",
        "clear",
    }
)
# Applied to the score too, so a mutator sharing only half the words is dropped.
_MUTATOR_PENALTY = 0.8
# Dropping an optional word (a leading ``get``, the owner's own noun) finds the
# intended name, but a match without dropping anything ranks first on a tie.
_OPTIONAL_WORD_DISCOUNT = 0.9
# First parameters that make a method on another manager a plausible target for
# the same call: it takes an address or a function, like the manager it replaces.
_ADDRESS_PARAMETERS = frozenset(
    {"ea", "address", "start_ea", "ea_or_func", "func", "function", "start", "end"}
)
_ADDRESS_ANNOTATION = re.compile(r"\b(?:ea_t|func_t)\b")
_MAX_SUGGESTIONS = 3
_MIN_SCORE = 0.5
# Below _MIN_SCORE, a single member still stands out when it shares a real part
# of the name and nothing else comes close (``imagebase`` -> ``base_address``).
# It is shown with the listing, since the match is weak.
_WEAK_MIN_SCORE = 0.3
# Listings stand in for dir(), so they cover even the largest managers; the
# cap only guards against pathological classes.
_MAX_LISTED_MEMBERS = 150
# A name on more managers than this is generic (``get_all``, ``get_at``), so
# pointing at each of them would be noise rather than a correction.
_MAX_OTHER_MANAGERS = 2
# Word boundaries inside CamelCase and camelCase: getNameAt, XrefsFlags, HTTPServer.
_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_PYTHON_SUGGESTION = re.compile(r"\. Did you mean: '[^'\n]*'\?$")


def add_attribute_hints(error: BaseException, formatted: str) -> str:
    """Append ida-domain name suggestions to a formatted exception, if any apply.

    Python's own single "Did you mean" is dropped when hints are added, so the
    caller never sees two disagreeing suggestions.
    """

    try:
        hints = _attribute_hints(error)
    except Exception:  # noqa: BLE001 -- hints must never mask the user's error
        return formatted
    if not hints:
        return formatted
    first, newline, rest = formatted.partition("\n")
    return _PYTHON_SUGGESTION.sub("", first) + newline + rest + hints


def _attribute_hints(error: BaseException) -> str | None:
    if not isinstance(error, AttributeError):
        return None
    obj = getattr(error, "obj", None)
    name = getattr(error, "name", None)
    if obj is None or not name or name.startswith("_") or not _is_ida_domain(obj):
        return None
    owner = _owner(obj)
    missing = object()
    if inspect.getattr_static(obj, name, missing) is not missing:
        # The name exists; the error came from inside it, e.g. a property body.
        return None

    try:
        spec: dict[str, Any] | None = _build_reference_spec()
    except Exception:  # noqa: BLE001 -- fall back to runtime introspection
        spec = None
    entries = _entries_by_qualname(spec)
    members = _public_members(obj)
    # A dataclass field read off the class itself fails but is still listed;
    # suggesting the name that just failed would only repeat the error.
    ranked, confident = _ranked(obj, name, members - {name})
    lines = [
        f"  {_describe(obj, member, entries)}" for member in ranked[:_MAX_SUGGESTIONS]
    ]
    lines.extend(_other_manager_lines(owner, name, spec))

    sections = []
    if lines:
        sections.append("Did you mean:\n" + "\n".join(lines))
    # A dataclass is small and its fields are its data, so it is always listed;
    # elsewhere the listing replaces the dir() call an empty hint would cause.
    if _fields(owner) or not lines or not confident:
        sections.extend(_listing(obj, members, entries))
    return "".join(f"{section}\n" for section in sections) or None


def _ranked(obj: Any, name: str, members: set[str]) -> tuple[list[str], bool]:
    """Members resembling ``name``, best first, and whether the match is strong."""

    nouns = _owner_nouns(_owner(obj))
    vocabulary = frozenset(word for member in members for word in _words(member))
    matches = []
    weak = []
    for member in members:
        score, rank = _score(name, member, nouns, vocabulary)
        if _is_mutator_for(obj, name, member):
            score *= _MUTATOR_PENALTY
            rank *= _MUTATOR_PENALTY
        if score >= _MIN_SCORE:
            distance = _edit_distance(name.casefold(), member.casefold())
            matches.append((-rank, distance, member))
        elif score > 0:
            weak.append((score, member))
    if matches:
        return [member for _, _, member in sorted(matches)], True
    weak.sort(reverse=True)
    if weak and weak[0][0] >= _WEAK_MIN_SCORE:
        runner_up = weak[1][0] if len(weak) > 1 else 0.0
        if runner_up <= weak[0][0] / 2:
            return [weak[0][1]], False
    return [], True


def _owner_nouns(owner: Any) -> frozenset[str]:
    """Words naming the owner class itself, which a member name may repeat.

    ``functions.get_func`` and ``xrefs.xrefs_to`` repeat the manager they are
    called on; the class's head noun, in either number, adds nothing to them.
    """

    if not isinstance(owner, type):
        return frozenset()
    words = _words(owner.__name__)
    if not words:
        return frozenset()
    noun = words[-1]
    forms = {noun, _other_number(noun)}
    return frozenset().union(*(_synonyms(form) for form in forms))


def _other_number(noun: str) -> str:
    if noun.endswith("ies"):
        return f"{noun[:-3]}y"
    if noun.endswith("s"):
        return noun[:-1]
    if noun.endswith("y"):
        return f"{noun[:-1]}ies"
    return f"{noun}s"


def _is_mutator_for(obj: Any, typed: str, member: str) -> bool:
    """Whether ``member`` changes or builds something while ``typed`` only reads."""

    typed_words = _words(typed)
    if typed_words and typed_words[0] in _MUTATOR_WORDS:
        return False
    member_words = _words(member)
    if member_words and member_words[0] in _MUTATOR_WORDS:
        return True
    owner = _owner(obj)
    if not isinstance(owner, type):
        return False
    # Classmethods and staticmethods on value classes are factories.
    return isinstance(_class_attribute(owner, member), (classmethod, staticmethod))


def _listing(
    obj: Any, members: set[str], entries: dict[str, dict[str, Any]]
) -> list[str]:
    """List members grouped by kind, so properties are never mistaken for absent."""

    owner = _owner(obj)
    if isinstance(obj, (ModuleType, enum.EnumMeta)):
        return [f"{owner.__name__} members: {_joined(sorted(members))}"]
    fields = _fields(owner)
    field_names = {field.name for field in fields}
    groups: dict[str, list[str]] = {
        "fields": [f"{field.name}: {_annotation_text(field.type)}" for field in fields],
        "properties": [],
        "methods": [],
        "attributes": [],
    }
    for member in sorted(members - field_names):
        attribute = _class_attribute(owner, member)
        if isinstance(attribute, property) or inspect.isdatadescriptor(attribute):
            returns = _property_type(owner, member, entries)
            groups["properties"].append(f"{member}: {returns}" if returns else member)
        elif isinstance(attribute, (staticmethod, classmethod)) or inspect.isroutine(
            attribute
        ):
            groups["methods"].append(member)
        else:
            groups["attributes"].append(member)
    return [
        f"{owner.__name__} {kind}: {_joined(items)}"
        for kind, items in groups.items()
        if items
    ]


def _joined(items: list[str]) -> str:
    if len(items) <= _MAX_LISTED_MEMBERS:
        return ", ".join(items)
    hidden = len(items) - _MAX_LISTED_MEMBERS
    return ", ".join(items[:_MAX_LISTED_MEMBERS]) + f", … and {hidden} more"


def _class_attribute(owner: Any, member: str) -> Any:
    """The raw class attribute behind ``member``, or None for instance data."""

    defining = _defining_class(owner, member)
    return None if defining is None else vars(defining)[member]


def _defining_class(owner: Any, member: str) -> type | None:
    return next((cls for cls in owner.__mro__ if member in vars(cls)), None)


def _is_ida_domain(obj: Any) -> bool:
    module = obj.__name__ if isinstance(obj, ModuleType) else _owner(obj).__module__
    return module == "ida_domain" or module.startswith("ida_domain.")


def _owner(obj: Any) -> Any:
    return obj if isinstance(obj, (type, ModuleType)) else type(obj)


def _public_members(obj: Any) -> set[str]:
    if isinstance(obj, enum.EnumMeta):
        # dir() of an IntFlag also lists int's methods (bit_length, to_bytes).
        return set(obj.__members__)
    # ``m_`` marks ida-domain's backing attributes (``m_database`` behind the
    # ``database`` property); they are internal despite the missing underscore.
    members = {member for member in dir(obj) if not member.startswith(("_", "m_"))}
    # Fields without defaults are absent from the class's dir().
    members.update(field.name for field in _fields(_owner(obj)))
    return members


def _fields(owner: Any) -> tuple[dataclasses.Field[Any], ...]:
    if isinstance(owner, type) and dataclasses.is_dataclass(owner):
        return dataclasses.fields(owner)
    return ()


def _words(name: str) -> list[str]:
    return [
        word for word in _CASE_BOUNDARY.sub("_", name).casefold().split("_") if word
    ]


def _synonyms(word: str) -> frozenset[str]:
    for group in _WORD_SYNONYMS:
        if word in group:
            return group
    return frozenset({word})


def _are_opposites(left: str, right: str) -> bool:
    return any(
        (left in first and right in second) or (left in second and right in first)
        for first, second in _OPPOSITE_WORDS
    )


def _words_match(typed: str, candidate: str, fuzzy: bool = True) -> bool:
    if candidate in _synonyms(typed):
        return True
    if not fuzzy or _are_opposites(typed, candidate):
        return False
    # Short words are too close to each other ("at", "ea", "to") to fuzz.
    return _is_typo(typed, candidate) or _is_abbreviation(typed, candidate)


def _is_abbreviation(typed: str, candidate: str) -> bool:
    # ``ord`` for ``ordinal``; shorter prefixes are too ambiguous ("to", "is").
    return (
        len(typed) >= 3 and len(candidate) > len(typed) and candidate.startswith(typed)
    )


def _score(
    typed: str,
    candidate: str,
    nouns: frozenset[str] = frozenset(),
    vocabulary: frozenset[str] = frozenset(),
) -> tuple[float, float]:
    """Word overlap of two snake_case names, allowing synonyms and typos.

    Matching whole words catches the common agent mistakes that edit distance
    misses: ``to`` for ``to_ea``, ``get_name_at`` for ``get_at``, and
    ``get_all`` for ``get_all_imports``. A leading ``get`` on either side and
    the owner's ``nouns`` in ``typed`` are optional. Returns the best overlap,
    which decides whether to suggest at all, and a rank that prefers matches
    needing no optional word dropped.
    """

    typed_words = _split_compounds(_words(typed), vocabulary)
    candidate_words = _words(candidate)
    if _differ_by_opposites(typed_words, candidate_words):
        # Also before dropping a leading "get": ``set_at`` is not ``get_at``.
        return 0.0, 0.0
    candidate_variants = _optional_variants(candidate_words, frozenset(), frozenset())
    score = rank = 0.0
    for typed_variant, typed_drops in _optional_variants(
        typed_words, nouns, vocabulary
    ):
        for candidate_variant, candidate_drops in candidate_variants:
            drops = typed_drops + candidate_drops
            # A lone word left after dropping the rest is too weak to also fuzz:
            # ``read_bytes`` would reach ``get_next_head`` via "read" ~ "head".
            fuzzy = not drops or len(typed_variant) > 1
            overlap = _overlap(typed_variant, candidate_variant, fuzzy)
            score = max(score, overlap)
            discount = _OPTIONAL_WORD_DISCOUNT**drops
            rank = max(rank, overlap * discount)

    if _is_typo(
        typed.replace("_", "").casefold(), candidate.replace("_", "").casefold()
    ):
        score = max(score, 0.75)
        rank = max(rank, 0.75)
    return score, rank


def _split_compounds(words: list[str], vocabulary: frozenset[str]) -> list[str]:
    """Split run-together words at a word the owner uses: ``strtype`` -> str, type."""

    split = []
    for word in words:
        if word in vocabulary or len(word) < 5:
            split.append(word)
            continue
        parts = next(
            (
                [word[:index], word[index:]]
                for index in range(2, len(word) - 1)
                if _is_split(word[:index], word[index:], vocabulary)
            ),
            [word],
        )
        split.extend(parts)
    return split


def _is_split(left: str, right: str, vocabulary: frozenset[str]) -> bool:
    # One side must be a word the owner uses; a two-letter rest must be one too,
    # or ``rename`` would split into "re" + "name".
    if left not in vocabulary and right not in vocabulary:
        return False
    return all(len(part) >= 3 or part in vocabulary for part in (left, right))


def _optional_variants(
    words: list[str], nouns: frozenset[str], vocabulary: frozenset[str]
) -> list[tuple[list[str], int]]:
    """``words`` with each combination of optional words dropped, and how many kinds."""

    variants = [(words, 0)]
    if words[:1] == ["get"]:
        variants.append((words[1:], 1))
    # A noun the members never use names the owner itself (``xrefs`` on Xrefs,
    # ``func`` on Functions), so it is dropped outright. One they do use
    # carries meaning there (``byte`` on Bytes, ``decompile`` on Pseudocode)
    # and is only optional.
    if owner_only := nouns - vocabulary:
        variants = [_dropping(owner_only, *variant) for variant in variants]
    if shared := nouns & vocabulary:
        for variant, drops in list(variants):
            kept, kept_drops = _dropping(shared, variant, drops)
            if kept_drops > drops:
                variants.append((kept, kept_drops))
    # A bare "get" left over would match every getter equally.
    return [
        (variant, drops)
        for variant, drops in variants
        if variant and (not drops or variant != ["get"])
    ]


def _dropping(
    optional: frozenset[str], words: list[str], drops: int
) -> tuple[list[str], int]:
    """``words`` without the ``optional`` ones, counting one more drop if any went."""

    kept = [word for word in words if word not in optional]
    return (kept, drops + 1) if len(kept) < len(words) else (words, drops)


def _overlap(
    typed_words: list[str], candidate_words: list[str], fuzzy: bool = True
) -> float:
    unmatched = list(candidate_words)
    matched = 0
    for word in typed_words:
        for other in unmatched:
            if _words_match(word, other, fuzzy):
                unmatched.remove(other)
                matched += 1
                break
    return matched / (len(typed_words) + len(candidate_words) - matched)


def _differ_by_opposites(typed_words: list[str], candidate_words: list[str]) -> bool:
    typed_only = set(typed_words) - set(candidate_words)
    candidate_only = set(candidate_words) - set(typed_words)
    return any(
        _are_opposites(left, right) for left in typed_only for right in candidate_only
    )


def _is_typo(typed: str, candidate: str) -> bool:
    # Python's and rustc's one-third cutoff accepts unrelated API names here,
    # e.g. ``get_name_at`` -> ``set_name`` and ``decompile`` -> ``compiler``.
    return len(typed) >= 4 and _edit_distance(typed, candidate) <= len(typed) // 4


def _edit_distance(left: str, right: str) -> int:
    """Optimal string alignment distance: Levenshtein plus transpositions."""

    previous_row: list[int] | None = None
    row = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            cost = left_char != right_char
            value = min(row[j] + 1, current[j - 1] + 1, row[j - 1] + cost)
            if (
                previous_row is not None
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                value = min(value, previous_row[j - 2] + 1)
            current.append(value)
        previous_row, row = row, current
    return row[-1]


def _entries_by_qualname(spec: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if spec is None:
        return {}
    return {
        entry["qualname"]: entry
        for entry in spec["entries"]
        if not _is_property_mutator(entry)
    }


def _is_property_mutator(entry: dict[str, Any]) -> bool:
    # ``@x.setter`` and ``@x.deleter`` share the getter's qualname but return
    # None, so they would hide the property's type.
    return any(
        decorator.endswith((".setter", ".deleter"))
        for decorator in entry.get("decorators", ())
    )


def _describe(obj: Any, member: str, entries: dict[str, dict[str, Any]]) -> str:
    if isinstance(obj, ModuleType):
        return f"{obj.__name__}.{member}"
    owner = _owner(obj)
    for field in _fields(owner):
        if field.name == member:
            return f".{member}: {_annotation_text(field.type)}"

    defining = _defining_class(owner, member)
    if defining is None:
        return f".{member}"
    attribute = vars(defining)[member]
    if isinstance(attribute, property):
        returns = _property_type(owner, member, entries)
        return f".{member}: {returns}" if returns else f".{member}"
    entry = _entry_for(defining, member, entries)
    if entry is not None and "signature" in entry:
        return f".{member}{_without_self(entry['signature'])}"
    if callable(attribute):
        try:
            return f".{member}{inspect.signature(getattr(obj, member))}"
        except (TypeError, ValueError):
            pass
    return f".{member}"


def _entry_for(
    defining: type, member: str, entries: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    return entries.get(f"{defining.__module__}.{defining.__qualname__}.{member}")


def _property_type(
    owner: Any, member: str, entries: dict[str, dict[str, Any]]
) -> str | None:
    """The getter's return type, from the reference index or the annotation."""

    defining = _defining_class(owner, member)
    if defining is None:
        return None
    attribute = vars(defining)[member]
    if (returns := _entry_returns(_entry_for(defining, member, entries))) is not None:
        return returns
    if isinstance(attribute, property) and attribute.fget is not None:
        try:
            annotation = inspect.signature(attribute.fget).return_annotation
        except (TypeError, ValueError):
            return None
        if annotation is not inspect.Signature.empty:
            return _annotation_text(annotation)
    return None


def _other_manager_lines(
    owner: Any, name: str, spec: dict[str, Any] | None
) -> list[str]:
    """Point to ``db.<manager>.<name>`` when the method lives on another manager.

    Only searched when the failing object is ``db`` or one of its managers, where
    the mistake is picking the wrong manager (``db.functions.decompile``). Value
    objects such as ``ImportModuleInfo`` would otherwise match unrelated names.
    """

    if spec is None:
        return []
    accessors = _manager_accessors(spec)
    if not isinstance(owner, type) or owner.__name__ not in accessors:
        return []
    found = [
        entry
        for entry in spec["entries"]
        if entry["kind"] == "method"
        and entry["name"] == name
        and entry["class"] in accessors
        and entry["class"] != owner.__name__
        and entry["visibility"] == "public"
        and not _is_property_mutator(entry)
    ]
    if len(found) > _MAX_OTHER_MANAGERS:
        return []
    lines = []
    for entry in found:
        target = f"{accessors[entry['class']]}.{entry['name']}"
        if "property" in entry["decorators"]:
            returns = _entry_returns(entry)
            text = f"{target}: {returns}" if returns else target
        elif _takes_address_first(entry["signature"]):
            text = f"{target}{_without_self(entry['signature'])}"
        else:
            continue
        lines.append(f"  {text}  (on {entry['class']}, not {owner.__name__})")
    return lines


def _takes_address_first(signature: str) -> bool:
    """Whether a method takes nothing, or an address or function, first.

    The same name on another manager is only the intended call when it fits the
    same arguments: ``db.entries.rename(ordinal, ...)`` is no stand-in for
    renaming a function, nor ``db.types.get_xrefs_to(type_info)`` for xrefs to
    an address.
    """

    first = _first_parameter(_without_self(signature))
    if not first:
        return True
    parameter, _, annotation = first.partition("=")[0].partition(":")
    return parameter.strip() in _ADDRESS_PARAMETERS or bool(
        _ADDRESS_ANNOTATION.search(annotation)
    )


def _first_parameter(signature: str) -> str:
    """The first parameter of ``(a: Union[int, func_t], b) -> X``, with its annotation."""

    depth = 0
    for index, char in enumerate(signature[1:], 1):
        if char in "[(":
            depth += 1
        elif char in "])":
            depth -= 1
        if depth < 0 or (depth == 0 and char == ","):
            return signature[1:index].strip()
    return signature[1:].strip()


def _manager_accessors(spec: dict[str, Any]) -> dict[str, str]:
    """Map ``Database`` and each manager class name to its ``db`` path."""

    accessors = {"Database": "db"}
    for entry in spec["entries"]:
        if (
            entry["kind"] == "method"
            and entry["module"] == "ida_domain.database"
            and entry["class"] == "Database"
            and entry["visibility"] == "public"
            and "property" in entry["decorators"]
        ):
            returns = _entry_returns(entry)
            if returns and returns.isidentifier() and returns[0].isupper():
                accessors.setdefault(returns, f"db.{entry['name']}")
    return accessors


def _entry_returns(entry: dict[str, Any] | None) -> str | None:
    if entry is None:
        return None
    _, arrow, returns = entry.get("signature", "").partition(" -> ")
    return returns if arrow else None


def _without_self(signature: str) -> str:
    return re.sub(r"^\((?:self|cls)(?:, |(?=\)))", "(", signature)


def _annotation_text(annotation: Any) -> str:
    if isinstance(annotation, str):
        return annotation
    return getattr(annotation, "__name__", None) or repr(annotation)
