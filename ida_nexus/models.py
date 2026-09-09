"""Public result models returned by Nexus database operations."""

from typing import Annotated, Any, Literal, TypeAlias, TypedDict


class PythonExecutionResult(TypedDict):
    result: Any
    stdout: str
    stderr: str


class AnalysisResult(TypedDict):
    status: str
    complete: bool


# IDB change payloads combine common metadata with event-specific fields.
DatabaseChangeEvent: TypeAlias = dict[str, Any]


class SaveResult(TypedDict):
    saved: bool
    idb_path: str


class ShutdownResult(TypedDict):
    shutting_down: bool
    save: bool


DatabaseStatus = Literal["available", "attached", "current", "unavailable"]


class DatabaseListing(TypedDict):
    path: str
    backend: Annotated[str, "Instance backend: gui or idalib."]
    status: Annotated[
        str,
        "Action state: available, attached, current, or unavailable.",
    ]
    instance_id: str | None
    error: str | None


class ListDatabasesResult(TypedDict):
    instances: list[DatabaseListing]
