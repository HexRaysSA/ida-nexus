"""Public exception hierarchy for IDA Nexus clients."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .database_state import DatabaseFileState


class NexusError(RuntimeError):
    """Base class for recoverable IDA Nexus service errors."""


class NexusConnectionError(NexusError):
    """A Nexus instance could not be reached or used."""


class DatabaseDisconnectedError(NexusConnectionError):
    """A previously attached database instance disconnected permanently."""


class RemoteError(NexusError):
    """The Nexus service rejected an operation with a structured error."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class DatabaseOpenError(NexusError):
    """A requested database instance could not be resolved or opened."""


class NoDatabaseInstanceError(DatabaseOpenError):
    """No matching live instance exists and spawning was disabled."""


class DatabaseBusyError(DatabaseOpenError):
    """A matching database is owned by an unusable or conflicting instance."""


class AmbiguousDatabaseError(DatabaseOpenError):
    """More than one live instance matches a requested database."""


class WorkerStartError(DatabaseOpenError):
    """A managed idalib worker failed to become ready."""


class DatabaseSelectionError(NexusError):
    """A multi-database manager has no valid selected target."""


class DatabaseCrashedError(DatabaseDisconnectedError):
    """An IDA process crashed and left a dirty unpacked database."""

    def __init__(self, message: str, database_state: "DatabaseFileState") -> None:
        super().__init__(message)
        self.database_state = database_state
