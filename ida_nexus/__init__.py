"""Public Python API for authenticated IDA Nexus database sessions."""

from ._remote import (
    OperationLabel,
    RemoteCodec,
    RemoteExecutor,
    RemoteFunction,
    RemoteModule,
    remote_ida,
)
from .database_state import (
    DatabaseFileState,
    DatabaseFileStateName,
    DatabaseRecovery,
    probe_database_state,
)
from .errors import (
    AmbiguousDatabaseError,
    DatabaseBusyError,
    DatabaseCrashedError,
    DatabaseDisconnectedError,
    DatabaseOpenError,
    DatabaseSelectionError,
    NexusConnectionError,
    NexusError,
    NoDatabaseInstanceError,
    RemoteError,
    WorkerStartError,
)
from .handle import DatabaseChangeSubscription, DatabaseHandle
from .instances import (
    DatabaseInstance,
    DiscoveredDatabase,
    InstanceState,
    discover_databases,
    find_database_owner,
    wait_database_released,
)
from .manager import (
    CloseDatabaseResult,
    DatabaseEventCallback,
    DatabaseListing,
    DatabaseManager,
    ListDatabasesResult,
    OpenDatabaseResult,
    SaveDatabaseResult,
    WaitAutoanalysisResult,
)
from .models import (
    AnalysisResult,
    DatabaseChangeEvent,
    PythonExecutionResult,
    SaveResult,
    ShutdownResult,
)
from .options import DatabaseOpenOptions
from .paths import get_state_dir
from .reference import get_ida_domain_version, reference

__all__ = [
    "AmbiguousDatabaseError",
    "AnalysisResult",
    "CloseDatabaseResult",
    "DatabaseBusyError",
    "DatabaseChangeEvent",
    "DatabaseChangeSubscription",
    "DatabaseCrashedError",
    "DatabaseDisconnectedError",
    "DatabaseEventCallback",
    "DatabaseFileState",
    "DatabaseFileStateName",
    "DatabaseHandle",
    "DatabaseInstance",
    "DatabaseListing",
    "DatabaseManager",
    "DatabaseOpenError",
    "DatabaseOpenOptions",
    "DatabaseRecovery",
    "DatabaseSelectionError",
    "DiscoveredDatabase",
    "InstanceState",
    "ListDatabasesResult",
    "NexusConnectionError",
    "NexusError",
    "NoDatabaseInstanceError",
    "OpenDatabaseResult",
    "OperationLabel",
    "PythonExecutionResult",
    "RemoteCodec",
    "RemoteError",
    "RemoteExecutor",
    "RemoteFunction",
    "RemoteModule",
    "SaveDatabaseResult",
    "SaveResult",
    "ShutdownResult",
    "WaitAutoanalysisResult",
    "WorkerStartError",
    "discover_databases",
    "find_database_owner",
    "get_ida_domain_version",
    "get_state_dir",
    "probe_database_state",
    "reference",
    "remote_ida",
    "wait_database_released",
]
