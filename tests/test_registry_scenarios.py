"""Registry metadata may be damaged; a live lifetime lock still owns the IDB."""

import json

import pytest

from ida_nexus import _registry as registry
from ida_nexus._registry import (
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    InstanceState,
)


@pytest.fixture
def published(tmp_path):
    registration = InstanceRegistration(
        tmp_path / "registry",
        InstanceIdentity(str(tmp_path / "db.i64"), "", "idalib", managed=True),
        token="test-token",
    )
    try:
        entry = registration.publish(12345)
        yield registration, entry
    finally:
        registration.release()


def test_invalid_live_record_is_not_reaped_until_lock_is_released(published):
    registration, _entry = published
    path = registration.registry_path
    path.write_text("{partial JSON", encoding="utf-8")
    assert registry.scan_instances(registration.directory) == []
    assert path.exists()
    registration.release()
    assert path.exists()  # release cannot authenticate malformed metadata
    assert registry.scan_instances(registration.directory) == []
    assert not path.exists()


@pytest.mark.parametrize("payload", [{"token": "someone-else"}, [], "malformed"])
def test_withdraw_never_deletes_unauthenticated_record(published, payload):
    registration, _entry = published
    path = registration.registry_path
    data = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(data, encoding="utf-8")
    registration.release()
    registration.release()
    assert path.read_text(encoding="utf-8") == data
    lock = FileLock(registration.lock.path)
    try:
        lock.acquire(timeout=0)
    finally:
        lock.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("record_id", "wrong"),
        ("backend", "other"),
        ("pid", True),
        ("pid", 0),
        ("port", 0),
        ("port", 65536),
        ("token", ""),
        ("version", True),
        ("idb_path", ""),
        ("idb_key", "wrong"),
        ("exe_path", None),
        ("managed", "yes"),
        ("started_at", "yesterday"),
    ],
)
def test_invalid_identity_fields_cannot_be_loaded_or_reap_live_owner(
    published, field, value
):
    registration, entry = published
    payload = entry._registry_payload()
    payload[field] = value
    path = registration.registry_path
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        registry.load_registry_entry(path)
    assert registry.scan_instances(registration.directory) == []
    assert path.exists()


@pytest.mark.parametrize("boundary", ["fsync", "replace"])
def test_failed_publication_leaves_no_partial_record_and_can_retry(
    tmp_path, monkeypatch, boundary
):
    registration = InstanceRegistration(
        tmp_path / "registry",
        InstanceIdentity(str(tmp_path / "db.i64"), "", "idalib"),
        token="test-token",
    )
    try:
        with monkeypatch.context() as patch:

            def fail(*_args):
                raise OSError("publication failed")

            patch.setattr(registry.os, boundary, fail)
            with pytest.raises(OSError, match="publication failed"):
                registration.publish(12345)
        assert list(registration.directory.glob("*.json")) == []
        assert list(registration.directory.glob("*.tmp")) == []
        entry = registration.publish(12345)
        assert registration.publish(54321) is entry
        assert registry.load_registry_entry(registration.registry_path) == entry
    finally:
        registration.release()


def test_failed_health_probe_blocks_live_owner_without_reaping(published, monkeypatch):
    registration, entry = published
    monkeypatch.setattr(
        registry, "probe_health", lambda *_a, **_k: (False, "identity mismatch")
    )
    found = registry.scan_instances(registration.directory)
    assert len(found) == 1
    assert found[0].instance == entry
    assert found[0].state is InstanceState.BLOCKED
    assert "identity mismatch" in found[0].detail
    assert registration.registry_path.exists()
