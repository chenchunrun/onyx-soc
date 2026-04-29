from unittest.mock import MagicMock

from onyx.db.enums import ConnectorCredentialPairStatus
from onyx.server.manage.administrative import create_deletion_attempt_for_connector_id
from onyx.server.documents.models import ConnectorCredentialPairIdentifier


def test_deletion_attempt_commits_deleting_before_external_side_effects(
    monkeypatch,
) -> None:
    events: list[str] = []
    db_session = MagicMock()
    db_session.commit.side_effect = lambda: events.append("commit")

    cc_pair = MagicMock()
    cc_pair.id = 123
    cc_pair.connector.source = "slack"

    redis_connector = MagicMock()
    redis_connector.delete.reset.side_effect = lambda: events.append("redis_reset")
    redis_connector.stop.set_fence.side_effect = lambda _value: events.append(
        "redis_fence"
    )
    redis_connector.stop.set_timeout.side_effect = lambda: events.append(
        "redis_timeout"
    )

    def update_status(**kwargs: object) -> None:
        assert kwargs["status"] == ConnectorCredentialPairStatus.DELETING
        events.append("update_status")

    monkeypatch.setattr(
        "onyx.server.manage.administrative.get_current_tenant_id",
        lambda: "tenant",
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.get_connector_credential_pair_for_user",
        lambda **_kwargs: cc_pair,
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.update_connector_credential_pair_from_id",
        update_status,
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.RedisConnector",
        lambda **_kwargs: redis_connector,
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.revoke_tasks_blocking_deletion",
        lambda **_kwargs: events.append("revoke"),
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.cancel_indexing_attempts_for_ccpair",
        lambda **_kwargs: events.append("cancel_indexing"),
    )
    monkeypatch.setattr(
        "onyx.server.manage.administrative.client_app.send_task",
        lambda *_args, **_kwargs: events.append("send_task"),
    )

    create_deletion_attempt_for_connector_id(
        ConnectorCredentialPairIdentifier(connector_id=10, credential_id=20),
        user=MagicMock(),
        db_session=db_session,
    )

    assert events[:2] == ["update_status", "commit"]
    assert events[2:] == [
        "redis_reset",
        "redis_fence",
        "redis_timeout",
        "revoke",
        "cancel_indexing",
        "commit",
        "send_task",
    ]
