from onyx.redis.redis_connector import RedisConnector


def test_get_id_from_task_id_supports_three_segment_format() -> None:
    assert (
        RedisConnector.get_id_from_task_id(
            "connectordeletion_123_6dd32ded3-00aa-4884-8b21-42f8332e7fac"
        )
        == "123"
    )


def test_get_id_from_task_id_supports_execution_scoped_format() -> None:
    assert (
        RedisConnector.get_id_from_task_id(
            "connectordeletion_123_execabc_6dd32ded3-00aa-4884-8b21-42f8332e7fac"
        )
        == "123"
    )


def test_get_id_from_task_id_rejects_invalid_format() -> None:
    assert RedisConnector.get_id_from_task_id("invalid") is None
