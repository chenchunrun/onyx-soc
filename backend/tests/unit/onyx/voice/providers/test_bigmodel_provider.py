from onyx.voice.providers.bigmodel import BigModelVoiceProvider


def test_bigmodel_provider_default_models() -> None:
    provider = BigModelVoiceProvider(api_key="test")
    assert provider.stt_model == "glm-asr-2512"
    assert provider.tts_model == "glm-tts"
    assert provider.default_voice == "tongtong"


def test_bigmodel_provider_is_non_streaming() -> None:
    provider = BigModelVoiceProvider(api_key="test")
    assert provider.supports_streaming_stt() is False
    assert provider.supports_streaming_tts() is False


def test_bigmodel_provider_returns_static_options() -> None:
    provider = BigModelVoiceProvider(api_key="test")
    assert provider.get_available_stt_models()[0]["id"] == "glm-asr-2512"
    assert provider.get_available_tts_models()[0]["id"] == "glm-tts"
    assert provider.get_available_voices()[0]["id"] == "tongtong"
