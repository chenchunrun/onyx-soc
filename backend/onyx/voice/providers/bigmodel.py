from onyx.voice.providers.openai import OpenAIVoiceProvider

BIGMODEL_VOICE_API_BASE = "https://open.bigmodel.cn/api/paas/v4"
BIGMODEL_STT_MODELS = [
    {"id": "glm-asr-2512", "name": "GLM-ASR-2512"},
]
BIGMODEL_TTS_MODELS = [
    {"id": "glm-tts", "name": "GLM-TTS"},
]
BIGMODEL_VOICES = [
    {"id": "tongtong", "name": "Tongtong"},
]


class BigModelVoiceProvider(OpenAIVoiceProvider):
    def __init__(
        self,
        api_key: str | None,
        api_base: str | None = None,
        stt_model: str | None = None,
        tts_model: str | None = None,
        default_voice: str | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key,
            api_base=api_base or BIGMODEL_VOICE_API_BASE,
            stt_model=stt_model or "glm-asr-2512",
            tts_model=tts_model or "glm-tts",
            default_voice=default_voice or "tongtong",
        )

    def get_available_voices(self) -> list[dict[str, str]]:
        return BIGMODEL_VOICES.copy()

    def get_available_stt_models(self) -> list[dict[str, str]]:
        return BIGMODEL_STT_MODELS.copy()

    def get_available_tts_models(self) -> list[dict[str, str]]:
        return BIGMODEL_TTS_MODELS.copy()

    def supports_streaming_stt(self) -> bool:
        return False

    def supports_streaming_tts(self) -> bool:
        return False
