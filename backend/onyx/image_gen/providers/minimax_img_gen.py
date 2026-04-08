from __future__ import annotations

from typing import Any

import requests
from litellm.types.utils import ImageObject
from litellm.types.utils import ImageResponse

from onyx.image_gen.interfaces import ImageGenerationProvider
from onyx.image_gen.interfaces import ImageGenerationProviderCredentials
from onyx.image_gen.interfaces import ReferenceImage

MINIMAX_IMAGE_API_BASE = "https://api.minimax.io"
_SIZE_TO_ASPECT_RATIO = {
    "1024x1024": "1:1",
    "1024x1536": "2:3",
    "1536x1024": "3:2",
}


class MiniMaxImageGenerationProvider(ImageGenerationProvider):
    def __init__(self, api_key: str, api_base: str | None = None) -> None:
        self._api_key = api_key
        self._api_base = (api_base or MINIMAX_IMAGE_API_BASE).rstrip("/")

    @classmethod
    def validate_credentials(
        cls,
        credentials: ImageGenerationProviderCredentials,
    ) -> bool:
        return bool(credentials.api_key)

    @classmethod
    def _build_from_credentials(
        cls,
        credentials: ImageGenerationProviderCredentials,
    ) -> "MiniMaxImageGenerationProvider":
        assert credentials.api_key
        return cls(
            api_key=credentials.api_key,
            api_base=credentials.api_base,
        )

    def generate_image(
        self,
        prompt: str,
        model: str,
        size: str,
        n: int,
        quality: str | None = None,
        reference_images: list[ReferenceImage] | None = None,
        **kwargs: Any,
    ) -> ImageResponse:
        if reference_images:
            raise ValueError("MiniMax image generation does not support reference images.")

        response = requests.post(
            f"{self._api_base}/v1/image_generation",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "prompt": prompt,
                "aspect_ratio": _SIZE_TO_ASPECT_RATIO.get(size, "1:1"),
                "response_format": "base64",
                "n": n,
            },
            timeout=120,
        )
        response.raise_for_status()
        response_json = response.json()

        response_data = response_json.get("data", {})
        if isinstance(response_data, list):
            image_base64_list = [
                item.get("image_base64")
                for item in response_data
                if isinstance(item, dict) and item.get("image_base64")
            ]
        else:
            image_base64_list = response_data.get("image_base64", [])
        image_objects = [
            ImageObject(b64_json=image_base64, revised_prompt=prompt)
            for image_base64 in image_base64_list
        ]

        return ImageResponse(
            created=0,
            data=image_objects,
            size=size,
            quality=quality,
        )
