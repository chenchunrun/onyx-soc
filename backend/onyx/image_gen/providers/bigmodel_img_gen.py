from __future__ import annotations

import base64
from typing import Any

import requests
from litellm.types.utils import ImageObject
from litellm.types.utils import ImageResponse

from onyx.image_gen.interfaces import ImageGenerationProvider
from onyx.image_gen.interfaces import ImageGenerationProviderCredentials
from onyx.image_gen.interfaces import ReferenceImage

BIGMODEL_IMAGE_API_BASE = "https://open.bigmodel.cn/api/paas/v4"


class BigModelImageGenerationProvider(ImageGenerationProvider):
    def __init__(self, api_key: str, api_base: str | None = None) -> None:
        self._api_key = api_key
        self._api_base = (api_base or BIGMODEL_IMAGE_API_BASE).rstrip("/")

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
    ) -> "BigModelImageGenerationProvider":
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
            raise ValueError("BigModel image generation does not support reference images.")

        response = requests.post(
            f"{self._api_base}/images/generations",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "prompt": prompt,
                "size": size,
                "n": n,
            },
            timeout=120,
        )
        response.raise_for_status()
        response_json = response.json()

        image_objects: list[ImageObject] = []
        for image_data in response_json.get("data", []):
            image_url = image_data.get("url")
            if not image_url:
                continue
            image_response = requests.get(image_url, timeout=120)
            image_response.raise_for_status()
            image_objects.append(
                ImageObject(
                    b64_json=base64.b64encode(image_response.content).decode("utf-8"),
                    revised_prompt=prompt,
                    url=image_url,
                )
            )

        return ImageResponse(
            created=response_json.get("created", 0),
            data=image_objects,
            size=size,
            quality=quality,
        )
