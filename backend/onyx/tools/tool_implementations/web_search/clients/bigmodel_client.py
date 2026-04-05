from __future__ import annotations

from datetime import datetime
from typing import Any

import requests
from fastapi import HTTPException

from onyx.tools.tool_implementations.web_search.models import (
    WebSearchProvider,
)
from onyx.tools.tool_implementations.web_search.models import WebSearchResult
from onyx.utils.logger import setup_logger
from onyx.utils.retry_wrapper import retry_builder

logger = setup_logger()

BIGMODEL_SEARCH_URL = "https://open.bigmodel.cn/api/paas/v4/web_search"
BIGMODEL_SOURCE_CHANNEL = "python-sdk"
BIGMODEL_REQUEST_TIMEOUT_SECONDS = 60


class BigModelClient(WebSearchProvider):
    """BigModel (智谱) web search provider.

    API Docs: https://open.bigmodel.cn/dev/api
    Base URL: https://open.bigmodel.cn/api/paas/v4
    Endpoint: POST /web_search
    """

    def __init__(
        self,
        api_key: str,
        *,
        num_results: int = 10,
        content_size: str = "medium",
    ) -> None:
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "x-source-channel": BIGMODEL_SOURCE_CHANNEL,
            "Content-Type": "application/json",
        }
        self._num_results = min(max(1, num_results), 50)
        self._content_size = content_size

    @retry_builder(tries=3, delay=1, backoff=2)
    def search(self, query: str) -> list[WebSearchResult]:
        payload: dict[str, Any] = {
            "search_engine": "search_pro",
            "search_query": query,
            "count": self._num_results,
            "content_size": self._content_size,
        }

        response = requests.post(
            BIGMODEL_SEARCH_URL,
            headers=self._headers,
            json=payload,
            timeout=BIGMODEL_REQUEST_TIMEOUT_SECONDS,
        )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            error_msg = _build_error_message(response)
            raise ValueError(error_msg) from exc

        data = response.json()
        search_results = data.get("search_result") or []

        results: list[WebSearchResult] = []
        for result in search_results:
            if not isinstance(result, dict):
                continue

            link = (result.get("link") or "").strip()
            if not link:
                continue

            title = (result.get("title") or "").strip()
            snippet = (result.get("content") or "").strip()

            published_date: datetime | None = None
            publish_date_str = (result.get("publish_date") or "").strip()
            if publish_date_str:
                try:
                    # BigModel returns dates like "2025-05-23"
                    published_date = datetime.strptime(publish_date_str, "%Y-%m-%d")
                except ValueError:
                    published_date = None

            results.append(
                WebSearchResult(
                    title=title,
                    link=link,
                    snippet=snippet,
                    author=None,
                    published_date=published_date,
                )
            )

        return results

    def test_connection(self) -> dict[str, str]:
        try:
            test_results = self.search("test")
            if not test_results or not any(result.link for result in test_results):
                raise HTTPException(
                    status_code=400,
                    detail="BigModel API key validation failed: search returned no results.",
                )
        except HTTPException:
            raise
        except Exception as e:
            error_msg = str(e)
            lower = error_msg.lower()
            if (
                "401" in lower
                or "403" in lower
                or "api" in lower
                or "key" in lower
                or "auth" in lower
                or "unauthorized" in lower
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid BigModel API key: {error_msg}",
                ) from e
            raise HTTPException(
                status_code=400,
                detail=f"BigModel API key validation failed: {error_msg}",
            ) from e

        logger.info("Web search provider test succeeded for BigModel.")
        return {"status": "ok"}


def _build_error_message(response: requests.Response) -> str:
    try:
        payload: Any = response.json()
    except Exception:
        text = response.text.strip()
        return text[:200] if text else f"HTTP {response.status_code}"

    if isinstance(payload, dict):
        error = payload.get("error") or payload.get("message")
        if isinstance(error, str):
            return error
        if isinstance(error, dict):
            detail = error.get("detail") or error.get("message")
            if isinstance(detail, str):
                return detail

    return f"HTTP {response.status_code}: {str(payload)[:200]}"
