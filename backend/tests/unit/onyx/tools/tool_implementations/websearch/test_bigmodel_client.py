"""Unit tests for the BigModel web search client."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import requests

from onyx.tools.tool_implementations.web_search.clients.bigmodel_client import (
    BigModelClient,
)
from onyx.tools.tool_implementations.web_search.models import WebSearchResult


class TestBigModelClient:
    """Tests for BigModelClient."""

    def test_search_parses_results_correctly(self) -> None:
        """Test that search correctly parses BigModel API response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "created": 1775397751,
            "id": "202604052202312da1ea3530d44c59",
            "request_id": "202604052202312da1ea3530d44c59",
            "search_intent": [
                {
                    "intent": "SEARCH_ALWAYS",
                    "keywords": "test",
                    "query": "test",
                }
            ],
            "search_result": [
                {
                    "content": "Test content snippet",
                    "icon": "https://example.com/icon.jpg",
                    "link": "https://example.com/article",
                    "media": "Example Media",
                    "publish_date": "2025-05-23",
                    "refer": "ref_1",
                    "title": "Test Article Title",
                },
                {
                    "content": "Second result content",
                    "icon": "https://example.com/icon2.jpg",
                    "link": "https://example.com/article2",
                    "media": "Example Media 2",
                    "publish_date": "2025-06-01",
                    "refer": "ref_2",
                    "title": "Second Article Title",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key", num_results=10)
            results = client.search("test query")

        assert len(results) == 2
        assert results[0].title == "Test Article Title"
        assert results[0].link == "https://example.com/article"
        assert results[0].snippet == "Test content snippet"
        assert results[1].title == "Second Article Title"
        assert results[1].link == "https://example.com/article2"
        assert results[1].snippet == "Second result content"

    def test_search_skips_results_without_link(self) -> None:
        """Test that search skips results without a valid link."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "search_result": [
                {
                    "content": "Has link",
                    "link": "https://example.com/valid",
                    "title": "Valid Result",
                    "publish_date": "2025-05-23",
                },
                {
                    "content": "No link",
                    "link": "",
                    "title": "Invalid Result",
                },
                {
                    "content": "None link",
                    "link": None,  # type: ignore
                    "title": "Also Invalid",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            results = client.search("test")

        assert len(results) == 1
        assert results[0].title == "Valid Result"

    def test_search_handles_empty_results(self) -> None:
        """Test that search handles empty search_result gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "search_result": [],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            results = client.search("test")

        assert len(results) == 0

    def test_search_handles_missing_search_result_field(self) -> None:
        """Test that search handles missing search_result field gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "created": 1775397751,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            results = client.search("test")

        assert len(results) == 0

    def test_search_parses_publish_date(self) -> None:
        """Test that search parses publish_date correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "search_result": [
                {
                    "content": "Content",
                    "link": "https://example.com",
                    "title": "Title",
                    "publish_date": "2025-05-23",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            results = client.search("test")

        assert len(results) == 1
        assert results[0].published_date is not None
        assert results[0].published_date.year == 2025
        assert results[0].published_date.month == 5
        assert results[0].published_date.day == 23

    def test_search_handles_invalid_publish_date(self) -> None:
        """Test that search handles invalid publish_date gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "search_result": [
                {
                    "content": "Content",
                    "link": "https://example.com",
                    "title": "Title",
                    "publish_date": "not-a-date",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            results = client.search("test")

        assert len(results) == 1
        assert results[0].published_date is None

    def test_search_raises_on_http_error(self) -> None:
        """Test that search raises ValueError on HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "Unauthorized"}'
        mock_response.json.return_value = {"error": "Unauthorized"}

        def raise_for_status() -> None:
            raise requests.HTTPError("401 Unauthorized")

        mock_response.raise_for_status = raise_for_status

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="bad-key")
            with pytest.raises(ValueError, match="Unauthorized"):
                client.search("test")

    def test_search_uses_correct_headers(self) -> None:
        """Test that search uses correct authentication headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"search_result": []}
        mock_response.raise_for_status = MagicMock()

        captured_request: dict[str, Any] = {}

        def capture_post(url: str, **kwargs: Any) -> MagicMock:
            captured_request["url"] = url
            captured_request["headers"] = kwargs.get("headers", {})
            captured_request["json"] = kwargs.get("json", {})
            return mock_response

        with patch("requests.post", side_effect=capture_post):
            client = BigModelClient(api_key="my-secret-key", num_results=15)
            client.search("my query")

        assert captured_request["url"] == "https://open.bigmodel.cn/api/paas/v4/web_search"
        headers = captured_request["headers"]
        assert headers["Authorization"] == "Bearer my-secret-key"
        assert headers["x-source-channel"] == "python-sdk"
        assert headers["Content-Type"] == "application/json"

        json_body = captured_request["json"]
        assert json_body["search_engine"] == "search_pro"
        assert json_body["search_query"] == "my query"
        assert json_body["count"] == 15
        assert json_body["content_size"] == "medium"

    def test_search_uses_timeout(self) -> None:
        """Test that search uses a timeout on the HTTP request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"search_result": []}
        mock_response.raise_for_status = MagicMock()

        captured_kwargs: dict[str, Any] = {}

        def capture_post(url: str, **kwargs: Any) -> MagicMock:
            captured_kwargs.update(kwargs)
            return mock_response

        with patch("requests.post", side_effect=capture_post):
            client = BigModelClient(api_key="test-key")
            client.search("test")

        assert "timeout" in captured_kwargs
        assert captured_kwargs["timeout"] == 60

    def test_test_connection_success(self) -> None:
        """Test that test_connection returns ok on successful search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "search_result": [
                {
                    "content": "Found something",
                    "link": "https://example.com",
                    "title": "Result",
                    "publish_date": "2025-05-23",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            result = client.test_connection()

        assert result == {"status": "ok"}

    def test_test_connection_raises_on_empty_results(self) -> None:
        """Test that test_connection raises HTTPException on empty results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"search_result": []}
        mock_response.raise_for_status = MagicMock()

        from fastapi import HTTPException

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="test-key")
            with pytest.raises(HTTPException, match="no results"):
                client.test_connection()

    def test_test_connection_raises_on_auth_error(self) -> None:
        """Test that test_connection provides clear error on auth failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        def raise_for_status() -> None:
            raise requests.HTTPError("401 Unauthorized")

        mock_response.raise_for_status = raise_for_status

        from fastapi import HTTPException

        with patch("requests.post", return_value=mock_response):
            client = BigModelClient(api_key="bad-key")
            with pytest.raises(HTTPException, match="Invalid BigModel API key"):
                client.test_connection()

    def test_num_results_clamped_to_valid_range(self) -> None:
        """Test that num_results is clamped to [1, 50]."""
        client = BigModelClient(api_key="test-key", num_results=0)
        assert client._num_results == 1

        client = BigModelClient(api_key="test-key", num_results=100)
        assert client._num_results == 50

        client = BigModelClient(api_key="test-key", num_results=25)
        assert client._num_results == 25
