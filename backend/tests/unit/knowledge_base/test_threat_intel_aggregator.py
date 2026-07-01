from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = (
    REPO_ROOT / "knowledge-base" / "threat-intelligence" / "threat_intel_aggregator.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "threat_intel_aggregator", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extract_cncert_weekly_report_links_parses_index_entries() -> None:
    module = _load_module()
    index_html = """
    <ul class="waring_con">
      <li><span>[2026-04-03]</span><a href="javascript:void(0)" onclick='window.open("/publish/main/44/2026/report-a.html")'>网络安全信息与动态周报-2026年第12期</a></li>
      <li><span>[2026-03-23]</span><a href="javascript:void(0)" onclick='window.open("/publish/main/44/2026/report-b.html")'>网络安全信息与动态周报-2026年第11期</a></li>
    </ul>
    """

    result = module.extract_cncert_weekly_report_links(
        index_html,
        base_url="https://www.cert.org.cn/publish/main/44/index.html",
        max_reports=10,
    )

    assert len(result) == 2
    assert result[0]["published_date"] == "2026-04-03"
    assert result[0]["title"] == "网络安全信息与动态周报-2026年第12期"
    assert result[0]["page_url"] == "https://www.cert.org.cn/publish/main/44/2026/report-a.html"


def test_parse_cncert_weekly_report_page_extracts_metadata() -> None:
    module = _load_module()
    detail_html = """
    <h2 class="artil_tit"><font>网络安全信息与动态周报-2026年第12期</font></h2>
    <div class="artil_art">来源：CNCERT　时间：2026-04-03</div>
    <div class="artil_content">
      <p><a href="/publish/main/upload/File/Weekly-12.pdf">网络安全信息与动态周报-2026年第12期</a> (点击下载)</p>
    </div>
    """

    result = module.parse_cncert_weekly_report_page(
        detail_html,
        page_url="https://www.cert.org.cn/publish/main/44/2026/report-a.html",
        base_url="https://www.cert.org.cn/publish/main/44/index.html",
    )

    assert result["title"] == "网络安全信息与动态周报-2026年第12期"
    assert result["published_date"] == "2026-04-03"
    assert result["source"] == "CNCERT"
    assert result["pdf_url"] == "https://www.cert.org.cn/publish/main/upload/File/Weekly-12.pdf"


def test_fetch_cncert_weekly_reports_builds_records(monkeypatch) -> None:
    module = _load_module()
    index_url = "https://www.cert.org.cn/publish/main/44/index.html"
    page_url = "https://www.cert.org.cn/publish/main/44/2026/report-a.html"
    pdf_url = "https://www.cert.org.cn/publish/main/upload/File/Weekly-12.pdf"

    index_html = """
    <ul class="waring_con">
      <li><span>[2026-04-03]</span><a href="javascript:void(0)" onclick='window.open("/publish/main/44/2026/report-a.html")'>网络安全信息与动态周报-2026年第12期</a></li>
    </ul>
    """
    detail_html = """
    <h2 class="artil_tit"><font>网络安全信息与动态周报-2026年第12期</font></h2>
    <div class="artil_art">来源：CNCERT　时间：2026-04-03</div>
    <div class="artil_content">
      <p><a href="/publish/main/upload/File/Weekly-12.pdf">网络安全信息与动态周报-2026年第12期</a> (点击下载)</p>
    </div>
    """

    class _Response:
        def __init__(self, *, text: str = "", content: bytes = b"") -> None:
            self.text = text
            self.content = content

        def raise_for_status(self) -> None:
            return None

    def _fake_get(url: str, timeout: int = 30, headers=None):  # noqa: ARG001
        if url == index_url:
            return _Response(text=index_html)
        if url == page_url:
            return _Response(text=detail_html)
        if url == pdf_url:
            return _Response(content=b"%PDF-mock")
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(module.requests, "get", _fake_get)
    monkeypatch.setattr(module, "extract_pdf_text", lambda pdf_bytes, page_limit: "本周重点包括漏洞利用和攻击活动。")

    result = module.fetch_cncert_weekly_reports(index_url, max_reports=5, pdf_page_limit=2)

    assert len(result) == 1
    assert result[0]["source"] == "CNCERT"
    assert result[0]["publication_date"] == "2026-04-03"
    assert result[0]["title"] == "网络安全信息与动态周报-2026年第12期"
    assert "本周重点包括漏洞利用和攻击活动。" in result[0]["content"]
    assert result[0]["advisory_id"] == "CNCERT_WEEKLY_2026-04-03"


# ─── Adapter registry tests ───────────────────────────────────────────────────


class TestAdapterRegistry:
    def test_exact_match_resolves_registered_adapter(self) -> None:
        module = _load_module()
        assert module.get_adapter("cisa_kev") is module.CisaKevAdapter
        assert module.get_adapter("cncert_weekly_reports") is module.CncertWeeklyAdapter

    def test_prefix_wildcard_resolves_nvd_family(self) -> None:
        module = _load_module()
        for key in (
            "nvd_security_advisories",
            "nvd_ics_advisories",
            "nvd_medical_advisories",
            "nvd_something_new",
        ):
            assert module.get_adapter(key) is module.NvdKeywordAdapter, key

    def test_unknown_feed_returns_none(self) -> None:
        module = _load_module()
        assert module.get_adapter("totally_unknown_feed") is None
        assert module.get_adapter("") is None

    def test_exact_match_takes_priority_over_prefix(self) -> None:
        """If a key is registered both exactly and via prefix, exact wins."""
        module = _load_module()

        class _Custom:
            def fetch(self, feed: dict) -> list[dict]:
                return []

            def build_summary(self, records: list[dict], feed: dict) -> dict:
                return {}

        module.register_adapter("nvd_special")(_Custom)
        try:
            assert module.get_adapter("nvd_special") is _Custom
            # Other nvd_* keys still resolve to the prefix adapter.
            assert module.get_adapter("nvd_other") is module.NvdKeywordAdapter
        finally:
            module._FEED_ADAPTERS.pop("nvd_special", None)

    def test_register_adapter_supports_multiple_keys(self) -> None:
        module = _load_module()

        class _Multi:
            def fetch(self, feed: dict) -> list[dict]:
                return []

            def build_summary(self, records: list[dict], feed: dict) -> dict:
                return {}

        module.register_adapter("alpha", "beta")(_Multi)
        try:
            assert module.get_adapter("alpha") is _Multi
            assert module.get_adapter("beta") is _Multi
        finally:
            module._FEED_ADAPTERS.pop("alpha", None)
            module._FEED_ADAPTERS.pop("beta", None)


# ─── fetch_with_retry tests ───────────────────────────────────────────────────


class TestFetchWithRetry:
    def test_returns_result_on_success(self, monkeypatch) -> None:
        module = _load_module()
        monkeypatch.setattr(module.time, "sleep", lambda _: None)
        result = module.fetch_with_retry(lambda: [{"id": 1}], max_retries=3)
        assert result == [{"id": 1}]

    def test_retries_then_succeeds(self, monkeypatch) -> None:
        module = _load_module()
        monkeypatch.setattr(module.time, "sleep", lambda _: None)
        calls = {"n": 0}

        def _flaky() -> list[dict]:
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("transient")
            return [{"ok": True}]

        result = module.fetch_with_retry(_flaky, feed_key="test", max_retries=3)
        assert result == [{"ok": True}]
        assert calls["n"] == 3

    def test_returns_empty_after_exhausting_retries(self, monkeypatch) -> None:
        module = _load_module()
        monkeypatch.setattr(module.time, "sleep", lambda _: None)

        def _always_fail() -> list[dict]:
            raise RuntimeError("permanent")

        result = module.fetch_with_retry(_always_fail, feed_key="test", max_retries=2)
        assert result == []

    def test_uses_exponential_backoff(self, monkeypatch) -> None:
        module = _load_module()
        delays: list[float] = []
        monkeypatch.setattr(module.time, "sleep", lambda d: delays.append(d))

        def _fail() -> list[dict]:
            raise RuntimeError("boom")

        module.fetch_with_retry(_fail, feed_key="t", max_retries=3, backoff_base=2.0)
        # backoff_base ** attempt for attempts 1 and 2 (attempt 3 is final)
        assert delays == [2.0, 4.0]


# ─── CisaKevAdapter end-to-end (mocked HTTP) ──────────────────────────────────


class TestCisaKevAdapter:
    def test_fetch_and_build_summary(self, monkeypatch) -> None:
        module = _load_module()
        monkeypatch.setattr(module.time, "sleep", lambda _: None)

        fake_catalog = {
            "title": "CISA KEV Catalog",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vulnerability": {
                        "dateAdded": "2021-11-10",
                        "dueDate": "2022-05-03",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": "Log4Shell",
                        "shortDescription": "Remote code execution.",
                        "requiredAction": "Apply patch.",
                        "knownRansomwareCampaignUse": "Known",
                        "weaknesses": "CWE-502",
                        "notes": "",
                    },
                }
            ],
        }

        class _FakeResp:
            status_code = 200

            def json(self) -> dict:
                return fake_catalog

        monkeypatch.setattr(module.requests, "get", lambda *a, **kw: _FakeResp())

        feed = module.FEEDS["cisa_kev"]
        adapter = module.CisaKevAdapter()
        records = adapter.fetch(feed)
        assert len(records) == 1
        assert records[0]["cve_id"] == "CVE-2021-44228"
        assert "Remote code execution" in records[0]["content"]

        summary = adapter.build_summary(records, feed)
        assert summary["semantic_identifier"] == "CISA_KEV_Catalog_Summary"
        assert summary["severity"] == "CRITICAL"
        assert "Apache" in summary["content"] or "Total Known" in summary["content"]

    def test_fetch_returns_empty_on_persistent_failure(self, monkeypatch) -> None:
        module = _load_module()
        monkeypatch.setattr(module.time, "sleep", lambda _: None)

        class _FakeResp:
            status_code = 503

        monkeypatch.setattr(module.requests, "get", lambda *a, **kw: _FakeResp())
        records = module.CisaKevAdapter().fetch(module.FEEDS["cisa_kev"])
        assert records == []
