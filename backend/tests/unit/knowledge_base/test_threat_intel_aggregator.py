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
