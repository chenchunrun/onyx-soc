#!/usr/bin/env python3
"""
Mock Security Tools Server

Simulates the security tools for end-to-end testing:
- send_security_alert: POST / → Slack/Teams/PagerDuty webhook
- create_security_ticket: POST /issue → Jira/Linear/ServiceNow
- threat_intel_lookup: GET /ip_addresses/{ip}, GET /domains/{domain}, GET /files/{hash}
- search_security_alerts: GET /alerts/search
- isolate_endpoint_host: POST /hosts/{host_id}/isolate
- lookup_asset_context: GET /assets/search

Usage:
    python mock_tools_server.py [--port PORT] [--verbose]
    python mock_tools_server.py --port 9999 --verbose
"""

import argparse
import hashlib
import json
import random
import re
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

# ANSI colors for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"
CYAN = "\033[96m"

# Global log store
RECEIVED_REQUESTS: list[dict] = []
MOCK_DB: dict[str, Any] = {}


def log(tag: str, color: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{color}[{ts}] {tag}{RESET} {msg}", flush=True)


def log_request(method: str, path: str, body: dict | None, headers: dict):
    log("REQUEST", CYAN, f"{method} {path}")
    if body:
        log("  BODY", BLUE, json.dumps(body, indent=2, ensure_ascii=False)[:500])
    api_key = headers.get("x-apikey", "none")
    log("  AUTH", BLUE, f"x-apikey: {api_key[:8]}..." if len(api_key) > 8 else f"x-apikey: {api_key}")
    RECEIVED_REQUESTS.append({
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "path": path,
        "body": body,
        "headers": {k: v for k, v in headers.items() if k.lower() not in ("host", "user-agent", "content-length")},
    })


# ─── Mock Data ────────────────────────────────────────────────────────────────

KNOWN_MALICIOUS_IPS = {
    "1.2.3.4": {"malicious": True, "country": "CN", "as_owner": "Test ASN", "reputation": -85, "tags": ["spam", "bot"]},
    "5.6.7.8": {"malicious": True, "country": "RU", "as_owner": "Test ASN", "reputation": -95, "tags": ["apt", "nation-state"]},
    "8.8.8.8": {"malicious": False, "country": "US", "as_owner": "Google LLC", "reputation": 100, "tags": ["dns", "resolver"]},
    "1.1.1.1": {"malicious": False, "country": "US", "as_owner": "Cloudflare", "reputation": 100, "tags": ["dns", "resolver"]},
}

KNOWN_MALICIOUS_DOMAINS = {
    "amaz0n-security.com": {"malicious": True, "registrar": "NameCheap", "created": "2024-01-15", "tags": ["phishing", "brand-impersonation"]},
    "micros0ft-verify.com": {"malicious": True, "registrar": "GoDaddy", "created": "2024-02-20", "tags": ["phishing", "credential-theft"]},
    "paypa1-secure.com": {"malicious": True, "registrar": "NameCheap", "created": "2024-03-10", "tags": ["phishing", "financial"]},
    "google.com": {"malicious": False, "registrar": "MarkMonitor", "created": "1997-09-15", "tags": ["legitimate", "search-engine"]},
    "github.com": {"malicious": False, "registrar": "MarkMonitor", "created": "2007-08-25", "tags": ["legitimate", "code-hosting"]},
}

KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": {"malicious": True, "names": ["EICAR Test File"], "type": "test"},
    "e3b0c44298fc1c149afbf4c8996fb924": {"malicious": False, "names": ["Empty file"], "type": "hash-only"},
}

MOCK_ALERTS = [
    {
        "id": "ALERT-1001",
        "title": "Suspicious PowerShell from finance-host-01",
        "severity": "high",
        "status": "open",
        "source": "EDR",
        "asset": "finance-host-01",
        "created_at": "2026-04-07T09:00:00Z",
    },
    {
        "id": "ALERT-1002",
        "title": "Outbound connection to rare domain from vpn-user-12",
        "severity": "medium",
        "status": "investigating",
        "source": "SIEM",
        "asset": "vpn-user-12",
        "created_at": "2026-04-07T09:30:00Z",
    },
]

MOCK_ASSETS = [
    {
        "asset_id": "asset-001",
        "hostname": "finance-host-01",
        "ip": "10.20.1.15",
        "environment": "prod",
        "business_owner": "Finance",
        "criticality": "high",
        "tags": ["windows", "finance", "endpoint"],
    },
    {
        "asset_id": "asset-002",
        "hostname": "hr-app-01",
        "ip": "10.20.8.21",
        "environment": "prod",
        "business_owner": "HR",
        "criticality": "medium",
        "tags": ["linux", "hr", "server"],
    },
]


def ip_lookup(ip: str) -> dict:
    """Simulate IP threat intelligence lookup."""
    info = KNOWN_MALICIOUS_IPS.get(ip)
    if info is None:
        # Generate plausible data for unknown IPs
        h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        return {
            "malicious": h % 10 == 0,
            "country": ["US", "CN", "DE", "JP", "BR", "IN", "RU"][h % 7],
            "as_owner": f"ASN-{1000 + (h % 9000)}",
            "reputation": (h % 100) - 50,
            "tags": [],
        }

    return {
        "country": info["country"],
        "as_owner": info["as_owner"],
        "reputation": info["reputation"],
        "tags": info["tags"],
        "last_analysis_stats": {
            "malicious": 85 if info["malicious"] else 0,
            "suspicious": 10 if info["malicious"] else 0,
            "harmless": 0 if info["malicious"] else 85,
            "undetected": 5,
        },
    }


def domain_lookup(domain: str) -> dict:
    """Simulate domain threat intelligence lookup."""
    info = KNOWN_MALICIOUS_DOMAINS.get(domain)
    if info is None:
        return {
            "malicious": False,
            "registrar": "Unknown",
            "tags": [],
        }
    return {
        "malicious": info["malicious"],
        "registrar": info["registrar"],
        "created_date": info["created"],
        "tags": info["tags"],
    }


def hash_lookup(hash_val: str) -> dict:
    """Simulate file hash threat intelligence lookup."""
    info = KNOWN_MALICIOUS_HASHES.get(hash_val)
    if info is None:
        h = int(hashlib.md5(hash_val.encode()).hexdigest()[:8], 16)
        return {
            "malicious": False,
            "names": [],
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 70,
                "undetected": 30,
            },
        }
    return {
        "malicious": info["malicious"],
        "names": info["names"],
        "last_analysis_stats": {
            "malicious": 95 if info["malicious"] else 0,
            "suspicious": 5 if info["malicious"] else 0,
            "harmless": 0 if info["malicious"] else 70,
            "undetected": 5,
        },
    }


# ─── Request Handler ───────────────────────────────────────────────────────────

class MockToolsHandler(BaseHTTPRequestHandler):
    """Handles all mock tool requests."""

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _parse_json(self) -> dict | None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def _read_headers(self) -> dict:
        return {k: v for k, v in self.headers.items()}

    def _cors_preflight(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-apikey, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        self._cors_preflight()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        headers = self._read_headers()

        # ── Threat Intel: IP lookup ──
        m = re.match(r"/ip_addresses/(.+)", path)
        if m:
            ip = m.group(1)
            log_request("GET", path, None, headers)
            result = ip_lookup(ip)
            data = {
                "data": {
                    "attributes": result
                }
            }
            self._set_headers(200)
            self.wfile.write(json.dumps(data).encode("utf-8"))
            log("RESPONSE", GREEN, f"IP {ip}: malicious={result.get('malicious')}, country={result.get('country')}")
            return

        # ── Threat Intel: Domain lookup ──
        m = re.match(r"/domains/(.+)", path)
        if m:
            domain = m.group(1)
            log_request("GET", path, None, headers)
            result = domain_lookup(domain)
            self._set_headers(200)
            self.wfile.write(json.dumps({"data": {"attributes": result}}).encode("utf-8"))
            log("RESPONSE", GREEN, f"Domain {domain}: malicious={result.get('malicious')}")
            return

        if path == "/alerts/search":
            query_params = parse_qs(parsed.query)
            query = (query_params.get("query", [""])[0] or "").lower()
            severity = (query_params.get("severity", [""])[0] or "").lower()
            limit = int((query_params.get("limit", ["10"])[0] or "10"))
            log_request("GET", self.path, None, headers)

            alerts = [
                alert
                for alert in MOCK_ALERTS
                if (
                    not query
                    or query in json.dumps(alert, ensure_ascii=False).lower()
                )
                and (not severity or str(alert["severity"]).lower() == severity)
            ][:limit]

            self._set_headers(200)
            self.wfile.write(json.dumps({"alerts": alerts}).encode("utf-8"))
            log("RESPONSE", GREEN, f"SIEM alerts returned: {len(alerts)}")
            return

        if path == "/assets/search":
            query_params = parse_qs(parsed.query)
            hostname = (query_params.get("hostname", [""])[0] or "").lower()
            ip = (query_params.get("ip", [""])[0] or "").lower()
            owner = (query_params.get("owner", [""])[0] or "").lower()
            limit = int((query_params.get("limit", ["10"])[0] or "10"))
            log_request("GET", self.path, None, headers)

            assets = [
                asset
                for asset in MOCK_ASSETS
                if (not hostname or hostname in asset["hostname"].lower())
                and (not ip or ip == asset["ip"].lower())
                and (
                    not owner
                    or owner in str(asset["business_owner"]).lower()
                )
            ][:limit]

            self._set_headers(200)
            self.wfile.write(json.dumps({"assets": assets}).encode("utf-8"))
            log("RESPONSE", GREEN, f"Asset records returned: {len(assets)}")
            return

        # ── Threat Intel: Hash lookup ──
        m = re.match(r"/files/(.+)", path)
        if m:
            hash_val = m.group(1)
            log_request("GET", path, None, headers)
            result = hash_lookup(hash_val)
            self._set_headers(200)
            self.wfile.write(json.dumps({"data": {"attributes": result}}).encode("utf-8"))
            log("RESPONSE", GREEN, f"Hash {hash_val[:16]}...: malicious={result.get('malicious')}")
            return

        # ── Health check ──
        if path == "/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "ok", "requests_received": len(RECEIVED_REQUESTS)}).encode())
            return

        # ── Get received requests ──
        if path == "/__requests__":
            self._set_headers(200)
            self.wfile.write(json.dumps(RECEIVED_REQUESTS, default=str).encode())
            return

        # 404
        log("404", RED, f"Unknown path: {path}")
        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Not found", "path": path}).encode())

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ── Clear received requests ──
        if path == "/__requests__":
            RECEIVED_REQUESTS.clear()
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "cleared"}).encode())
            log("DELETE", CYAN, "/__requests__ (cleared)")
            return

        log("404", RED, f"DELETE {path}")
        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Not found", "path": path}).encode())

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._parse_json()
        headers = self._read_headers()

        # ── Security Alert Webhook ──
        if path == "/" or path == "/webhook":
            log_request("POST", path, body, headers)

            # Simulate processing delay
            alert_type = body.get("alert_type", "UNKNOWN") if body else "UNKNOWN"
            severity = body.get("severity", "P4") if body else "P4"
            title = body.get("title", "Untitled") if body else "Untitled"

            self._set_headers(200)
            response = {
                "status": "success",
                "alert_id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "message": f"Alert '{title}' ({alert_type}/{severity}) processed successfully",
                "channel": "mock-slack",
                "timestamp": datetime.now().isoformat() + "Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
            log("RESPONSE", GREEN, f"Alert sent: {alert_type}/{severity} - {title}")
            return

        # ── Ticket Creation ──
        m = re.match(r"/issue(?:/(.+))?$", path)
        if m:
            log_request("POST", path, body, headers)

            summary = (body.get("summary", "Untitled Ticket") if body else "Untitled Ticket")
            priority = (body.get("priority", "MEDIUM") if body else "MEDIUM")
            project_key = (body.get("project_key", "SEC") if body else "SEC")
            labels = (body.get("labels", []) if body else [])

            ticket_num = random.randint(100, 999)

            self._set_headers(201)
            response = {
                "id": f"{project_key}-{ticket_num}",
                "key": f"{project_key}-{ticket_num}",
                "self": f"https://mock-jira.example.com/rest/api/2/issue/{project_key}-{ticket_num}",
                "summary": summary,
                "priority": priority,
                "labels": labels,
                "created": datetime.now().isoformat() + "Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
            log("RESPONSE", GREEN, f"Ticket created: {project_key}-{ticket_num} ({priority}) - {summary[:50]}")
            return

        # ── Ticket Comment ──
        m = re.match(r"/issue/[^/]+/comment", path)
        if m:
            log_request("POST", path, body, headers)
            self._set_headers(201)
            response = {
                "id": f"comment-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "created": datetime.now().isoformat() + "Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
            log("RESPONSE", GREEN, "Comment added to ticket")
            return

        m = re.match(r"/hosts/([^/]+)/isolate", path)
        if m:
            host_id = m.group(1)
            log_request("POST", path, body, headers)
            self._set_headers(202)
            response = {
                "host_id": host_id,
                "status": "queued",
                "action": "isolate",
                "reason": (body or {}).get("reason", ""),
                "requested_at": datetime.now().isoformat() + "Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
            log("RESPONSE", GREEN, f"Host isolation queued: {host_id}")
            return

        # 404
        log("404", RED, f"Unknown POST path: {path}")
        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Not found", "path": path}).encode())

    def log_message(self, format, *args):
        # Suppress default HTTP logging to stderr
        pass


# ─── Server ───────────────────────────────────────────────────────────────────

def run_server(port: int, verbose: bool):
    server = HTTPServer(("0.0.0.0", port), MockToolsHandler)
    log("SERVER", BOLD + GREEN, f"Mock Tools Server running on http://localhost:{port}")
    log("ENDPOINTS", BOLD + BLUE, """
  POST /                     → send_security_alert (webhook)
  POST /issue               → create_security_ticket (Jira)
  POST /issue/{key}/comment → add_ticket_comment
  GET  /alerts/search       → search_security_alerts
  POST /hosts/{id}/isolate  → isolate_endpoint_host
  GET  /assets/search       → lookup_asset_context
  GET  /ip_addresses/{ip}   → threat_intel_lookup (IP)
  GET  /domains/{domain}     → threat_intel_lookup (Domain)
  GET  /files/{hash}         → threat_intel_lookup (Hash)
  GET  /health               → health check
""")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        log("SERVER", RED, "Shutting down...")


def get_received_requests() -> list[dict]:
    return RECEIVED_REQUESTS


def clear_received_requests():
    RECEIVED_REQUESTS.clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock Security Tools Server")
    parser.add_argument("--port", "-p", type=int, default=9999, help="Port to listen on (default: 9999)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    run_server(args.port, args.verbose)
