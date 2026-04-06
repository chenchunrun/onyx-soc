#!/usr/bin/env python3
"""
Onyx Security CLI - Command-line interface for the Security Knowledge Base

Provides a convenient CLI for security analysts to interact with Onyx without
opening a browser.

Usage:
    onyx-cli ask "what is the incident response for ransomware?"
    onyx-cli search --query "phishing prevention"
    onyx-cli chat --persona 安全事件分析师 --query "analyze this IoC: 192.168.1.1"
    onyx-cli status
    onyx-cli list-personas
    onyx-cli whoami

Install:
    pip install requests rich
    ln -s $(pwd)/onyx-cli.py /usr/local/bin/onyx-cli

Or use directly:
    python onyx-cli.py ask "..."
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))

import requests

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_BASE_URL = os.environ.get("ONYX_URL", "http://localhost:8080")
DEFAULT_EMAIL = os.environ.get("ONYX_EMAIL", "security-admin@onyx.local")
DEFAULT_PASSWORD = os.environ.get("ONYX_PASSWORD", "admin123")

CONFIG_DIR = Path.home() / ".config" / "onyx-cli"
CONFIG_FILE = CONFIG_DIR / "config.json"
SESSION_FILE = CONFIG_DIR / "session.json"


def load_config() -> dict:
    """Load saved configuration."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {
        "base_url": DEFAULT_BASE_URL,
        "email": DEFAULT_EMAIL,
        "default_persona_id": None,
    }


def save_config(config: dict) -> None:
    """Save configuration."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def load_session() -> dict | None:
    """Load saved session."""
    if SESSION_FILE.exists():
        return json.loads(SESSION_FILE.read_text())
    return None


def save_session(session: dict) -> None:
    """Save session cookie."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(session, indent=2))


def clear_session() -> None:
    """Clear saved session."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ─── API Client ───────────────────────────────────────────────────────────────

class OnyxClient:
    """Onyx API client with session management."""

    def __init__(self, base_url: str, email: str | None = None, password: str | None = None):
        self.base_url = base_url
        self.email = email
        self.password = password
        self.cookie = None
        self.user_info = None

        # Try to load saved session
        session = load_session()
        if session and session.get("base_url") == base_url:
            self.cookie = session.get("cookie")
            self.email = session.get("email")

    def login(self, email: str | None = None, password: str | None = None) -> bool:
        """Login to Onyx."""
        email = email or self.email
        password = password or self.password

        if not email or not password:
            print("[ERROR] Email and password required for login")
            print("  Set ONYX_EMAIL and ONYX_PASSWORD environment variables")
            print("  Or use --email and --password flags")
            return False

        try:
            resp = requests.post(
                f"{self.base_url}/auth/login",
                data={"username": email, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            if resp.status_code == 204:
                cookie = resp.headers.get("set-cookie", "")
                for part in cookie.split(","):
                    part = part.strip()
                    if "fastapiusersauth=" in part:
                        self.cookie = part.split(";")[0].split("=")[1]
                        break

                if self.cookie:
                    self.email = email
                    save_session({
                        "base_url": self.base_url,
                        "cookie": self.cookie,
                        "email": self.email,
                    })
                    return True
            elif resp.status_code == 401:
                print(f"[ERROR] Authentication failed. Check credentials.")
                return False
            else:
                print(f"[ERROR] Login failed: HTTP {resp.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            return False

        print("[ERROR] Could not extract session cookie")
        return False

    def is_authenticated(self) -> bool:
        """Check if session is valid."""
        if not self.cookie:
            return False
        try:
            resp = requests.get(
                f"{self.base_url}/me",
                cookies={"fastapiusersauth": self.cookie},
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    def me(self) -> dict | None:
        """Get current user info."""
        if not self.cookie:
            return None
        try:
            resp = requests.get(
                f"{self.base_url}/me",
                cookies={"fastapiusersauth": self.cookie},
                timeout=10
            )
            if resp.status_code == 200:
                self.user_info = resp.json()
                return self.user_info
        except Exception:
            pass
        return None

    def list_personas(self) -> list[dict]:
        """List available personas."""
        if not self.cookie:
            return []
        try:
            resp = requests.get(
                f"{self.base_url}/persona",
                cookies={"fastapiusersauth": self.cookie},
                timeout=10
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return []

    def search(self, query: str, persona_id: int = 0, limit: int = 5) -> list[dict]:
        """Search the knowledge base."""
        if not self.cookie:
            return []

        try:
            resp = requests.post(
                f"{self.base_url}/search/send-search-message",
                json={
                    "search_query": query,
                    "filters": {"persona_id": persona_id} if persona_id else None,
                    "stream": False,
                },
                cookies={"fastapiusersauth": self.cookie},
                timeout=30
            )
            if resp.status_code == 200:
                return resp.json().get("search_docs", [])
        except Exception as e:
            print(f"[ERROR] Search failed: {e}")
        return []

    def chat(
        self,
        query: str,
        persona_id: int = 0,
        persona_name: str = "",
        stream: bool = True,
    ) -> str:
        """Send a chat message and return the response."""
        if not self.cookie:
            return "Not authenticated. Run 'onyx-cli login' first."

        # Create chat session
        try:
            resp = requests.post(
                f"{self.base_url}/chat/create-chat-session",
                json={"persona_id": persona_id, "description": f"CLI: {query[:50]}"},
                cookies={"fastapiusersauth": self.cookie},
                timeout=10
            )
            if resp.status_code != 200:
                return f"Failed to create chat session: {resp.status_code}"

            session_id = resp.json().get("chat_session_id")
            if not session_id:
                return f"No session ID returned. Response: {resp.text}"

        except Exception as e:
            return f"Failed to create chat session: {e}"

        # Send message
        try:
            if stream:
                return self._chat_stream(session_id, query, persona_name)
            else:
                return self._chat_nonstream(session_id, query)
        except Exception as e:
            return f"Chat failed: {e}"

    def _chat_stream(self, session_id: str, query: str, persona_name: str) -> str:
        """Stream chat response."""
        try:
            resp = requests.post(
                f"{self.base_url}/chat/send-chat-message",
                json={
                    "message": query,
                    "chat_session_id": session_id,
                    "stream": True,
                    "file_descriptors": [],
                },
                cookies={"fastapiusersauth": self.cookie},
                stream=True,
                timeout=120
            )

            if resp.status_code != 200:
                return f"Chat request failed: HTTP {resp.status_code} - {resp.text}"

            full_response = []
            for line in resp.iter_lines():
                if not line:
                    continue
                # Remove SSE "data: " prefix if present
                if line.startswith(b"data: "):
                    line = line[6:]
                if line == b"[DONE]":
                    break
                try:
                    data = json.loads(line)
                    # Check for error in packet
                    if data.get("error"):
                        return f"Stream error: {data.get('error')}"
                    obj = data.get("obj", {})
                    pkt_type = obj.get("type", "")
                    # message_delta packets contain text content
                    if pkt_type == "message_delta":
                        content = obj.get("content", "")
                        if content:
                            full_response.append(content)
                except (json.JSONDecodeError, KeyError):
                    continue

            result = "".join(full_response)

            # Add metadata
            if persona_name:
                result += f"\n\n[_via {persona_name} persona_]"

            return result

        except requests.exceptions.Timeout:
            return "Chat request timed out. Try a shorter query."
        except Exception as e:
            return f"Stream error: {e}"

    def _chat_nonstream(self, session_id: str, query: str) -> str:
        """Non-streaming chat."""
        try:
            resp = requests.post(
                f"{self.base_url}/chat/send-chat-message",
                json={
                    "message": query,
                    "chat_session_id": session_id,
                    "stream": False,
                    "file_descriptors": [],
                },
                cookies={"fastapiusersauth": self.cookie},
                timeout=120
            )
            if resp.status_code == 200:
                result = resp.json()
                return result.get("answer", str(result))
            return f"Chat failed: HTTP {resp.status_code} - {resp.text}"
        except Exception as e:
            return f"Chat failed: {e}"

    def status(self) -> dict:
        """Get system status."""
        status = {
            "authenticated": self.is_authenticated(),
            "base_url": self.base_url,
            "user": None,
            "personas": [],
        }

        if status["authenticated"]:
            status["user"] = self.me()
            status["personas"] = self.list_personas()

        return status


# ─── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_login(client: OnyxClient, args: argparse.Namespace) -> int:
    """Login to Onyx."""
    if client.is_authenticated():
        user = client.me()
        if user:
            print(f"Already logged in as {user.get('email', 'unknown')}")
            return 0

    if client.login(email=args.email, password=args.password):
        user = client.me()
        if user:
            print(f"Logged in as {user.get('email')} (role: {user.get('role', 'unknown')})")
            return 0
    return 1


def cmd_logout(client: OnyxClient, args: argparse.Namespace) -> int:
    """Logout from Onyx."""
    clear_session()
    client.cookie = None
    client.user_info = None
    print("Logged out.")
    return 0


def cmd_whoami(client: OnyxClient, args: argparse.Namespace) -> int:
    """Show current user info."""
    if not client.cookie:
        print("Not logged in.")
        return 1

    user = client.me()
    if not user:
        print("Session expired. Please login again.")
        clear_session()
        return 1

    print(f"Email: {user.get('email')}")
    print(f"Role: {user.get('role', 'N/A')}")
    print(f"Active: {user.get('is_active', False)}")
    print(f"Superuser: {user.get('is_superuser', False)}")

    prefs = user.get("preferences", {})
    if prefs:
        print(f"Default persona: {prefs.get('chosen_assistants', 'N/A')}")

    return 0


def cmd_list_personas(client: OnyxClient, args: argparse.Namespace) -> int:
    """List available personas."""
    personas = client.list_personas()
    if not personas:
        print("No personas available (not authenticated?).")
        return 1

    print(f"\nAvailable Personas ({len(personas)}):\n")
    for p in personas:
        tool_count = len(p.get("tool_ids", []))
        ds_count = len(p.get("document_sets", []))
        print(f"  [{p['id']}] {p['name']}")
        if args.verbose:
            desc = p.get("description", "")
            if desc:
                print(f"      {desc[:80]}...")
            print(f"      Tools: {tool_count}, Document sets: {ds_count}")
    return 0


def cmd_search(client: OnyxClient, args: argparse.Namespace) -> int:
    """Search the knowledge base."""
    results = client.search(args.query, persona_id=args.persona, limit=args.limit)

    if not results:
        print(f"No results found for: {args.query}")
        return 1

    print(f"\nSearch: {args.query}")
    print(f"Results: {len(results)}\n")

    for i, doc in enumerate(results, 1):
        score = doc.get(" relevance_score", doc.get("match_score", 0))
        source = doc.get("source_type", doc.get("document", {}).get("source_type", "N/A"))

        print(f"  {i}. {doc.get('semantic_identifier', 'N/A')}")
        print(f"     Score: {score:.3f} | Source: {source}")

        blurb = doc.get("blurb", "")
        if blurb:
            print(f"     {blurb[:200]}")

        link = doc.get("link", "")
        if link:
            print(f"     Link: {link}")
        print()

    return 0


def cmd_ask(client: OnyxClient, args: argparse.Namespace) -> int:
    """Ask a question to the security knowledge base."""
    if not client.is_authenticated():
        print("Not authenticated. Running login...")
        if not client.login():
            return 1

    # Resolve persona
    persona_id = args.persona or 0
    persona_name = ""

    if args.persona_name:
        persona_name = args.persona_name
        personas = client.list_personas()
        for p in personas:
            if p["name"] == args.persona_name:
                persona_id = p["id"]
                break
    elif args.persona:
        personas = client.list_personas()
        for p in personas:
            if p["id"] == args.persona:
                persona_name = p["name"]
                break

    # Show persona being used
    if persona_name:
        print(f"[Using persona: {persona_name}]\n")

    # Handle multi-line queries
    query = args.query
    if args.file:
        query = Path(args.file).read_text(encoding="utf-8")

    if args.interactive:
        print("Enter your question (Ctrl+D to send, Ctrl+C to cancel):")
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        query = "\n".join(lines)

    print(f"[Query: {query[:100]}{'...' if len(query) > 100 else ''}]\n")

    # Search first for context
    print("[Searching knowledge base...]")
    search_results = client.search(query, persona_id=persona_id, limit=args.limit)
    if search_results:
        print(f"[Found {len(search_results)} relevant documents]\n")

    # Send to chat
    print("[Waiting for response...]\n")
    response = client.chat(query, persona_id=persona_id, persona_name=persona_name, stream=args.stream)

    print(response)
    print()

    # Show search results for reference
    if args.show_context and search_results:
        print("\n[Reference Documents]:")
        for i, doc in enumerate(search_results, 1):
            print(f"  {i}. {doc.get('semantic_identifier', 'N/A')}")

    return 0


def cmd_chat(client: OnyxClient, args: argparse.Namespace) -> int:
    """Interactive chat session with a persona."""
    if not client.is_authenticated():
        if not client.login():
            return 1

    # Resolve persona
    persona_id = 0
    persona_name = ""

    if args.persona_name:
        personas = client.list_personas()
        for p in personas:
            if p["name"] == args.persona_name:
                persona_id = p["id"]
                persona_name = p["name"]
                break

    print(f"Starting chat session with persona: {persona_name or 'Default'}")
    print("Type 'quit' or 'exit' to end the session.\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting chat.")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            print("Ending chat session.")
            break

        if not user_input:
            continue

        print("\nAssistant: ", end="", flush=True)

        # Stream response
        try:
            resp = requests.post(
                f"{client.base_url}/chat/create-chat-session",
                json={"persona_id": persona_id, "description": "CLI chat"},
                cookies={"fastapiusersauth": client.cookie},
                timeout=10
            )
            if resp.status_code != 200:
                print(f"Error: {resp.status_code}")
                continue

            session_id = resp.json().get("id")

            resp = requests.post(
                f"{client.base_url}/chat/{session_id}/send",
                json={"message": user_input, "file_ids": []},
                cookies={"fastapiusersauth": client.cookie},
                stream=True,
                timeout=120
            )

            if resp.status_code != 200:
                print(f"Error: {resp.status_code}")
                continue

            full_response = []
            for line in resp.iter_lines():
                if not line:
                    continue
                if line.startswith(b"data: "):
                    data = line[7:]
                    if data == b"[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                        if obj.get("type") == "assistant":
                            content = obj.get("content", [])
                            for item in content:
                                if item.get("type") == "text":
                                    text = item.get("text", "")
                                    print(text, end="", flush=True)
                                    full_response.append(text)
                    except (json.JSONDecodeError, KeyError):
                        continue

            print("\n")

        except KeyboardInterrupt:
            print("\n[Interrupted]")
            break
        except Exception as e:
            print(f"\nError: {e}")
            break

    return 0


def cmd_status(client: OnyxClient, args: argparse.Namespace) -> int:
    """Show system status."""
    status = client.status()

    print(f"\nOnyx Security CLI Status")
    print(f"{'='*40}")
    print(f"Base URL: {status['base_url']}")
    print(f"Authenticated: {status['authenticated']}")

    if status["user"]:
        user = status["user"]
        print(f"\nUser: {user.get('email')}")
        print(f"Role: {user.get('role', 'N/A')}")

    if args.verbose:
        print(f"\nPersonas: {len(status['personas'])}")
        for p in status["personas"]:
            print(f"  [{p['id']}] {p['name']}")

    return 0


def cmd_config(client: OnyxClient, args: argparse.Namespace) -> int:
    """Manage configuration."""
    config = load_config()

    if args.set_url:
        config["base_url"] = args.set_url
        save_config(config)
        print(f"Base URL set to: {args.set_url}")
        return 0

    if args.set_email:
        config["email"] = args.set_email
        save_config(config)
        print(f"Default email set to: {args.set_email}")
        return 0

    if args.set_persona:
        config["default_persona_id"] = int(args.set_persona)
        save_config(config)
        print(f"Default persona set to: {args.set_persona}")
        return 0

    if args.clear_session:
        clear_session()
        print("Session cleared.")
        return 0

    # Show current config
    print(f"Base URL: {config.get('base_url', 'not set')}")
    print(f"Email: {config.get('email', 'not set')}")
    print(f"Default Persona: {config.get('default_persona_id', 'not set')}")
    return 0


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Build parser
    parser = argparse.ArgumentParser(
        description="Onyx Security CLI - Security Knowledge Base Command Line",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  onyx-cli ask "what is the ransomware incident response?"
  onyx-cli ask --persona 安全事件分析师 "analyze this IP: 1.2.3.4"
  onyx-cli search "phishing email indicators"
  onyx-cli chat --persona-name "应急响应指挥官"
  onyx-cli status --verbose
  onyx-cli config --set-url http://localhost:8080
  onyx-cli whoami
        """
    )

    # Global options
    parser.add_argument("--url", default=None, help=f"Onyx base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--email", default=None, help="Onyx email")
    parser.add_argument("--password", default=None, help="Onyx password")

    subparsers = parser.add_subparsers(dest="command", title="commands")

    # ask command
    ask_parser = subparsers.add_parser("ask", help="Ask a question to the security knowledge base")
    ask_parser.add_argument("query", nargs="?", help="The question to ask")
    ask_parser.add_argument("--persona", "-p", type=int, default=0, help="Persona ID (default: 0)")
    ask_parser.add_argument("--persona-name", help="Persona name (e.g. 安全事件分析师)")
    ask_parser.add_argument("--limit", "-l", type=int, default=5, help="Number of search results (default: 5)")
    ask_parser.add_argument("--file", "-f", help="Read query from file")
    ask_parser.add_argument("--interactive", "-i", action="store_true", help="Interactive multi-line input")
    ask_parser.add_argument("--show-context", action="store_true", help="Show reference documents")
    ask_parser.add_argument("--no-stream", dest="stream", action="store_false", default=True,
                           help="Disable streaming response")
    ask_parser.set_defaults(func=cmd_ask)

    # search command
    search_parser = subparsers.add_parser("search", help="Search the knowledge base")
    search_parser.add_argument("--query", "-q", required=True, help="Search query")
    search_parser.add_argument("--persona", "-p", type=int, default=0, help="Persona ID")
    search_parser.add_argument("--limit", "-l", type=int, default=5, help="Number of results")
    search_parser.set_defaults(func=cmd_search)

    # chat command
    chat_parser = subparsers.add_parser("chat", help="Interactive chat session")
    chat_parser.add_argument("--persona-name", help="Persona name")
    chat_parser.add_argument("--persona", "-p", type=int, default=0, help="Persona ID")
    chat_parser.set_defaults(func=cmd_chat)

    # list-personas command
    lp_parser = subparsers.add_parser("list-personas", help="List available personas")
    lp_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed info")
    lp_parser.set_defaults(func=cmd_list_personas)

    # login command
    login_parser = subparsers.add_parser("login", help="Login to Onyx")
    login_parser.set_defaults(func=cmd_login)

    # logout command
    logout_parser = subparsers.add_parser("logout", help="Logout from Onyx")
    logout_parser.set_defaults(func=cmd_logout)

    # whoami command
    whoami_parser = subparsers.add_parser("whoami", help="Show current user")
    whoami_parser.set_defaults(func=cmd_whoami)

    # status command
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed info")
    status_parser.set_defaults(func=cmd_status)

    # config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("--set-url", metavar="URL", help="Set base URL")
    config_parser.add_argument("--set-email", metavar="EMAIL", help="Set default email")
    config_parser.add_argument("--set-persona", metavar="ID", help="Set default persona ID")
    config_parser.add_argument("--clear-session", action="store_true", help="Clear saved session")
    config_parser.set_defaults(func=cmd_config)

    args = parser.parse_args()

    # Load config
    config = load_config()
    base_url = args.url or config.get("base_url", DEFAULT_BASE_URL)
    email = args.email or config.get("email", DEFAULT_EMAIL)

    # Create client
    client = OnyxClient(base_url=base_url, email=email)

    # Handle default command
    if not args.command:
        # Interactive ask mode
        if len(sys.argv) > 1:
            # Treat remaining args as a query
            args.query = " ".join(sys.argv[1:])
            args.persona = 0
            args.persona_name = None
            args.limit = 5
            args.file = None
            args.interactive = False
            args.show_context = False
            args.stream = True
            return cmd_ask(client, args)
        parser.print_help()
        return 0

    # Auto-login for commands that need it
    if args.command in ("ask", "search", "chat", "list-personas", "whoami", "status"):
        if not client.is_authenticated():
            if not client.login(email=args.email, password=args.password):
                return 1

    # Execute command
    return args.func(client, args)


if __name__ == "__main__":
    sys.exit(main())
