"""Tests for the SkillTool.

Verifies:
- Tool definition schema is well-formed
- ``list`` action returns bound skills
- ``load`` action returns SKILL.md content and rejects unbound keys
- ``read_file`` action reads reference files and blocks path traversal
- Unknown actions and missing parameters raise ``ToolCallException``

The registry layer (``onyx.server.manage.skills.registry``) is mocked so these
tests stay as pure unit tests with no dependency on the filesystem layout.
"""

from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from onyx.server.query_and_chat.placement import Placement
from onyx.tools.models import ToolCallException
from onyx.tools.tool_implementations.skill.skill_tool import ACTION_FIELD
from onyx.tools.tool_implementations.skill.skill_tool import FILE_PATH_FIELD
from onyx.tools.tool_implementations.skill.skill_tool import MAX_CONTENT_CHARS
from onyx.tools.tool_implementations.skill.skill_tool import SKILL_KEY_FIELD
from onyx.tools.tool_implementations.skill.skill_tool import SkillTool

REGISTRY_MODULE = "onyx.server.manage.skills.registry"
_PLACEMENT = Placement(turn_index=0)

_BOUND_KEY = "auth-log-analysis"
_UNBOUND_KEY = "some-other-skill"


def _make_tool(skill_keys: list[str] | None = None) -> SkillTool:
    return SkillTool(
        tool_id=42,
        emitter=MagicMock(),
        skill_keys=skill_keys if skill_keys is not None else [_BOUND_KEY],
    )


# ------------------------------------------------------------------
# Tool metadata
# ------------------------------------------------------------------


class TestToolMetadata:
    def test_tool_name(self) -> None:
        assert _make_tool().name == "load_skill"

    def test_tool_definition_schema(self) -> None:
        defn = _make_tool().tool_definition()
        assert defn["type"] == "function"
        func = defn["function"]
        assert func["name"] == "load_skill"
        props = func["parameters"]["properties"]
        assert ACTION_FIELD in props
        assert SKILL_KEY_FIELD in props
        assert FILE_PATH_FIELD in props
        assert func["parameters"]["required"] == [ACTION_FIELD]
        assert set(props[ACTION_FIELD]["enum"]) == {"list", "load", "read_file"}

    def test_emit_start_does_not_raise(self) -> None:
        # Should simply emit a packet via the emitter without raising.
        _make_tool().emit_start(_PLACEMENT)


# ------------------------------------------------------------------
# list action
# ------------------------------------------------------------------


class TestListAction:
    @patch(f"{REGISTRY_MODULE}.list_managed_skills")
    def test_list_returns_bound_skills(self, mock_list: MagicMock) -> None:
        from onyx.server.manage.skills.registry import ManagedSkill

        mock_list.return_value = [
            ManagedSkill(
                key=_BOUND_KEY,
                name="Auth Log Analysis",
                description="Analyzes auth logs.",
                path="/skills/auth-log-analysis",
                risk_level="low",
                access_scope="all_users",
                enabled=True,
                builtin=True,
                has_scripts=False,
                has_references=False,
                has_tools=False,
                has_requirements=False,
            )
        ]
        resp = _make_tool().run(
            placement=_PLACEMENT, override_kwargs=None, **{ACTION_FIELD: "list"}
        )
        assert _BOUND_KEY in resp.llm_facing_response
        assert "Auth Log Analysis" in resp.llm_facing_response
        mock_list.assert_called_once_with(enabled=True)

    @patch(f"{REGISTRY_MODULE}.list_managed_skills")
    def test_list_marks_unavailable_keys(self, mock_list: MagicMock) -> None:
        # Skill is bound but not currently registered/scanned.
        mock_list.return_value = []
        resp = _make_tool().run(
            placement=_PLACEMENT, override_kwargs=None, **{ACTION_FIELD: "list"}
        )
        assert _BOUND_KEY in resp.llm_facing_response
        assert "not currently available" in resp.llm_facing_response


# ------------------------------------------------------------------
# load action
# ------------------------------------------------------------------


class TestLoadAction:
    @patch(f"{REGISTRY_MODULE}.read_skill_content")
    @patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", Path("/skills"))
    def test_load_returns_content(self, mock_read: MagicMock) -> None:
        mock_read.return_value = "# Steps\n1. Do the thing"
        resp = _make_tool().run(
            placement=_PLACEMENT,
            override_kwargs=None,
            **{ACTION_FIELD: "load", SKILL_KEY_FIELD: _BOUND_KEY},
        )
        assert "Do the thing" in resp.llm_facing_response
        assert _BOUND_KEY in resp.llm_facing_response
        mock_read.assert_called_once_with(_BOUND_KEY)

    @patch(f"{REGISTRY_MODULE}.read_skill_content")
    def test_load_rejects_unbound_key(self, mock_read: MagicMock) -> None:
        with pytest.raises(ToolCallException, match="not available"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{ACTION_FIELD: "load", SKILL_KEY_FIELD: _UNBOUND_KEY},
            )
        mock_read.assert_not_called()

    @patch(f"{REGISTRY_MODULE}.read_skill_content")
    def test_load_raises_when_content_missing(self, mock_read: MagicMock) -> None:
        mock_read.return_value = None
        with pytest.raises(ToolCallException, match="content not found"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{ACTION_FIELD: "load", SKILL_KEY_FIELD: _BOUND_KEY},
            )

    @patch(f"{REGISTRY_MODULE}.read_skill_content")
    def test_load_truncates_oversized_content(self, mock_read: MagicMock) -> None:
        mock_read.return_value = "x" * (MAX_CONTENT_CHARS + 1000)
        resp = _make_tool().run(
            placement=_PLACEMENT,
            override_kwargs=None,
            **{ACTION_FIELD: "load", SKILL_KEY_FIELD: _BOUND_KEY},
        )
        # Header + truncated body should not exceed a small margin over the cap.
        assert len(resp.llm_facing_response) <= MAX_CONTENT_CHARS + 200
        assert "Content truncated" in resp.llm_facing_response

    def test_load_requires_skill_key(self) -> None:
        with pytest.raises(ToolCallException, match="skill_key"):
            _make_tool().run(
                placement=_PLACEMENT, override_kwargs=None, **{ACTION_FIELD: "load"}
            )


# ------------------------------------------------------------------
# read_file action
# ------------------------------------------------------------------


class TestReadFileAction:
    @patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", Path("/skills"))
    def test_read_file_returns_content(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / _BOUND_KEY
        skill_dir.mkdir()
        ref = skill_dir / "references" / "format.md"
        ref.parent.mkdir(parents=True)
        ref.write_text("# Report Format\nUse this template.")

        with patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", tmp_path):
            resp = _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{
                    ACTION_FIELD: "read_file",
                    SKILL_KEY_FIELD: _BOUND_KEY,
                    FILE_PATH_FIELD: "references/format.md",
                },
            )
        assert "Use this template." in resp.llm_facing_response

    @patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", Path("/skills"))
    def test_read_file_rejects_unbound_key(self) -> None:
        with pytest.raises(ToolCallException, match="not available"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{
                    ACTION_FIELD: "read_file",
                    SKILL_KEY_FIELD: _UNBOUND_KEY,
                    FILE_PATH_FIELD: "x.md",
                },
            )

    def test_read_file_rejects_dotdot(self) -> None:
        with pytest.raises(ToolCallException, match="Invalid file path"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{
                    ACTION_FIELD: "read_file",
                    SKILL_KEY_FIELD: _BOUND_KEY,
                    FILE_PATH_FIELD: "../etc/passwd",
                },
            )

    def test_read_file_rejects_absolute_path(self) -> None:
        with pytest.raises(ToolCallException, match="Invalid file path"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{
                    ACTION_FIELD: "read_file",
                    SKILL_KEY_FIELD: _BOUND_KEY,
                    FILE_PATH_FIELD: "/etc/passwd",
                },
            )

    @patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", Path("/skills"))
    def test_read_file_rejects_missing_file(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / _BOUND_KEY
        skill_dir.mkdir()
        with patch(f"{REGISTRY_MODULE}.SKILLS_ROOT", tmp_path):
            with pytest.raises(ToolCallException, match="File not found"):
                _make_tool().run(
                    placement=_PLACEMENT,
                    override_kwargs=None,
                    **{
                        ACTION_FIELD: "read_file",
                        SKILL_KEY_FIELD: _BOUND_KEY,
                        FILE_PATH_FIELD: "nope.md",
                    },
                )

    def test_read_file_requires_file_path(self) -> None:
        with pytest.raises(ToolCallException, match="file_path"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{ACTION_FIELD: "read_file", SKILL_KEY_FIELD: _BOUND_KEY},
            )

    def test_read_file_requires_skill_key(self) -> None:
        with pytest.raises(ToolCallException, match="skill_key"):
            _make_tool().run(
                placement=_PLACEMENT,
                override_kwargs=None,
                **{ACTION_FIELD: "read_file", FILE_PATH_FIELD: "x.md"},
            )


# ------------------------------------------------------------------
# run() — error paths
# ------------------------------------------------------------------


class TestRunErrors:
    def test_unknown_action(self) -> None:
        with pytest.raises(ToolCallException, match="Unknown action"):
            _make_tool().run(
                placement=_PLACEMENT, override_kwargs=None, **{ACTION_FIELD: "frobnicate"}
            )

    def test_missing_action(self) -> None:
        # Empty action falls through to the unknown-action branch.
        with pytest.raises(ToolCallException, match="Unknown action"):
            _make_tool().run(placement=_PLACEMENT, override_kwargs=None)
