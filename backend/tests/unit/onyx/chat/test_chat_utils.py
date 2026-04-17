"""Tests for chat_utils.py, specifically get_custom_agent_prompt."""

from unittest.mock import MagicMock
from unittest.mock import patch

from onyx.chat.chat_utils import _build_tool_call_response_history_message
from onyx.chat.chat_utils import get_custom_agent_prompt
from onyx.chat.chat_utils import get_persona_runtime_instruction_block
from onyx.configs.constants import DEFAULT_PERSONA_ID
from onyx.prompts.chat_prompts import TOOL_CALL_RESPONSE_CROSS_MESSAGE


class TestGetCustomAgentPrompt:
    """Tests for the get_custom_agent_prompt function."""

    def _create_mock_persona(
        self,
        persona_id: int = 1,
        system_prompt: str | None = None,
        replace_base_system_prompt: bool = False,
        skill_keys: list[str] | None = None,
        prompt_preset_id: str | None = None,
    ) -> MagicMock:
        """Create a mock Persona with the specified attributes."""
        persona = MagicMock()
        persona.id = persona_id
        persona.system_prompt = system_prompt
        persona.replace_base_system_prompt = replace_base_system_prompt
        persona.skill_keys = skill_keys or []
        persona.prompt_preset_id = prompt_preset_id
        return persona

    def _create_mock_chat_session(
        self,
        project: MagicMock | None = None,
    ) -> MagicMock:
        """Create a mock ChatSession with the specified attributes."""
        chat_session = MagicMock()
        chat_session.project = project
        return chat_session

    def _create_mock_project(
        self,
        instructions: str = "",
    ) -> MagicMock:
        """Create a mock UserProject with the specified attributes."""
        project = MagicMock()
        project.instructions = instructions
        return project

    def test_default_persona_no_project(self) -> None:
        """Test that default persona without a project returns None."""
        persona = self._create_mock_persona(persona_id=DEFAULT_PERSONA_ID)
        chat_session = self._create_mock_chat_session(project=None)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is None

    def test_default_persona_with_project_instructions(self) -> None:
        """Test that default persona in a project returns project instructions."""
        persona = self._create_mock_persona(persona_id=DEFAULT_PERSONA_ID)
        project = self._create_mock_project(instructions="Do X and Y")
        chat_session = self._create_mock_chat_session(project=project)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result == "Do X and Y"

    def test_default_persona_with_empty_project_instructions(self) -> None:
        """Test that default persona in a project with empty instructions returns None."""
        persona = self._create_mock_persona(persona_id=DEFAULT_PERSONA_ID)
        project = self._create_mock_project(instructions="")
        chat_session = self._create_mock_chat_session(project=project)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is None

    def test_custom_persona_replace_base_prompt_true(self) -> None:
        """Test that custom persona with replace_base_system_prompt=True returns None."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            replace_base_system_prompt=True,
        )
        chat_session = self._create_mock_chat_session(project=None)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is None

    def test_custom_persona_with_system_prompt(self) -> None:
        """Test that custom persona with system_prompt returns the system_prompt."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            replace_base_system_prompt=False,
        )
        chat_session = self._create_mock_chat_session(project=None)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result == "Custom system prompt"

    def test_custom_persona_empty_string_system_prompt(self) -> None:
        """Test that custom persona with empty string system_prompt returns None."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="",
            replace_base_system_prompt=False,
        )
        chat_session = self._create_mock_chat_session(project=None)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is None

    def test_custom_persona_none_system_prompt(self) -> None:
        """Test that custom persona with None system_prompt returns None."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt=None,
            replace_base_system_prompt=False,
        )
        chat_session = self._create_mock_chat_session(project=None)

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is None

    def test_custom_persona_in_project_uses_persona_prompt(self) -> None:
        """Test that custom persona in a project uses persona's system_prompt, not project instructions."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            replace_base_system_prompt=False,
        )
        project = self._create_mock_project(instructions="Project instructions")
        chat_session = self._create_mock_chat_session(project=project)

        result = get_custom_agent_prompt(persona, chat_session)

        # Should use persona's system_prompt, NOT project instructions
        assert result == "Custom system prompt"

    def test_custom_persona_replace_base_in_project(self) -> None:
        """Test that custom persona with replace_base_system_prompt=True in a project still returns None."""
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            replace_base_system_prompt=True,
        )
        project = self._create_mock_project(instructions="Project instructions")
        chat_session = self._create_mock_chat_session(project=project)

        result = get_custom_agent_prompt(persona, chat_session)

        # Should return None because replace_base_system_prompt=True
        assert result is None

    @patch("onyx.server.manage.skills.registry.list_managed_skills")
    @patch("onyx.server.manage.prompt_presets.registry.scan_prompt_presets")
    def test_runtime_block_includes_prompt_preset_and_bound_skills(
        self,
        mock_scan_prompt_presets: MagicMock,
        mock_list_managed_skills: MagicMock,
    ) -> None:
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            skill_keys=["code-audit"],
            prompt_preset_id="preset-1",
        )
        prompt_preset = MagicMock()
        prompt_preset.id = "preset-1"
        prompt_preset.name = "Preset One"
        prompt_preset.content = "Use terse incident-response formatting."
        mock_scan_prompt_presets.return_value = [prompt_preset]

        skill = MagicMock()
        skill.key = "code-audit"
        skill.name = "Code Audit"
        skill.description = "Review source code for security defects."
        mock_list_managed_skills.return_value = [skill]

        runtime_block = get_persona_runtime_instruction_block(persona)

        assert runtime_block is not None
        assert "## Bound Prompt Preset" in runtime_block
        assert "Preset One" in runtime_block
        assert "Use terse incident-response formatting." in runtime_block
        assert "## Bound Skills" in runtime_block
        assert "Code Audit (code-audit)" in runtime_block

    @patch("onyx.server.manage.skills.registry.list_managed_skills")
    def test_runtime_block_only_includes_active_skill_keys(
        self,
        mock_list_managed_skills: MagicMock,
    ) -> None:
        persona = self._create_mock_persona(
            persona_id=1,
            skill_keys=["code-audit", "asset-discovery"],
        )

        code_audit = MagicMock()
        code_audit.key = "code-audit"
        code_audit.name = "Code Audit"
        code_audit.description = "Review source code for security defects."

        asset_discovery = MagicMock()
        asset_discovery.key = "asset-discovery"
        asset_discovery.name = "Asset Discovery"
        asset_discovery.description = "Scan approved corp assets."
        mock_list_managed_skills.return_value = [code_audit, asset_discovery]

        runtime_block = get_persona_runtime_instruction_block(
            persona,
            active_skill_keys=["code-audit"],
        )

        assert runtime_block is not None
        assert "Code Audit (code-audit)" in runtime_block
        assert "Asset Discovery (asset-discovery)" not in runtime_block

    @patch("onyx.server.manage.skills.registry.list_managed_skills")
    @patch("onyx.server.manage.prompt_presets.registry.scan_prompt_presets")
    def test_custom_persona_prompt_appends_runtime_block(
        self,
        mock_scan_prompt_presets: MagicMock,
        mock_list_managed_skills: MagicMock,
    ) -> None:
        persona = self._create_mock_persona(
            persona_id=1,
            system_prompt="Custom system prompt",
            replace_base_system_prompt=False,
            skill_keys=["code-audit"],
            prompt_preset_id="preset-1",
        )
        chat_session = self._create_mock_chat_session(project=None)

        prompt_preset = MagicMock()
        prompt_preset.id = "preset-1"
        prompt_preset.name = "Preset One"
        prompt_preset.content = "Use terse incident-response formatting."
        mock_scan_prompt_presets.return_value = [prompt_preset]

        skill = MagicMock()
        skill.key = "code-audit"
        skill.name = "Code Audit"
        skill.description = "Review source code for security defects."
        mock_list_managed_skills.return_value = [skill]

        result = get_custom_agent_prompt(persona, chat_session)

        assert result is not None
        assert result.startswith("Custom system prompt")
        assert "## Bound Prompt Preset" in result
        assert "## Bound Skills" in result


class TestBuildToolCallResponseHistoryMessage:
    def test_image_tool_uses_generated_images(self) -> None:
        message = _build_tool_call_response_history_message(
            tool_name="generate_image",
            generated_images=[{"file_id": "img-1", "revised_prompt": "p1"}],
            tool_call_response=None,
        )
        assert message == '[{"file_id": "img-1", "revised_prompt": "p1"}]'

    def test_non_image_tool_uses_placeholder(self) -> None:
        message = _build_tool_call_response_history_message(
            tool_name="web_search",
            generated_images=None,
            tool_call_response='{"raw":"value"}',
        )
        assert message == TOOL_CALL_RESPONSE_CROSS_MESSAGE
