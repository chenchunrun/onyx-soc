from typing import Any

from typing_extensions import override

from onyx.chat.emitter import Emitter
from onyx.server.query_and_chat.placement import Placement
from onyx.server.query_and_chat.streaming_models import CustomToolStart
from onyx.server.query_and_chat.streaming_models import Packet
from onyx.tools.interface import Tool
from onyx.tools.models import ToolCallException
from onyx.tools.models import ToolResponse
from onyx.utils.logger import setup_logger

logger = setup_logger()

ACTION_FIELD = "action"
SKILL_KEY_FIELD = "skill_key"
FILE_PATH_FIELD = "file_path"

MAX_CONTENT_CHARS = 32000


class SkillTool(Tool[None]):
    NAME = "load_skill"
    DISPLAY_NAME = "Skill Loader"
    DESCRIPTION = (
        "Load skill instructions and reference files on demand. "
        "Use action='list' to see available skills, "
        "action='load' to get full skill instructions, "
        "action='read_file' to read reference documents."
    )

    def __init__(
        self,
        tool_id: int,
        emitter: Emitter,
        skill_keys: list[str],
    ) -> None:
        super().__init__(emitter=emitter)
        self._id = tool_id
        self._skill_keys = set(skill_keys)

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    @property
    def display_name(self) -> str:
        return self.DISPLAY_NAME

    @override
    def tool_definition(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.DESCRIPTION,
                "parameters": {
                    "type": "object",
                    "properties": {
                        ACTION_FIELD: {
                            "type": "string",
                            "enum": ["list", "load", "read_file"],
                            "description": (
                                "Action to perform: "
                                "'list' shows available skills, "
                                "'load' returns full skill instructions, "
                                "'read_file' reads a reference file."
                            ),
                        },
                        SKILL_KEY_FIELD: {
                            "type": "string",
                            "description": "Skill key, e.g. 'auth-log-analysis'. Required for 'load' and 'read_file'.",
                        },
                        FILE_PATH_FIELD: {
                            "type": "string",
                            "description": (
                                "Relative path within the skill directory, e.g. 'references/report-format.md'. "
                                "Required for 'read_file'."
                            ),
                        },
                    },
                    "required": [ACTION_FIELD],
                },
            },
        }

    @override
    def emit_start(self, placement: Placement) -> None:
        self.emitter.emit(
            Packet(
                placement=placement,
                obj=CustomToolStart(
                    tool_name=self.name,
                    tool_id=self._id,
                ),
            )
        )

    def _list_skills(self) -> ToolResponse:
        from onyx.server.manage.skills.registry import list_managed_skills

        managed = {
            s.key: s
            for s in list_managed_skills(enabled=True)
            if s.key in self._skill_keys
        }
        lines = ["Available skills:"]
        for key in sorted(self._skill_keys):
            skill = managed.get(key)
            if skill:
                lines.append(f"- {skill.name} ({skill.key}): {skill.description}")
            else:
                lines.append(f"- {key} (not currently available)")
        lines.append("")
        lines.append(
            "Use action='load' with a skill_key to get full instructions. "
            "Use action='read_file' to read reference files."
        )
        return ToolResponse(rich_response=None, llm_facing_response="\n".join(lines))

    def _load_skill(self, skill_key: str) -> ToolResponse:
        if skill_key not in self._skill_keys:
            raise ToolCallException(
                message=f"Skill '{skill_key}' not available",
                llm_facing_message=(
                    f"Skill '{skill_key}' is not bound to this agent. "
                    f"Available skills: {', '.join(sorted(self._skill_keys))}"
                ),
            )

        from onyx.server.manage.skills.registry import read_skill_content
        from onyx.server.manage.skills.registry import SKILLS_ROOT

        content = read_skill_content(skill_key)
        if not content:
            raise ToolCallException(
                message=f"Skill content not found: {skill_key}",
                llm_facing_message=f"Could not load instructions for skill '{skill_key}'.",
            )

        header = f"# Skill: {skill_key}\nFiles: {SKILLS_ROOT / skill_key}/\n\n"
        full = header + content
        if len(full) > MAX_CONTENT_CHARS:
            full = full[:MAX_CONTENT_CHARS] + "\n\n[Content truncated. Use read_file to access specific sections.]"

        return ToolResponse(rich_response=None, llm_facing_response=full)

    def _read_file(self, skill_key: str, file_path: str) -> ToolResponse:
        if skill_key not in self._skill_keys:
            raise ToolCallException(
                message=f"Skill '{skill_key}' not available",
                llm_facing_message=(
                    f"Skill '{skill_key}' is not bound to this agent. "
                    f"Available skills: {', '.join(sorted(self._skill_keys))}"
                ),
            )

        if ".." in file_path or file_path.startswith("/"):
            raise ToolCallException(
                message=f"Invalid file path: {file_path}",
                llm_facing_message="File path must be relative and cannot contain '..'.",
            )

        from onyx.server.manage.skills.registry import SKILLS_ROOT

        full_path = (SKILLS_ROOT / skill_key / file_path).resolve()
        skill_dir = (SKILLS_ROOT / skill_key).resolve()

        if not str(full_path).startswith(str(skill_dir)):
            raise ToolCallException(
                message=f"Path traversal blocked: {file_path}",
                llm_facing_message="File path is outside the skill directory.",
            )

        if not full_path.exists():
            raise ToolCallException(
                message=f"File not found: {full_path}",
                llm_facing_message=(
                    f"File '{file_path}' not found in skill '{skill_key}'. "
                    f"Available at: {skill_dir}/"
                ),
            )

        if not full_path.is_file():
            raise ToolCallException(
                message=f"Not a file: {full_path}",
                llm_facing_message=f"'{file_path}' is not a file.",
            )

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            raise ToolCallException(
                message=f"Failed to read file: {e}",
                llm_facing_message=f"Could not read file '{file_path}'.",
            )

        if len(content) > MAX_CONTENT_CHARS:
            content = content[:MAX_CONTENT_CHARS] + "\n\n[Content truncated.]"

        return ToolResponse(rich_response=None, llm_facing_response=content)

    @override
    def run(
        self,
        placement: Placement,
        override_kwargs: None,
        **llm_kwargs: Any,
    ) -> ToolResponse:
        action = llm_kwargs.get(ACTION_FIELD, "")

        if action == "list":
            return self._list_skills()

        if action == "load":
            skill_key = llm_kwargs.get(SKILL_KEY_FIELD, "")
            if not skill_key:
                raise ToolCallException(
                    message="Missing skill_key for load action",
                    llm_facing_message="Please provide a 'skill_key' parameter.",
                )
            return self._load_skill(skill_key)

        if action == "read_file":
            skill_key = llm_kwargs.get(SKILL_KEY_FIELD, "")
            file_path = llm_kwargs.get(FILE_PATH_FIELD, "")
            if not skill_key:
                raise ToolCallException(
                    message="Missing skill_key for read_file action",
                    llm_facing_message="Please provide a 'skill_key' parameter.",
                )
            if not file_path:
                raise ToolCallException(
                    message="Missing file_path for read_file action",
                    llm_facing_message="Please provide a 'file_path' parameter, e.g. 'references/report-format.md'.",
                )
            return self._read_file(skill_key, file_path)

        raise ToolCallException(
            message=f"Unknown action: {action}",
            llm_facing_message=(
                f"Unknown action '{action}'. "
                "Use 'list', 'load', or 'read_file'."
            ),
        )
