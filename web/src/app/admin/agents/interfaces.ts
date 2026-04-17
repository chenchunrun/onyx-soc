import { ValidSources } from "@/lib/types";
import { ToolSnapshot } from "@/lib/tools/interfaces";
import { DocumentSetSummary, MinimalUserSnapshot } from "@/lib/types";

// Represents a hierarchy node (folder, space, channel, etc.) attached to a persona
export interface HierarchyNodeSnapshot {
  id: number;
  raw_node_id: string;
  display_name: string;
  link: string | null;
  source: ValidSources;
  node_type: string; // HierarchyNodeType enum value
}

// Represents a document attached to a persona
export interface AttachedDocumentSnapshot {
  id: string;
  title: string;
  link: string | null;
  parent_id: number | null;
  last_modified: string | null;
  last_synced: string | null;
  source: ValidSources | null;
}

export interface StarterMessageBase {
  message: string;
}

export interface StarterMessage extends StarterMessageBase {
  name: string;
}

export interface MinimalPersonaSnapshot {
  id: number;
  name: string;
  description: string;
  tools: ToolSnapshot[];
  starter_messages: StarterMessage[] | null;
  document_sets: DocumentSetSummary[];
  // Counts for knowledge sources (used to determine if search tool should be enabled)
  hierarchy_node_count?: number;
  attached_document_count?: number;
  // Unique sources from all knowledge (document sets + hierarchy nodes)
  // Used to populate source filters in chat
  knowledge_sources?: ValidSources[];
  llm_model_version_override?: string;
  llm_model_provider_override?: string;

  uploaded_image_id?: string;
  icon_name?: string;

  is_public: boolean;
  is_listed: boolean;
  display_priority: number | null;
  is_featured: boolean;
  builtin_persona: boolean;
  skill_keys?: string[];
  prompt_preset_id?: string | null;

  labels?: PersonaLabel[];
  owner: MinimalUserSnapshot | null;
}

export interface Persona extends MinimalPersonaSnapshot {
  user_file_ids: string[];
  users: MinimalUserSnapshot[];
  groups: number[];
  // Hierarchy nodes (folders, spaces, channels) attached for scoped search
  hierarchy_nodes?: HierarchyNodeSnapshot[];
  // Individual documents attached for scoped search
  attached_documents?: AttachedDocumentSnapshot[];

  // Embedded prompt fields on persona
  system_prompt: string | null;
  replace_base_system_prompt: boolean;
  task_prompt: string | null;
  datetime_aware: boolean;
}

export interface FullPersona extends Persona {
  search_start_date: string | null;
}

export interface PromptPresetRuntimeBinding {
  id: string;
  name: string;
  description: string;
  content: string;
  category: string;
  agent_type: string;
  source_file: string;
}

export interface AgentSkillRuntimeBinding {
  key: string;
  name: string;
  description: string;
  risk_level: string;
  access_scope: string;
  execution_scope: string;
  requires_approval: boolean;
  gateway_required: boolean;
  allowed_target_types: string[];
  notes: string | null;
  enabled: boolean;
  accessible: boolean;
}

export interface AuthorizedTargetSuggestion {
  target: string;
  target_type: string;
  owner: string;
  approval_reference: string;
  notes: string | null;
}

export interface AgentRuntimeProfile {
  persona_id: number;
  persona_name: string;
  prompt_preset: PromptPresetRuntimeBinding | null;
  bound_skills: AgentSkillRuntimeBinding[];
  accessible_skill_keys: string[];
  inaccessible_skill_keys: string[];
  active_skill_keys: string[];
  inactive_skill_keys: string[];
  activation_required_skill_keys: string[];
  blocked_skill_reasons: Record<string, string[]>;
  authorized_target_suggestions: AuthorizedTargetSuggestion[];
  approval_reference_suggestions: string[];
  runtime_instruction_block: string | null;
  policy_markdown: string;
}

export interface PersonaLabel {
  id: number;
  name: string;
}
