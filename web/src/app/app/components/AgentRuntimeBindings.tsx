"use client";

import useSWR from "swr";
import {
  AgentSkillRuntimeBinding,
  AgentRuntimeProfile,
  MinimalPersonaSnapshot,
} from "@/app/admin/agents/interfaces";
import { errorHandlingFetcher } from "@/lib/fetcher";
import { SWR_KEYS } from "@/lib/swr-keys";
import Popover from "@/refresh-components/Popover";
import Tag from "@/refresh-components/buttons/Tag";
import { Button } from "@opal/components";
import Text from "@/refresh-components/texts/Text";
import { cn } from "@/lib/utils";

interface AgentRuntimeBindingsProps {
  agent?: MinimalPersonaSnapshot;
  className?: string;
}

function formatBindingLabel(value: string): string {
  return value
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function RuntimeStatusTag({
  label,
  tone = "default",
}: {
  label: string;
  tone?: "default" | "success" | "warning" | "danger";
}) {
  return (
    <span
      className={cn(
        "rounded-full border px-2 py-1 text-[11px] font-medium",
        tone === "success" &&
          "border-status-success-04/40 bg-status-success-02/15 text-status-success-04",
        tone === "warning" &&
          "border-status-warning-04/40 bg-status-warning-02/20 text-status-warning-05",
        tone === "danger" &&
          "border-status-error-04/40 bg-status-error-02/20 text-status-error-05",
        tone === "default" &&
          "border-border bg-background-neutral-00 text-text-03"
      )}
    >
      {label}
    </span>
  );
}

function SkillCard({ skill }: { skill: AgentSkillRuntimeBinding }) {
  const metadata = [
    skill.execution_scope,
    skill.risk_level,
    skill.gateway_required ? "gateway" : null,
    skill.requires_approval ? "approval" : null,
  ].filter(Boolean);

  return (
    <div className="rounded-xl border border-border bg-background-neutral-00 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <Text as="p" className="font-semibold">
            {skill.name}
          </Text>
          <Text text03 secondaryBody className="mt-1">
            {skill.description}
          </Text>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <RuntimeStatusTag
            label={skill.accessible ? "Accessible" : "Restricted"}
            tone={skill.accessible ? "success" : "danger"}
          />
          <RuntimeStatusTag
            label={skill.enabled ? "Enabled" : "Inactive"}
            tone={skill.enabled ? "default" : "warning"}
          />
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        {metadata.map((item) => (
          <Tag
            key={`${skill.key}-${item}`}
            label={String(item)}
            className="pointer-events-none"
          />
        ))}
        {skill.allowed_target_types.map((targetType) => (
          <Tag
            key={`${skill.key}-${targetType}`}
            label={`target: ${targetType}`}
            className="pointer-events-none"
          />
        ))}
      </div>

      {skill.notes && (
        <div className="mt-3 rounded-lg bg-background-subtle p-3">
          <Text as="p" className="text-xs font-semibold uppercase tracking-[0.08em] text-text-03">
            Notes
          </Text>
          <Text text03 secondaryBody className="mt-1">
            {skill.notes}
          </Text>
        </div>
      )}
    </div>
  );
}

export default function AgentRuntimeBindings({
  agent,
  className,
}: AgentRuntimeBindingsProps) {
  const { data: runtimeProfile } = useSWR<AgentRuntimeProfile>(
    agent?.id ? SWR_KEYS.personaRuntimeProfile(agent.id) : null,
    errorHandlingFetcher,
    {
      revalidateOnFocus: false,
      revalidateIfStale: false,
      dedupingInterval: 60000,
    }
  );

  if (!agent) {
    return null;
  }

  const skillKeys = agent.skill_keys ?? [];
  const promptPresetId = agent.prompt_preset_id ?? null;

  if (!skillKeys.length && !promptPresetId) {
    return null;
  }

  return (
    <div
      className={`flex flex-wrap items-center justify-center gap-2 text-xs text-text-03 ${className ?? ""}`}
    >
      {promptPresetId && (
        <span className="rounded-full border border-border px-2 py-1">
          Prompt: {formatBindingLabel(promptPresetId)}
        </span>
      )}
      {skillKeys.slice(0, 3).map((skillKey) => (
        <span
          key={skillKey}
          className="rounded-full border border-border px-2 py-1"
        >
          Skill: {formatBindingLabel(skillKey)}
        </span>
      ))}
      {skillKeys.length > 3 && (
        <span className="rounded-full border border-border px-2 py-1">
          +{skillKeys.length - 3} more
        </span>
      )}
      {runtimeProfile && (
        <Popover>
          <Popover.Trigger asChild>
            <Button prominence="secondary">View Runtime Profile</Button>
          </Popover.Trigger>
          <Popover.Content align="center" width="fit">
            <div className="flex max-h-[min(42rem,calc(100vh-3rem))] w-[min(46rem,calc(100vw-1.5rem))] max-w-[46rem] flex-col overflow-hidden">
              <div className="border-b border-border bg-background-neutral-00 px-5 py-4">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <Text as="p" className="font-semibold">
                      Runtime Profile
                    </Text>
                    <Text text03 secondaryBody className="mt-1">
                      {runtimeProfile.persona_name}
                    </Text>
                  </div>
                  <div className="flex flex-wrap justify-end gap-2">
                    <RuntimeStatusTag
                      label={`${runtimeProfile.bound_skills.length} skills`}
                    />
                    <RuntimeStatusTag
                      label={`${runtimeProfile.accessible_skill_keys.length} accessible`}
                      tone="success"
                    />
                    {runtimeProfile.activation_required_skill_keys.length > 0 && (
                      <RuntimeStatusTag
                        label={`${runtimeProfile.activation_required_skill_keys.length} require activation`}
                        tone="warning"
                      />
                    )}
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-4 overflow-y-auto bg-background-tint-01 px-5 py-4">
                {runtimeProfile.prompt_preset && (
                  <div className="rounded-xl border border-border bg-background-neutral-00 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <Text as="p" className="font-semibold">
                          Prompt Preset
                        </Text>
                        <Text text03 secondaryBody className="mt-1">
                          {runtimeProfile.prompt_preset.name}
                        </Text>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Tag
                          label={formatBindingLabel(runtimeProfile.prompt_preset.id)}
                          className="pointer-events-none"
                        />
                        <Tag
                          label={runtimeProfile.prompt_preset.category}
                          className="pointer-events-none"
                        />
                        <Tag
                          label={runtimeProfile.prompt_preset.agent_type}
                          className="pointer-events-none"
                        />
                      </div>
                    </div>
                    <Text text03 secondaryBody className="mt-3">
                      {runtimeProfile.prompt_preset.description}
                    </Text>
                  </div>
                )}

                <div className="rounded-xl border border-border bg-background-neutral-00 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <Text as="p" className="font-semibold">
                      Bound Skills
                    </Text>
                    <div className="flex flex-wrap gap-2">
                      {runtimeProfile.inaccessible_skill_keys.length > 0 && (
                        <RuntimeStatusTag
                          label={`${runtimeProfile.inaccessible_skill_keys.length} restricted`}
                          tone="danger"
                        />
                      )}
                      {runtimeProfile.inactive_skill_keys.length > 0 && (
                        <RuntimeStatusTag
                          label={`${runtimeProfile.inactive_skill_keys.length} inactive`}
                          tone="warning"
                        />
                      )}
                    </div>
                  </div>
                  <div className="mt-4 flex flex-col gap-3">
                    {runtimeProfile.bound_skills.map((skill) => (
                      <SkillCard key={skill.key} skill={skill} />
                    ))}
                  </div>
                </div>

                {runtimeProfile.runtime_instruction_block && (
                  <div className="rounded-xl border border-border bg-background-neutral-00 p-4">
                    <Text as="p" className="font-semibold">
                      Runtime Instructions
                    </Text>
                    <div className="mt-3 rounded-lg bg-background-subtle p-3">
                      <pre className="overflow-x-auto whitespace-pre-wrap text-xs leading-6 text-text-03">
                        {runtimeProfile.runtime_instruction_block}
                      </pre>
                    </div>
                  </div>
                )}

                <div className="rounded-xl border border-border bg-background-neutral-00 p-4">
                  <Text as="p" className="font-semibold">
                    Policy
                  </Text>
                  <div className="mt-3 rounded-lg bg-background-subtle p-3">
                    <pre className="overflow-x-auto whitespace-pre-wrap text-xs leading-6 text-text-03">
                      {runtimeProfile.policy_markdown}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </Popover.Content>
        </Popover>
      )}
    </div>
  );
}
