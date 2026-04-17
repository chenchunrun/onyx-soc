"use client";

import useSWR from "swr";
import {
  AgentRuntimeProfile,
  MinimalPersonaSnapshot,
} from "@/app/admin/agents/interfaces";
import { errorHandlingFetcher } from "@/lib/fetcher";
import { SWR_KEYS } from "@/lib/swr-keys";
import Popover from "@/refresh-components/Popover";
import { Button } from "@opal/components";
import Text from "@/refresh-components/texts/Text";

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
          <Popover.Content width="lg" align="center">
            <div className="flex max-h-[28rem] flex-col gap-3 overflow-y-auto p-1">
              <div>
                <Text as="p" className="font-semibold">
                  Runtime Profile
                </Text>
                <Text text03 secondaryBody>
                  {runtimeProfile.persona_name}
                </Text>
              </div>

              {runtimeProfile.prompt_preset && (
                <div className="rounded-lg border border-border p-3">
                  <Text as="p" className="font-semibold">
                    Prompt Preset
                  </Text>
                  <Text text03 secondaryBody>
                    {runtimeProfile.prompt_preset.name}
                  </Text>
                  <div className="mt-2 whitespace-pre-wrap text-xs text-text-03">
                    {runtimeProfile.prompt_preset.description}
                  </div>
                </div>
              )}

              <div className="rounded-lg border border-border p-3">
                <Text as="p" className="font-semibold">
                  Bound Skills
                </Text>
                <div className="mt-2 flex flex-col gap-2">
                  {runtimeProfile.bound_skills.map((skill) => (
                    <div
                      key={skill.key}
                      className="rounded-md border border-border px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <Text as="p" className="font-semibold">
                          {skill.name}
                        </Text>
                        <span className="text-[11px] text-text-03">
                          {skill.accessible ? "accessible" : "restricted"}
                        </span>
                      </div>
                      <div className="mt-1 text-xs text-text-03">
                        {skill.description}
                      </div>
                      <div className="mt-1 text-[11px] text-text-03">
                        {skill.execution_scope} · {skill.risk_level}
                        {skill.gateway_required ? " · gateway" : ""}
                        {skill.requires_approval ? " · approval" : ""}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-border p-3">
                <Text as="p" className="font-semibold">
                  Policy
                </Text>
                <div className="mt-2 whitespace-pre-wrap text-xs text-text-03">
                  {runtimeProfile.policy_markdown}
                </div>
              </div>
            </div>
          </Popover.Content>
        </Popover>
      )}
    </div>
  );
}
