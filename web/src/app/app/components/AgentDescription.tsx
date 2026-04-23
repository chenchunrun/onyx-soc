"use client";

import Text from "@/refresh-components/texts/Text";
import { MinimalPersonaSnapshot } from "@/app/admin/agents/interfaces";

export interface AgentDescriptionProps {
  agent?: MinimalPersonaSnapshot;
}

export default function AgentDescription({ agent }: AgentDescriptionProps) {
  if (!agent?.description) {
    return null;
  }

  return (
    <div className="flex w-full min-w-0 flex-col items-center gap-2">
      {agent?.description && (
        <Text
          as="p"
          secondaryBody
          text03
          className="w-full min-w-0 text-center break-words"
        >
          {agent.description}
        </Text>
      )}
    </div>
  );
}
