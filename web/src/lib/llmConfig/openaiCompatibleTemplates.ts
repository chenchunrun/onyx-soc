import {
  LLMProviderView,
  ModelConfiguration,
  WellKnownLLMProviderDescriptor,
} from "@/interfaces/llm";

export type OpenAICompatibleTemplateId = "bigmodel" | "minimax" | "kimi";

export interface OpenAICompatibleTemplate {
  id: OpenAICompatibleTemplateId;
  displayName: string;
  productName: string;
  providerDisplayName: string;
  providerName: "openai";
  defaultApiBase: string;
  defaultModelName: string;
  knownModels: ModelConfiguration[];
  hostnames: string[];
}

const visible = true;

export const OPENAI_COMPATIBLE_TEMPLATES: Record<
  OpenAICompatibleTemplateId,
  OpenAICompatibleTemplate
> = {
  bigmodel: {
    id: "bigmodel",
    displayName: "BigModel",
    productName: "BigModel",
    providerDisplayName: "Zhipu BigModel (OpenAI-compatible)",
    providerName: "openai",
    defaultApiBase: "https://open.bigmodel.cn/api/paas/v4",
    defaultModelName: "glm-5",
    hostnames: ["open.bigmodel.cn"],
    knownModels: [
      {
        name: "glm-5",
        display_name: "GLM-5",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: true,
      },
      {
        name: "glm-4.5-air",
        display_name: "GLM-4.5 Air",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: true,
      },
      {
        name: "glm-4.5v",
        display_name: "GLM-4.5V",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: true,
        supports_reasoning: false,
      },
    ],
  },
  minimax: {
    id: "minimax",
    displayName: "MiniMax",
    productName: "MiniMax",
    providerDisplayName: "MiniMax (OpenAI-compatible)",
    providerName: "openai",
    defaultApiBase: "https://api.minimax.io/v1",
    defaultModelName: "MiniMax-M2.7",
    hostnames: ["api.minimax.io", "api.minimaxi.com"],
    knownModels: [
      {
        name: "MiniMax-M2.7",
        display_name: "MiniMax M2.7",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: true,
      },
      {
        name: "MiniMax-M2.7-Thinking",
        display_name: "MiniMax M2.7 Thinking",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: true,
      },
      {
        name: "MiniMax-M2.7-highspeed",
        display_name: "MiniMax M2.7 Highspeed",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: false,
      },
    ],
  },
  kimi: {
    id: "kimi",
    displayName: "Kimi",
    productName: "Kimi",
    providerDisplayName: "Moonshot Kimi (OpenAI-compatible)",
    providerName: "openai",
    defaultApiBase: "https://api.moonshot.cn/v1",
    defaultModelName: "kimi-k2-250711",
    hostnames: ["api.moonshot.cn"],
    knownModels: [
      {
        name: "kimi-k2-250711",
        display_name: "Kimi K2.5",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: true,
        supports_reasoning: true,
      },
      {
        name: "kimi-k2-turbo-preview",
        display_name: "Kimi K2 Turbo Preview",
        is_visible: visible,
        max_input_tokens: null,
        supports_image_input: false,
        supports_reasoning: true,
      },
      {
        name: "moonshot-v1-128k",
        display_name: "Moonshot V1 128K",
        is_visible: visible,
        max_input_tokens: 128000,
        supports_image_input: false,
        supports_reasoning: false,
      },
    ],
  },
};

export function getOpenAICompatibleTemplate(
  provider:
    | Pick<LLMProviderView, "name" | "provider" | "api_base">
    | null
    | undefined
): OpenAICompatibleTemplate | null {
  if (!provider || provider.provider !== "openai") {
    return null;
  }

  const name = provider.name.trim().toLowerCase();
  const byName = Object.values(OPENAI_COMPATIBLE_TEMPLATES).find(
    (template) => template.displayName.toLowerCase() === name
  );
  if (byName) {
    return byName;
  }

  if (!provider.api_base) {
    return null;
  }

  try {
    const hostname = new URL(provider.api_base).hostname.toLowerCase();
    return (
      Object.values(OPENAI_COMPATIBLE_TEMPLATES).find((template) =>
        template.hostnames.includes(hostname)
      ) ?? null
    );
  } catch {
    return null;
  }
}

export function getOpenAICompatibleTemplateDescriptors(): WellKnownLLMProviderDescriptor[] {
  return Object.values(OPENAI_COMPATIBLE_TEMPLATES).map((template) => ({
    name: template.id,
    known_models: template.knownModels,
    recommended_default_model: {
      name: template.defaultModelName,
      display_name:
        template.knownModels.find(
          (model) => model.name === template.defaultModelName
        )?.display_name ?? template.defaultModelName,
    },
  }));
}
