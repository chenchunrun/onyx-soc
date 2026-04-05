"use client";

import { useState, useEffect } from "react";
import { useSWRConfig } from "swr";
import { Formik, FormikProps } from "formik";
import InputTypeInField from "@/refresh-components/form/InputTypeInField";
import * as InputLayouts from "@/layouts/input-layouts";
import {
  LLMProviderFormProps,
  LLMProviderName,
  LLMProviderView,
  ModelConfiguration,
} from "@/interfaces/llm";
import { fetchLiteLLMProxyModels } from "@/app/admin/configuration/llm/utils";
import * as Yup from "yup";
import { useWellKnownLLMProvider } from "@/hooks/useLLMProviders";
import {
  buildDefaultInitialValues,
  buildDefaultValidationSchema,
  buildAvailableModelConfigurations,
  buildOnboardingInitialValues,
  BaseLLMFormValues,
} from "@/sections/modals/llmConfig/utils";
import {
  submitLLMProvider,
  submitOnboardingProvider,
} from "@/sections/modals/llmConfig/svc";
import {
  APIKeyField,
  ModelsField,
  DisplayNameField,
  ModelsAccessField,
  FieldSeparator,
  FieldWrapper,
  SingleDefaultModelField,
  LLMConfigurationModalWrapper,
} from "@/sections/modals/llmConfig/shared";
import { toast } from "@/hooks/useToast";
import { Button } from "@/components/buttons/button/components";
import SvgPlus from "@/icons/plus";
import SvgX from "@/icons/x";

const DEFAULT_API_BASE = "http://localhost:4000";

interface LiteLLMProxyModalValues extends BaseLLMFormValues {
  api_key: string;
  api_base: string;
}

interface LiteLLMProxyModalInternalsProps {
  formikProps: FormikProps<LiteLLMProxyModalValues>;
  existingLlmProvider: LLMProviderView | undefined;
  fetchedModels: ModelConfiguration[];
  setFetchedModels: (models: ModelConfiguration[]) => void;
  modelConfigurations: ModelConfiguration[];
  isTesting: boolean;
  onClose: () => void;
  isOnboarding: boolean;
}

function LiteLLMProxyModalInternals({
  formikProps,
  existingLlmProvider,
  fetchedModels,
  setFetchedModels,
  modelConfigurations,
  isTesting,
  onClose,
  isOnboarding,
}: LiteLLMProxyModalInternalsProps) {
  const currentModels =
    fetchedModels.length > 0
      ? fetchedModels
      : existingLlmProvider?.model_configurations || modelConfigurations;

  const isFetchDisabled =
    !formikProps.values.api_base || !formikProps.values.api_key;

  const [manualModelNames, setManualModelNames] = useState<string[]>([]);
  const [newModelInput, setNewModelInput] = useState("");

  const handleFetchModels = async (manualModels?: string[]) => {
    const { models, error } = await fetchLiteLLMProxyModels({
      api_base: formikProps.values.api_base,
      api_key: formikProps.values.api_key,
      provider_name: existingLlmProvider?.name,
      models: manualModels,
    });
    if (error) {
      throw new Error(error);
    }
    setFetchedModels(models);
    setManualModelNames([]);
    setNewModelInput("");
  };

  const handleAddManualModel = () => {
    const trimmed = newModelInput.trim();
    if (trimmed && !manualModelNames.includes(trimmed)) {
      setManualModelNames([...manualModelNames, trimmed]);
      setNewModelInput("");
    }
  };

  const handleRemoveManualModel = (model: string) => {
    setManualModelNames(manualModelNames.filter((m) => m !== model));
  };

  const handleSubmitManualModels = async () => {
    if (manualModelNames.length === 0) return;
    await handleFetchModels(manualModelNames);
  };

  // Auto-fetch models on initial load when editing an existing provider
  useEffect(() => {
    if (existingLlmProvider && !isFetchDisabled) {
      handleFetchModels().catch((err) => {
        toast.error(
          err instanceof Error ? err.message : "Failed to fetch models"
        );
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <LLMConfigurationModalWrapper
      providerEndpoint={LLMProviderName.LITELLM_PROXY}
      existingProviderName={existingLlmProvider?.name}
      onClose={onClose}
      isFormValid={formikProps.isValid}
      isDirty={formikProps.dirty}
      isTesting={isTesting}
      isSubmitting={formikProps.isSubmitting}
    >
      <FieldWrapper>
        <InputLayouts.Vertical
          name="api_base"
          title="API Base URL"
          subDescription="The base URL for your LiteLLM Proxy server."
        >
          <InputTypeInField
            name="api_base"
            placeholder="https://your-litellm-proxy.com"
          />
        </InputLayouts.Vertical>
      </FieldWrapper>

      <APIKeyField providerName="LiteLLM Proxy" />

      {!isOnboarding && (
        <>
          <FieldSeparator />
          <DisplayNameField disabled={!!existingLlmProvider} />
        </>
      )}

      <FieldSeparator />

      {isOnboarding ? (
        <SingleDefaultModelField placeholder="E.g. gpt-4o" />
      ) : (
        <>
          <ModelsField
            modelConfigurations={currentModels}
            formikProps={formikProps}
            recommendedDefaultModel={null}
            shouldShowAutoUpdateToggle={false}
            onRefetch={isFetchDisabled ? undefined : handleFetchModels}
          />

          {/* Manual model entry for providers without /v1/models endpoint */}
          <div className="mt-3 space-y-2">
            {manualModelNames.length > 0 && (
              <div className="space-y-1">
                {manualModelNames.map((model) => (
                  <div
                    key={model}
                    className="flex items-center justify-between rounded border border-border-02 bg-background-tint-02 px-3 py-1.5"
                  >
                    <span className="text-sm text-text-03">{model}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveManualModel(model)}
                      className="text-text-05 hover:text-action-danger-03"
                    >
                      <SvgX size={14} />
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newModelInput}
                onChange={(e) => setNewModelInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleAddManualModel();
                  }
                }}
                placeholder="Enter model name manually (e.g. glm-5)"
                className="flex-1 rounded border border-border-02 bg-background-neutral-01 px-3 py-1.5 text-sm text-text-01 placeholder:text-text-05 focus:border-action-link-03 focus:outline-none"
              />
              <Button
                variant="action"
                prominence="secondary"
                size="sm"
                icon={SvgPlus}
                onClick={handleAddManualModel}
                disabled={!newModelInput.trim()}
              >
                Add
              </Button>
              {manualModelNames.length > 0 && (
                <Button
                  variant="default"
                  prominence="primary"
                  size="sm"
                  onClick={handleSubmitManualModels}
                >
                  Save
                </Button>
              )}
            </div>
            <p className="text-xs text-text-05">
              If auto-discovery fails (no /v1/models endpoint), add models manually
            </p>
          </div>
        </>
      )}

      {!isOnboarding && (
        <>
          <FieldSeparator />
          <ModelsAccessField formikProps={formikProps} />
        </>
      )}
    </LLMConfigurationModalWrapper>
  );
}

export default function LiteLLMProxyModal({
  variant = "llm-configuration",
  existingLlmProvider,
  shouldMarkAsDefault,
  open,
  onOpenChange,
  defaultModelName,
  onboardingState,
  onboardingActions,
  llmDescriptor,
}: LLMProviderFormProps) {
  const [fetchedModels, setFetchedModels] = useState<ModelConfiguration[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const isOnboarding = variant === "onboarding";
  const { mutate } = useSWRConfig();
  const { wellKnownLLMProvider } = useWellKnownLLMProvider(
    LLMProviderName.LITELLM_PROXY
  );

  if (open === false) return null;

  const onClose = () => onOpenChange?.(false);

  const modelConfigurations = buildAvailableModelConfigurations(
    existingLlmProvider,
    wellKnownLLMProvider ?? llmDescriptor
  );

  const initialValues: LiteLLMProxyModalValues = isOnboarding
    ? ({
        ...buildOnboardingInitialValues(),
        name: LLMProviderName.LITELLM_PROXY,
        provider: LLMProviderName.LITELLM_PROXY,
        api_key: "",
        api_base: DEFAULT_API_BASE,
        default_model_name: "",
      } as LiteLLMProxyModalValues)
    : {
        ...buildDefaultInitialValues(
          existingLlmProvider,
          modelConfigurations,
          defaultModelName
        ),
        api_key: existingLlmProvider?.api_key ?? "",
        api_base: existingLlmProvider?.api_base ?? DEFAULT_API_BASE,
      };

  const validationSchema = isOnboarding
    ? Yup.object().shape({
        api_key: Yup.string().required("API Key is required"),
        api_base: Yup.string().required("API Base URL is required"),
        default_model_name: Yup.string().required("Model name is required"),
      })
    : buildDefaultValidationSchema().shape({
        api_key: Yup.string().required("API Key is required"),
        api_base: Yup.string().required("API Base URL is required"),
      });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validationSchema}
      validateOnMount={true}
      onSubmit={async (values, { setSubmitting }) => {
        if (isOnboarding && onboardingState && onboardingActions) {
          const modelConfigsToUse =
            fetchedModels.length > 0 ? fetchedModels : [];

          await submitOnboardingProvider({
            providerName: LLMProviderName.LITELLM_PROXY,
            payload: {
              ...values,
              model_configurations: modelConfigsToUse,
            },
            onboardingState,
            onboardingActions,
            isCustomProvider: false,
            onClose,
            setIsSubmitting: setSubmitting,
          });
        } else {
          await submitLLMProvider({
            providerName: LLMProviderName.LITELLM_PROXY,
            values,
            initialValues,
            modelConfigurations:
              fetchedModels.length > 0 ? fetchedModels : modelConfigurations,
            existingLlmProvider,
            shouldMarkAsDefault,
            setIsTesting,
            mutate,
            onClose,
            setSubmitting,
          });
        }
      }}
    >
      {(formikProps) => (
        <LiteLLMProxyModalInternals
          formikProps={formikProps}
          existingLlmProvider={existingLlmProvider}
          fetchedModels={fetchedModels}
          setFetchedModels={setFetchedModels}
          modelConfigurations={modelConfigurations}
          isTesting={isTesting}
          onClose={onClose}
          isOnboarding={isOnboarding}
        />
      )}
    </Formik>
  );
}
