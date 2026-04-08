"use client";

import { useState } from "react";
import { useSWRConfig } from "swr";
import { Formik } from "formik";
import * as Yup from "yup";
import InputTypeInField from "@/refresh-components/form/InputTypeInField";
import * as InputLayouts from "@/layouts/input-layouts";
import { LLMProviderFormProps } from "@/interfaces/llm";
import {
  OPENAI_COMPATIBLE_TEMPLATES,
  OpenAICompatibleTemplateId,
} from "@/lib/llmConfig/openaiCompatibleTemplates";
import {
  buildAvailableModelConfigurations,
  buildDefaultInitialValues,
  buildDefaultValidationSchema,
  buildOnboardingInitialValues,
  BaseLLMFormValues,
} from "@/sections/modals/llmConfig/utils";
import {
  submitLLMProvider,
  submitOnboardingProvider,
} from "@/sections/modals/llmConfig/svc";
import {
  APIKeyField,
  DisplayNameField,
  FieldSeparator,
  FieldWrapper,
  LLMConfigurationModalWrapper,
  ModelsAccessField,
  ModelsField,
  SingleDefaultModelField,
} from "@/sections/modals/llmConfig/shared";

interface OpenAICompatibleTemplateModalProps extends LLMProviderFormProps {
  templateId: OpenAICompatibleTemplateId;
}

interface OpenAICompatibleTemplateValues extends BaseLLMFormValues {
  api_key: string;
  api_base: string;
  provider: string;
}

export default function OpenAICompatibleTemplateModal({
  templateId,
  variant = "llm-configuration",
  existingLlmProvider,
  shouldMarkAsDefault,
  open,
  onOpenChange,
  defaultModelName,
  onboardingState,
  onboardingActions,
}: OpenAICompatibleTemplateModalProps) {
  const template = OPENAI_COMPATIBLE_TEMPLATES[templateId];
  const isOnboarding = variant === "onboarding";
  const [isTesting, setIsTesting] = useState(false);
  const { mutate } = useSWRConfig();

  if (open === false) {
    return null;
  }

  const onClose = () => onOpenChange?.(false);
  const modelConfigurations = buildAvailableModelConfigurations(
    existingLlmProvider,
    {
      name: template.id,
      known_models: template.knownModels,
      recommended_default_model: {
        name: template.defaultModelName,
        display_name:
          template.knownModels.find(
            (model) => model.name === template.defaultModelName
          )?.display_name ?? template.defaultModelName,
      },
    }
  );

  const initialValues: OpenAICompatibleTemplateValues = isOnboarding
    ? ({
        ...buildOnboardingInitialValues(),
        name: template.displayName,
        provider: template.providerName,
        api_key: "",
        api_base: template.defaultApiBase,
        default_model_name: template.defaultModelName,
      } as OpenAICompatibleTemplateValues)
    : {
        ...buildDefaultInitialValues(
          existingLlmProvider,
          modelConfigurations,
          defaultModelName
        ),
        name: existingLlmProvider?.name ?? template.displayName,
        provider: existingLlmProvider?.provider ?? template.providerName,
        api_key: existingLlmProvider?.api_key ?? "",
        api_base: existingLlmProvider?.api_base ?? template.defaultApiBase,
        default_model_name:
          defaultModelName &&
          modelConfigurations.some((model) => model.name === defaultModelName)
            ? defaultModelName
            : template.defaultModelName,
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
          await submitOnboardingProvider({
            providerName: template.providerName,
            payload: {
              ...values,
              provider: template.providerName,
              model_configurations: modelConfigurations,
            },
            onboardingState,
            onboardingActions,
            isCustomProvider: false,
            onClose,
            setIsSubmitting: setSubmitting,
          });
        } else {
          await submitLLMProvider({
            providerName: template.providerName,
            values,
            initialValues,
            modelConfigurations,
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
        <LLMConfigurationModalWrapper
          providerEndpoint={template.id}
          providerName={template.providerDisplayName}
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
              subDescription="Defaults to the provider's OpenAI-compatible endpoint. Replace it only if you need a regional or proxy endpoint."
            >
              <InputTypeInField
                name="api_base"
                placeholder={template.defaultApiBase}
              />
            </InputLayouts.Vertical>
          </FieldWrapper>

          <APIKeyField providerName={template.displayName} />

          {!isOnboarding && (
            <>
              <FieldSeparator />
              <DisplayNameField disabled={!!existingLlmProvider} />
            </>
          )}

          <FieldSeparator />
          {isOnboarding ? (
            <SingleDefaultModelField placeholder={`E.g. ${template.defaultModelName}`} />
          ) : (
            <ModelsField
              modelConfigurations={modelConfigurations}
              formikProps={formikProps}
              recommendedDefaultModel={{
                name: template.defaultModelName,
                display_name:
                  template.knownModels.find(
                    (model) => model.name === template.defaultModelName
                  )?.display_name ?? template.defaultModelName,
              }}
              shouldShowAutoUpdateToggle={false}
            />
          )}

          {!isOnboarding && (
            <>
              <FieldSeparator />
              <ModelsAccessField formikProps={formikProps} />
            </>
          )}
        </LLMConfigurationModalWrapper>
      )}
    </Formik>
  );
}
