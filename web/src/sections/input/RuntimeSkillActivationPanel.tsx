"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AgentRuntimeProfile,
  AgentSkillRuntimeBinding,
} from "@/app/admin/agents/interfaces";
import { Button } from "@opal/components";
import Checkbox from "@/refresh-components/inputs/Checkbox";
import InputTextArea from "@/refresh-components/inputs/InputTextArea";
import InputTypeIn from "@/refresh-components/inputs/InputTypeIn";
import Text from "@/refresh-components/texts/Text";

interface RuntimeSkillValidationErrors {
  selection?: string | null;
  targets?: string | null;
  approvalReference?: string | null;
}

interface RuntimeSkillActivationPanelProps {
  runtimeProfile: AgentRuntimeProfile;
  selectedSkillKeys: string[];
  onSelectedSkillKeysChange: (skillKeys: string[]) => void;
  skillTargetsText: string;
  onSkillTargetsTextChange: (value: string) => void;
  skillApprovalReference: string;
  onSkillApprovalReferenceChange: (value: string) => void;
  validationErrors?: RuntimeSkillValidationErrors;
  disabled: boolean;
}

function getRestrictedSkills(
  runtimeProfile: AgentRuntimeProfile
): AgentSkillRuntimeBinding[] {
  const activationRequired = new Set(
    runtimeProfile.activation_required_skill_keys ?? []
  );
  return runtimeProfile.bound_skills.filter((skill) =>
    activationRequired.has(skill.key)
  );
}

function detectRuntimeTargetType(target: string): string | null {
  const trimmed = target.trim();
  if (!trimmed) {
    return null;
  }
  if (/^https?:\/\/\S+$/i.test(trimmed)) {
    return "url";
  }
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(trimmed)) {
    return "cidr";
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    return "ip";
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) {
    return "domain";
  }
  return null;
}

function getTargetTypeExample(targetType: string): string {
  switch (targetType) {
    case "domain":
      return "example.com";
    case "url":
      return "https://example.com/path";
    case "ip":
      return "192.0.2.10";
    case "cidr":
      return "192.0.2.0/24";
    default:
      return "supported target format";
  }
}

export default function RuntimeSkillActivationPanel({
  runtimeProfile,
  selectedSkillKeys,
  onSelectedSkillKeysChange,
  skillTargetsText,
  onSkillTargetsTextChange,
  skillApprovalReference,
  onSkillApprovalReferenceChange,
  validationErrors,
  disabled,
}: RuntimeSkillActivationPanelProps) {
  const restrictedSkills = getRestrictedSkills(runtimeProfile);
  if (!restrictedSkills.length) {
    return null;
  }

  const selectedSkillKeySet = new Set(selectedSkillKeys);
  const selectedRestrictedSkills = restrictedSkills.filter((skill) =>
    selectedSkillKeySet.has(skill.key)
  );
  const requiresTargets = selectedRestrictedSkills.some(
    (skill) => skill.execution_scope === "authorized_scan"
  );
  const requiresApproval = selectedRestrictedSkills.some(
    (skill) => skill.requires_approval
  );
  const selectedExecutionScopes = Array.from(
    new Set(selectedRestrictedSkills.map((skill) => skill.execution_scope))
  );
  const selectedAllowedTargetTypes = Array.from(
    new Set(
      selectedRestrictedSkills.flatMap((skill) => skill.allowed_target_types ?? [])
    )
  );
  const [targetQuery, setTargetQuery] = useState("");
  const normalizedTargetQuery = targetQuery.trim().toLowerCase();
  const targetSuggestions = useMemo(
    () =>
      runtimeProfile.authorized_target_suggestions
        .filter((suggestion) => {
          const matchesType =
            !selectedAllowedTargetTypes.length ||
            selectedAllowedTargetTypes.includes(suggestion.target_type);
          const matchesQuery =
            !normalizedTargetQuery ||
            suggestion.target.toLowerCase().includes(normalizedTargetQuery) ||
            suggestion.owner.toLowerCase().includes(normalizedTargetQuery) ||
            suggestion.approval_reference
              .toLowerCase()
              .includes(normalizedTargetQuery);
          return matchesType && matchesQuery;
        })
        .sort((left, right) => {
          const leftExact =
            left.target.toLowerCase() === normalizedTargetQuery ? 1 : 0;
          const rightExact =
            right.target.toLowerCase() === normalizedTargetQuery ? 1 : 0;
          if (leftExact !== rightExact) {
            return rightExact - leftExact;
          }
          const leftPrefix = left.target
            .toLowerCase()
            .startsWith(normalizedTargetQuery)
            ? 1
            : 0;
          const rightPrefix = right.target
            .toLowerCase()
            .startsWith(normalizedTargetQuery)
            ? 1
            : 0;
          if (leftPrefix !== rightPrefix) {
            return rightPrefix - leftPrefix;
          }
          return left.target.localeCompare(right.target);
        }),
    [
      runtimeProfile.authorized_target_suggestions,
      selectedAllowedTargetTypes,
      normalizedTargetQuery,
    ]
  );
  const groupedTargetSuggestions = useMemo(() => {
    const groups = new Map<string, typeof targetSuggestions>();
    targetSuggestions.forEach((suggestion) => {
      const existingGroup = groups.get(suggestion.target_type) ?? [];
      existingGroup.push(suggestion);
      groups.set(suggestion.target_type, existingGroup);
    });
    return Array.from(groups.entries()).sort(([left], [right]) =>
      left.localeCompare(right)
    );
  }, [targetSuggestions]);
  const availableTargetSuggestionCount = useMemo(
    () =>
      runtimeProfile.authorized_target_suggestions.filter((suggestion) => {
        return (
          !selectedAllowedTargetTypes.length ||
          selectedAllowedTargetTypes.includes(suggestion.target_type)
        );
      }).length,
    [runtimeProfile.authorized_target_suggestions, selectedAllowedTargetTypes]
  );
  const targetLines = skillTargetsText
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  const singleAllowedTargetType =
    selectedAllowedTargetTypes.length === 1 ? selectedAllowedTargetTypes[0] : null;
  const detectedTargetRows = useMemo(
    () =>
      targetLines.map((target) => {
        const detectedType = detectRuntimeTargetType(target);
        const matchesAllowedType =
          !detectedType ||
          selectedAllowedTargetTypes.length === 0 ||
          selectedAllowedTargetTypes.includes(detectedType);
        return {
          target,
          detectedType,
          matchesAllowedType,
          suggestedExample: singleAllowedTargetType
            ? getTargetTypeExample(singleAllowedTargetType)
            : null,
        };
      }),
    [selectedAllowedTargetTypes, singleAllowedTargetType, targetLines]
  );
  const selectedTargetSuggestionMatches = useMemo(
    () =>
      runtimeProfile.authorized_target_suggestions.filter(
        (suggestion) =>
          targetLines.includes(suggestion.target) &&
          (!selectedAllowedTargetTypes.length ||
            selectedAllowedTargetTypes.includes(suggestion.target_type))
      ),
    [
      runtimeProfile.authorized_target_suggestions,
      selectedAllowedTargetTypes,
      targetLines,
    ]
  );
  const approvalSuggestionSet = new Set(
    runtimeProfile.approval_reference_suggestions
  );
  const selectedTargetApprovalReferences = Array.from(
    new Set(
      selectedTargetSuggestionMatches
        .map((suggestion) => suggestion.approval_reference)
        .filter(Boolean)
    )
  );
  const visibleApprovalSuggestions =
    selectedTargetApprovalReferences.length > 0
      ? selectedTargetApprovalReferences
      : runtimeProfile.approval_reference_suggestions;

  useEffect(() => {
    if (!requiresApproval || skillApprovalReference.trim()) {
      return;
    }
    const autoApprovalReference =
      selectedTargetApprovalReferences.length === 1
        ? selectedTargetApprovalReferences[0]
        : null;
    if (autoApprovalReference) {
      onSkillApprovalReferenceChange(autoApprovalReference);
    }
  }, [
    onSkillApprovalReferenceChange,
    requiresApproval,
    selectedTargetApprovalReferences,
    skillApprovalReference,
  ]);
  const appendTargetSuggestion = (
    target: string,
    approvalReference?: string | null
  ) => {
    if (targetLines.includes(target)) {
      if (
        approvalReference &&
        !skillApprovalReference &&
        approvalSuggestionSet.has(approvalReference)
      ) {
        onSkillApprovalReferenceChange(approvalReference);
      }
      return;
    }
    onSkillTargetsTextChange([...targetLines, target].join("\n"));
    if (
      approvalReference &&
      !skillApprovalReference &&
      approvalSuggestionSet.has(approvalReference)
    ) {
      onSkillApprovalReferenceChange(approvalReference);
    }
  };
  const removeTargetSuggestion = (target: string) => {
    const remainingTargets = targetLines.filter((value) => value !== target);
    onSkillTargetsTextChange(remainingTargets.join("\n"));
  };
  const multiplePoliciesSelected = selectedRestrictedSkills.length > 1;
  const distinctPolicySignatures = new Set(
    selectedRestrictedSkills.map(
      (skill) =>
        `${skill.execution_scope}|${skill.requires_approval}|${skill.gateway_required}|${skill.allowed_target_types.join(",")}`
    )
  );
  const hasPolicyConflictHint =
    multiplePoliciesSelected && distinctPolicySignatures.size > 1;
  const authorizedScanSkills = selectedRestrictedSkills.filter(
    (skill) => skill.execution_scope === "authorized_scan"
  );
  const commonAuthorizedTargetTypes =
    authorizedScanSkills.length <= 1
      ? authorizedScanSkills[0]?.allowed_target_types ?? []
      : authorizedScanSkills.reduce<string[]>(
          (intersection, skill, index) =>
            index === 0
              ? [...skill.allowed_target_types]
              : intersection.filter((targetType) =>
                  skill.allowed_target_types.includes(targetType)
                ),
          []
        );
  const hasBlockingSelectionConflict =
    selectedExecutionScopes.length > 1 ||
    (authorizedScanSkills.length > 1 &&
      commonAuthorizedTargetTypes.length === 0);
  const conflictDetails = [
    selectedExecutionScopes.length > 1
      ? "different execution scopes"
      : null,
    new Set(
      selectedRestrictedSkills.map((skill) =>
        skill.allowed_target_types.join(",")
      )
    ).size > 1
      ? "different target types"
      : null,
    new Set(selectedRestrictedSkills.map((skill) => skill.requires_approval))
      .size > 1
      ? "mixed approval requirements"
      : null,
    new Set(selectedRestrictedSkills.map((skill) => skill.gateway_required)).size >
    1
      ? "mixed gateway requirements"
      : null,
    authorizedScanSkills.length > 1 && commonAuthorizedTargetTypes.length === 0
      ? "no shared target type"
      : null,
  ].filter(Boolean) as string[];

  return (
    <div className="mx-1 mb-1 rounded-12 border border-border bg-background-neutral-00 px-3 py-2">
      <Text as="p" className="font-semibold">
        Runtime Skill Activation
      </Text>
      <Text text03 secondaryBody>
        Restricted bound skills are not activated by default. Select only the
        skills you want to enable for this message.
      </Text>
      {validationErrors?.selection && (
        <Text className="mt-2 text-xs text-status-error-05">
          {validationErrors.selection}
        </Text>
      )}
      {hasPolicyConflictHint && (
        <Text
          className={`mt-2 text-xs ${
            hasBlockingSelectionConflict
              ? "text-status-error-05"
              : "text-status-warning-05"
          }`}
        >
          Selected skills do not share the same runtime policy. Check target
          types, approval, and gateway requirements before sending.
          {conflictDetails.length > 0 ? ` Conflict areas: ${conflictDetails.join("; ")}.` : ""}
        </Text>
      )}

      <div className="mt-3 flex flex-col gap-2">
        {restrictedSkills.map((skill) => {
          const checked = selectedSkillKeySet.has(skill.key);
          const blockedReasons =
            runtimeProfile.blocked_skill_reasons?.[skill.key] ?? [];
          const canSelect = skill.accessible && skill.enabled;

          return (
            <div
              key={skill.key}
              className="rounded-08 border border-border px-3 py-2"
            >
              <div className="flex items-start gap-3">
                <Checkbox
                  checked={checked}
                  disabled={disabled || !canSelect}
                  onCheckedChange={(nextChecked) => {
                    if (nextChecked) {
                      onSelectedSkillKeysChange([
                        ...selectedSkillKeys.filter((key) => key !== skill.key),
                        skill.key,
                      ]);
                    } else {
                      onSelectedSkillKeysChange(
                        selectedSkillKeys.filter((key) => key !== skill.key)
                      );
                    }
                  }}
                  aria-label={`Activate runtime skill ${skill.name}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-3">
                    <Text as="p" className="font-semibold">
                      {skill.name}
                    </Text>
                    <span className="text-[11px] text-text-03">
                      {skill.execution_scope}
                      {skill.gateway_required ? " · gateway" : ""}
                      {skill.requires_approval ? " · approval" : ""}
                    </span>
                  </div>
                  <Text text03 secondaryBody className="mt-1">
                    {skill.description}
                  </Text>
                  <Text className="mt-2 text-xs text-text-03">
                    Policy: target types{" "}
                    {skill.allowed_target_types.length
                      ? skill.allowed_target_types.join(", ")
                      : "none"}
                    ; approval {skill.requires_approval ? "required" : "optional"}
                    ; gateway {skill.gateway_required ? "required" : "optional"}
                  </Text>
                  {blockedReasons.length > 0 && (
                    <div className="mt-2 text-xs text-status-error-05">
                      {blockedReasons.join("; ")}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {requiresTargets && (
        <div className="mt-3">
          <Text as="p" className="mb-1 font-semibold">
            Authorized Targets
          </Text>
          <Text className="mb-2 text-xs text-text-03">
            Allowed target types:{" "}
            {selectedAllowedTargetTypes.length > 0
              ? selectedAllowedTargetTypes.join(", ")
              : "any"}
          </Text>
          {singleAllowedTargetType && (
            <Text className="mb-2 text-xs text-text-03">
              Only {singleAllowedTargetType} targets are allowed here. Example:{" "}
              {getTargetTypeExample(singleAllowedTargetType)}
            </Text>
          )}
          {targetLines.length > 0 && (
            <div className="mb-2">
              <Text className="mb-1 text-xs text-text-03">
                Selected authorized targets
              </Text>
              <div className="flex flex-wrap gap-1">
                {targetLines.map((target) => (
                  <Button
                    key={`selected-target-chip:${target}`}
                    type="button"
                    size="xs"
                    prominence="secondary"
                    onClick={() => removeTargetSuggestion(target)}
                    disabled={disabled}
                  >
                    {`${target} x`}
                  </Button>
                ))}
              </div>
            </div>
          )}
          <InputTextArea
            value={skillTargetsText}
            onChange={(event) => onSkillTargetsTextChange(event.target.value)}
            rows={3}
            resizable={false}
            placeholder="One target per line, for example: example.com"
            variant={disabled ? "disabled" : "primary"}
          />
          {validationErrors?.targets && (
            <Text className="mt-1 text-xs text-status-error-05">
              {validationErrors.targets}
            </Text>
          )}
          {detectedTargetRows.length > 0 && (
            <div className="mt-2 flex flex-col gap-1">
              <Text className="text-xs text-text-03">
                Manual target type detection
              </Text>
              {detectedTargetRows.map((row) => (
                <Text
                  key={`detected-target:${row.target}`}
                  className={`text-xs ${
                    row.matchesAllowedType
                      ? "text-text-03"
                      : "text-status-error-05"
                  }`}
                >
                  {`${row.target} -> ${row.detectedType ?? "unrecognized"}`}
                  {!row.matchesAllowedType
                    ? ` (not allowed for ${selectedAllowedTargetTypes.join(", ")}; try ${row.suggestedExample ?? "a supported target format"})`
                    : !row.detectedType && row.suggestedExample
                      ? ` (try ${row.suggestedExample})`
                    : ""}
                </Text>
              ))}
            </div>
          )}
          {availableTargetSuggestionCount > 0 && (
            <div className="mt-2">
              <Text className="mb-1 text-xs text-text-03">
                Suggested authorized targets
              </Text>
              <InputTypeIn
                value={targetQuery}
                onChange={(event) => setTargetQuery(event.target.value)}
                placeholder="Search authorized targets, owners, or approval refs"
                leftSearchIcon
                variant={disabled ? "disabled" : "primary"}
              />
              {targetSuggestions.length === 0 && (
                <Text className="mt-2 text-xs text-text-03">
                  No authorized targets match the current search or target type
                  constraints.
                </Text>
              )}
              <div className="mt-2 flex flex-col gap-2">
                {groupedTargetSuggestions.map(([targetType, suggestions]) => (
                  <div key={`target-group:${targetType}`}>
                    <Text className="mb-1 text-xs text-text-03">
                      {`${targetType} (${suggestions.length})`}
                    </Text>
                    <div className="flex flex-wrap gap-1">
                      {suggestions.map((suggestion) => (
                        <Button
                          key={`${suggestion.target_type}:${suggestion.target}:${suggestion.approval_reference}`}
                          type="button"
                          size="xs"
                          prominence={
                            targetLines.includes(suggestion.target)
                              ? "secondary"
                              : "tertiary"
                          }
                          onClick={() => {
                            if (targetLines.includes(suggestion.target)) {
                              removeTargetSuggestion(suggestion.target);
                              return;
                            }
                            appendTargetSuggestion(
                              suggestion.target,
                              suggestion.approval_reference
                            );
                          }}
                          disabled={disabled}
                        >
                          {targetLines.includes(suggestion.target)
                            ? `${suggestion.target} selected`
                            : suggestion.target}
                        </Button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {targetSuggestions.length > 0 && (
                <div className="mt-2 flex flex-col gap-1">
                  {targetSuggestions.slice(0, 5).map((suggestion) => (
                    <Text
                      key={`meta:${suggestion.target}:${suggestion.approval_reference}`}
                      className="text-xs text-text-03"
                    >
                      {suggestion.target} [{suggestion.target_type}] · owner{" "}
                      {suggestion.owner} · approval{" "}
                      {suggestion.approval_reference}
                    </Text>
                  ))}
                </div>
              )}
              {selectedTargetSuggestionMatches.length > 0 && (
                <div className="mt-2 flex flex-col gap-1">
                  <Text className="text-xs text-text-03">
                    Selected targets are linked to these approvals:
                  </Text>
                  {selectedTargetSuggestionMatches.map((suggestion) => (
                    <Text
                      key={`selected:${suggestion.target}:${suggestion.approval_reference}`}
                      className="text-xs text-text-03"
                    >
                      {suggestion.target} [{suggestion.target_type}] · approval{" "}
                      {suggestion.approval_reference}
                    </Text>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {requiresApproval && (
        <div className="mt-3">
          <Text as="p" className="mb-1 font-semibold">
            Approval Reference
          </Text>
          <InputTypeIn
            value={skillApprovalReference}
            onChange={(event) =>
              onSkillApprovalReferenceChange(event.target.value)
            }
            placeholder="For example: CHG-1001"
            variant={disabled ? "disabled" : "primary"}
          />
          {validationErrors?.approvalReference && (
            <Text className="mt-1 text-xs text-status-error-05">
              {validationErrors.approvalReference}
            </Text>
          )}
          {visibleApprovalSuggestions.length > 0 && (
            <div className="mt-2">
              <Text className="mb-1 text-xs text-text-03">
                {selectedTargetApprovalReferences.length > 0
                  ? "Approval references for selected targets"
                  : "Known approval references"}
              </Text>
              <div className="flex flex-wrap gap-1">
                {visibleApprovalSuggestions.map((reference) => (
                  <Button
                    key={reference}
                    type="button"
                    size="xs"
                    prominence="tertiary"
                    onClick={() => onSkillApprovalReferenceChange(reference)}
                    disabled={disabled}
                  >
                    {reference}
                  </Button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
