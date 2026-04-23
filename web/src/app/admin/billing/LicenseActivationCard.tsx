"use client";

import { useState } from "react";
import Card from "@/refresh-components/cards/Card";
import { Button } from "@opal/components";
import { Disabled } from "@opal/core";
import Text from "@/refresh-components/texts/Text";
import Message from "@/refresh-components/messages/Message";
import InputFile from "@/refresh-components/inputs/InputFile";
import { Section } from "@/layouts/general-layouts";
import * as InputLayouts from "@/layouts/input-layouts";
import { SvgXCircle, SvgCheckCircle, SvgXOctagon } from "@opal/icons";
import { uploadLicense } from "@/lib/billing/svc";
import {
  LicenseOperationalState,
  LicenseStatus,
} from "@/lib/billing/interfaces";
import { formatDateShort } from "@/lib/dateUtils";
import { BILLING_HELP_URL } from "@/lib/constants";

interface LicenseActivationCardProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  license?: LicenseStatus;
  hideClose?: boolean;
}

interface OperationalStateNotice {
  level: "warning" | "error";
  text: string;
  description: string;
}

function getOperationalStateNotice(
  operationalState: LicenseOperationalState | null | undefined,
  reason: string | null | undefined
): OperationalStateNotice | null {
  switch (operationalState) {
    case "verification_failed":
      return {
        level: "error",
        text: "Access key verification failed",
        description:
          reason ||
          "The stored key could not be verified. Upload a valid key to recover.",
      };
    case "disconnected_cached":
      return {
        level: "warning",
        text: "Billing service is temporarily disconnected",
        description:
          reason ||
          "Using cached billing state. You can still upload a local access key.",
      };
    case "grace_period":
      return {
        level: "warning",
        text: "Access key is in grace period",
        description:
          reason ||
          "Renew or update your key soon to avoid gated access.",
      };
    case "expired":
      return {
        level: "warning",
        text: "Access key is expired",
        description:
          reason ||
          "Upload a valid key to restore full access.",
      };
    default:
      return null;
  }
}

export default function LicenseActivationCard({
  isOpen,
  onClose,
  onSuccess,
  license,
  hideClose,
}: LicenseActivationCardProps) {
  const [licenseKey, setLicenseKey] = useState("");
  const [isActivating, setIsActivating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [showInput, setShowInput] = useState(!license?.has_license);

  const hasLicense = license?.has_license;
  const isDateExpired = license?.expires_at
    ? new Date(license.expires_at) < new Date()
    : false;
  const isExpired =
    license?.status === "expired" ||
    license?.status === "gated_access" ||
    isDateExpired;
  const expirationDate = license?.expires_at
    ? formatDateShort(license.expires_at)
    : null;
  const operationalStateNotice = getOperationalStateNotice(
    license?.operational_state,
    license?.operational_state_reason
  );

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      setError("Please enter an access key");
      return;
    }

    setIsActivating(true);
    setError(null);

    try {
      await uploadLicense(licenseKey.trim());
      setSuccess(true);
      setTimeout(() => {
        onSuccess();
        handleClose();
      }, 1000);
    } catch (err) {
      console.error("Error activating access key:", err);
      setError(
        err instanceof Error ? err.message : "Failed to activate access key"
      );
    } finally {
      setIsActivating(false);
    }
  };

  const handleClose = () => {
    setLicenseKey("");
    setError(null);
    setSuccess(false);
    setShowInput(!license?.has_license);
    onClose();
  };

  if (!isOpen) return null;

  // License status view (when license exists and not editing)
  if (hasLicense && !showInput) {
    return (
      <Card padding={1} alignItems="stretch">
        {operationalStateNotice && (
          <Message
            static
            icon
            close={false}
            warning={operationalStateNotice.level === "warning"}
            error={operationalStateNotice.level === "error"}
            text={operationalStateNotice.text}
            description={operationalStateNotice.description}
            className="w-full"
          />
        )}
        <Section
          flexDirection="row"
          justifyContent="between"
          alignItems="center"
          height="auto"
        >
          <Section
            flexDirection="column"
            alignItems="start"
            gap={0.5}
            height="auto"
            width="auto"
          >
            {isExpired ? (
              <SvgXOctagon size={16} className="stroke-status-error-05" />
            ) : (
              <SvgCheckCircle size={16} className="stroke-status-success-05" />
            )}
            <Text secondaryBody text03>
              {isExpired ? (
                <>Access key expired</>
              ) : (
                <>
                  Access key active until{" "}
                  <Text secondaryBody text04>
                    {expirationDate}
                  </Text>
                </>
              )}
            </Text>
          </Section>
          <Section flexDirection="row" gap={0.5} height="auto" width="auto">
            <Button prominence="secondary" onClick={() => setShowInput(true)}>
              Update Access Key
            </Button>
            {!hideClose && (
              <Button prominence="tertiary" onClick={handleClose}>
                Close
              </Button>
            )}
          </Section>
        </Section>
      </Card>
    );
  }

  // License input form
  return (
    <Card padding={0} alignItems="stretch" gap={0}>
      {/* Header */}
      <Section flexDirection="column" alignItems="stretch" gap={0} padding={1}>
        <Section
          flexDirection="row"
          justifyContent="between"
          alignItems="center"
        >
          <Text headingH3>
            {hasLicense ? "Update Access Key" : "Add Access Key"}
          </Text>
          <Disabled disabled={isActivating}>
            <Button prominence="secondary" onClick={handleClose}>
              Cancel
            </Button>
          </Disabled>
        </Section>
        <Text secondaryBody text03>
          Manually add an access key for this Onyx deployment.
        </Text>
      </Section>

      {/* Content */}
      <div className="billing-content-area">
        <Section
          flexDirection="column"
          alignItems="stretch"
          gap={0.5}
          padding={1}
        >
          {operationalStateNotice && (
            <Message
              static
              icon
              close={false}
              warning={operationalStateNotice.level === "warning"}
              error={operationalStateNotice.level === "error"}
              text={operationalStateNotice.text}
              description={operationalStateNotice.description}
              className="w-full"
            />
          )}
          {success && (
            <div className="billing-success-message">
              <Text secondaryBody>
                Access key {hasLicense ? "updated" : "activated"} successfully!
              </Text>
            </div>
          )}

          <InputLayouts.Vertical
            title="Access Key"
            subDescription={
              error
                ? undefined
                : "Paste or attach the access key file issued for this deployment."
            }
          >
            <InputFile
              placeholder="eyJwYXlsb2FkIjogeyJ2ZXJzaW9..."
              setValue={(value) => {
                setLicenseKey(value);
                setError(null);
              }}
              error={!!error}
              className="billing-license-input"
            />
            {error && (
              <Section
                flexDirection="row"
                alignItems="center"
                justifyContent="start"
                gap={0.25}
                height="auto"
              >
                <div className="billing-error-icon">
                  <SvgXCircle />
                </div>
                <Text secondaryBody text04>
                  {error}.{" "}
                  <a
                    href={BILLING_HELP_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="billing-help-link"
                  >
                    Deployment Help
                  </a>
                </Text>
              </Section>
            )}
          </InputLayouts.Vertical>
        </Section>
      </div>

      {/* Footer */}
      <Section flexDirection="row" justifyContent="end" padding={1}>
        <Disabled disabled={isActivating || !licenseKey.trim() || success}>
          <Button onClick={handleActivate}>
            {isActivating
              ? "Activating..."
              : hasLicense
                ? "Update Access Key"
                : "Activate Access Key"}
          </Button>
        </Disabled>
      </Section>
    </Card>
  );
}
