"use client";

import { useState } from "react";
import Link from "next/link";
import { COMMUNITY_URL, SUPPORT_EMAIL } from "@/lib/constants";
import ErrorPageLayout from "@/components/errorPages/ErrorPageLayout";
import { Button } from "@opal/components";
import { Disabled } from "@opal/core";
import InlineExternalLink from "@/refresh-components/InlineExternalLink";
import { logout } from "@/lib/user";
import { loadStripe } from "@stripe/stripe-js";
import { NEXT_PUBLIC_CLOUD_ENABLED } from "@/lib/constants";
import { useLicense } from "@/hooks/useLicense";
import { useSettingsContext } from "@/providers/SettingsProvider";
import { ApplicationStatus } from "@/interfaces/settings";
import Text from "@/refresh-components/texts/Text";
import Message from "@/refresh-components/messages/Message";
import { SvgLock } from "@opal/icons";

const linkClassName = "text-action-link-05 hover:text-action-link-06 underline";

type AccessOperationalNotice = {
  level: "warning" | "error";
  text: string;
  description: string;
};

function getAccessOperationalNotice(
  operationalState: string | null | undefined,
  reason: string | null | undefined
): AccessOperationalNotice | null {
  switch (operationalState) {
    case "verification_failed":
      return {
        level: "error",
        text: "Deployment access key verification failed",
        description:
          reason ||
          "The stored key could not be verified. Re-upload a valid key from Plans & Billing.",
      };
    case "disconnected_cached":
      return {
        level: "warning",
        text: "Billing service is temporarily disconnected",
        description:
          reason ||
          "The deployment is using cached access state. Retry from Plans & Billing when connectivity is restored.",
      };
    case "grace_period":
      return {
        level: "warning",
        text: "Deployment access is in grace period",
        description:
          reason ||
          "Renew or refresh deployment access soon to avoid full gating.",
      };
    case "expired":
      return {
        level: "warning",
        text: "Deployment access has expired",
        description:
          reason ||
          "Refresh or upload a valid access key from Plans & Billing to restore service.",
      };
    default:
      return null;
  }
}

const fetchStripePublishableKey = async (): Promise<string> => {
  const response = await fetch("/api/tenants/stripe-publishable-key");
  if (!response.ok) {
    throw new Error("Failed to fetch Stripe publishable key");
  }
  const data = await response.json();
  return data.publishable_key;
};

const fetchResubscriptionSession = async () => {
  const response = await fetch("/api/tenants/create-subscription-session", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error("Failed to create resubscription session");
  }
  return response.json();
};

export default function AccessRestricted() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data: license } = useLicense();
  const settings = useSettingsContext();

  const isSeatLimitExceeded =
    settings.settings.application_status ===
    ApplicationStatus.SEAT_LIMIT_EXCEEDED;
  const hadPreviousLicense = license?.has_license === true;
  const showRenewalMessage = NEXT_PUBLIC_CLOUD_ENABLED || hadPreviousLicense;
  const accessOperationalNotice = getAccessOperationalNotice(
    license?.operational_state,
    license?.operational_state_reason
  );

  function getSeatLimitMessage() {
    const { used_seats, seat_count } = settings.settings;
    const counts =
      used_seats != null && seat_count != null
        ? ` (${used_seats} users / ${seat_count} seats)`
        : "";
    return `Your organization has exceeded its configured seat count${counts}. Access is restricted until the number of users is reduced or your plan settings are updated.`;
  }

  const initialModalMessage = isSeatLimitExceeded
    ? getSeatLimitMessage()
    : showRenewalMessage
      ? NEXT_PUBLIC_CLOUD_ENABLED
        ? "Your access to Onyx has been temporarily suspended due to a lapse in your subscription."
        : "Your access to Onyx has been temporarily suspended because this deployment no longer has active paid access configured."
      : "Additional paid access is required to use this Onyx deployment. Your data remains protected and will be available once access is enabled.";

  const handleResubscribe = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const publishableKey = await fetchStripePublishableKey();
      const { sessionId } = await fetchResubscriptionSession();
      const stripe = await loadStripe(publishableKey);

      if (stripe) {
        await stripe.redirectToCheckout({ sessionId });
      } else {
        throw new Error("Stripe failed to load");
      }
    } catch (error) {
      console.error("Error creating resubscription session:", error);
      setError("Error opening resubscription page. Please try again later.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <ErrorPageLayout>
      <div className="flex items-center gap-2">
        <Text headingH2>Access Restricted</Text>
        <SvgLock className="stroke-status-error-05 w-[1.5rem] h-[1.5rem]" />
      </div>

      <Text text03>{initialModalMessage}</Text>
      {accessOperationalNotice && (
        <Message
          static
          icon
          close={false}
          warning={accessOperationalNotice.level === "warning"}
          error={accessOperationalNotice.level === "error"}
          text={accessOperationalNotice.text}
          description={accessOperationalNotice.description}
          className="w-full"
        />
      )}

      {isSeatLimitExceeded ? (
        <>
          <Text text03>
            If you are an administrator, you can manage users on the{" "}
            <Link className={linkClassName} href="/admin/users">
              User Management
            </Link>{" "}
            page or update plan settings on the{" "}
            <Link className={linkClassName} href="/admin/billing">
              Plans & Billing
            </Link>{" "}
            page.
          </Text>

          <div className="flex flex-row gap-2">
            <Button
              onClick={async () => {
                await logout();
                window.location.reload();
              }}
            >
              Log out
            </Button>
          </div>
        </>
      ) : NEXT_PUBLIC_CLOUD_ENABLED ? (
        <>
          <Text text03>
            To reinstate your access and continue benefiting from Onyx&apos;s
            powerful features, please update your payment information.
          </Text>

          <Text text03>
            If you&apos;re an admin, you can manage your subscription by
            clicking the button below. For other users, please reach out to your
            administrator to address this matter.
          </Text>

          <div className="flex flex-row gap-2">
            <Disabled disabled={isLoading}>
              <Button onClick={handleResubscribe}>
                {isLoading ? "Loading..." : "Resubscribe"}
              </Button>
            </Disabled>
            <Button
              prominence="secondary"
              onClick={async () => {
                await logout();
                window.location.reload();
              }}
            >
              Log out
            </Button>
          </div>

          {error && <Text className="text-status-error-05">{error}</Text>}
        </>
      ) : (
        <>
          <Text text03>
            {hadPreviousLicense
              ? "To reinstate your access and continue using Onyx, please contact your system administrator to refresh this deployment's paid access."
              : "To get started, please contact your system administrator to enable paid access for this deployment."}
          </Text>

          <Text text03>
            If you are the administrator, please visit the{" "}
            <Link className={linkClassName} href="/admin/billing">
              Plans & Billing
            </Link>{" "}
            page to {hadPreviousLicense ? "refresh" : "enable"} access, or
            reach out to{" "}
            <a className={linkClassName} href={`mailto:${SUPPORT_EMAIL}`}>
              {SUPPORT_EMAIL}
            </a>{" "}
            for deployment assistance.
          </Text>

          <div className="flex flex-row gap-2">
            <Button
              onClick={async () => {
                await logout();
                window.location.reload();
              }}
            >
              Log out
            </Button>
          </div>
        </>
      )}

      <Text text03>
        Need help? Join our{" "}
        <InlineExternalLink
          className={linkClassName}
          href={COMMUNITY_URL}
        >
          support center
        </InlineExternalLink>{" "}
        for support.
      </Text>
    </ErrorPageLayout>
  );
}
