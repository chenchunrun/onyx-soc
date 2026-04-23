"use client";

import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import * as SettingsLayouts from "@/layouts/settings-layouts";
import { Section } from "@/layouts/general-layouts";
import Button from "@/refresh-components/buttons/Button";
import Text from "@/refresh-components/texts/Text";
import { SvgArrowUpCircle, SvgWallet } from "@opal/icons";
import type { IconProps } from "@opal/types";
import {
  useBillingInformation,
  useLicense,
  BillingInformation,
  hasActiveSubscription,
  claimLicense,
  type LicenseOperationalState,
} from "@/lib/billing";
import {
  NEXT_PUBLIC_CLOUD_ENABLED,
  NEXT_PUBLIC_SELF_HOSTED_ONLINE_BILLING_ENABLED,
  SUPPORT_EMAIL,
} from "@/lib/constants";
import { useUser } from "@/providers/UserProvider";
import Message from "@/refresh-components/messages/Message";

import PlansView from "./PlansView";
import CheckoutView from "./CheckoutView";
import BillingDetailsView from "./BillingDetailsView";
import LicenseActivationCard from "./LicenseActivationCard";
import "./billing.css";

// sessionStorage key: value is a unix-ms expiry timestamp
const BILLING_ACTIVATING_KEY = "billing_license_activating_until";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

type BillingView = "plans" | "details" | "checkout" | null;

interface ViewConfig {
  icon: React.FunctionComponent<IconProps>;
  title: string;
  showBackButton: boolean;
}

interface OperationalStateBanner {
  level: "warning" | "error";
  text: string;
  description: string;
}

function getOperationalStateBanner(
  operationalState: LicenseOperationalState | null,
  reason: string | null
): OperationalStateBanner | null {
  switch (operationalState) {
    case "grace_period":
      return {
        level: "warning",
        text: "Deployment access is in grace period",
        description:
          reason ||
          "Renew your plan before the grace period ends to avoid gated access.",
      };
    case "expired":
      return {
        level: "warning",
        text: "Deployment access is expired",
        description:
          reason ||
          "Upload or claim a valid access key to restore full billing capabilities.",
      };
    case "verification_failed":
      return {
        level: "error",
        text: "Access key verification failed",
        description:
          reason ||
          "The stored access key could not be verified. Re-upload or re-claim a valid key.",
      };
    case "disconnected_cached":
      return {
        level: "warning",
        text: "Billing service is temporarily disconnected",
        description:
          reason ||
          "Showing cached subscription state while Stripe connectivity is unavailable.",
      };
    default:
      return null;
  }
}

// ----------------------------------------------------------------------------
// FooterLinks (inlined)
// ----------------------------------------------------------------------------

function FooterLinks({
  hasSubscription,
  onActivateLicense,
  hideLicenseLink,
}: {
  hasSubscription?: boolean;
  onActivateLicense?: () => void;
  hideLicenseLink?: boolean;
}) {
  const { user } = useUser();
  const licenseText = hasSubscription
    ? "Update Access Key"
    : "Activate Access Key";
  const billingHelpHref = `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(
    `[Billing] support for ${user?.email ?? "unknown"}`
  )}`;

  return (
    <Section flexDirection="row" justifyContent="center" gap={1} height="auto">
      {onActivateLicense && !hideLicenseLink && (
        <>
          <Text secondaryBody text03>
            Have an access key?
          </Text>
          {/* TODO(@raunakab): migrate to opal Button once className/iconClassName is resolved */}
          <Button action tertiary onClick={onActivateLicense}>
            <Text secondaryBody text05 className="underline">
              {licenseText}
            </Text>
          </Button>
        </>
      )}
      {/* TODO(@raunakab): migrate to opal Button once className/iconClassName is resolved */}
      <Button
        action
        tertiary
        href={billingHelpHref}
        className="billing-text-link"
      >
        <Text secondaryBody text03 className="underline">
          Deployment Help
        </Text>
      </Button>
    </Section>
  );
}

// ----------------------------------------------------------------------------
// BillingPage
// ----------------------------------------------------------------------------

export default function BillingPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  // Start with null view to prevent flash - will be set once data loads
  const [view, setView] = useState<BillingView | null>(null);
  const [showLicenseActivationInput, setShowLicenseActivationInput] =
    useState(false);
  const [licenseCardAutoOpened, setLicenseCardAutoOpened] = useState(false);
  const [viewChangeId, setViewChangeId] = useState(0);
  const [transitionType, setTransitionType] = useState<
    "expand" | "collapse" | "fade"
  >("fade");
  const [isActivating, setIsActivating] = useState<boolean>(false);

  const {
    data: billingData,
    isLoading: billingLoading,
    error: billingError,
    refresh: refreshBilling,
  } = useBillingInformation();
  const {
    data: licenseData,
    isLoading: licenseLoading,
    refresh: refreshLicense,
  } = useLicense();

  const isLoading = billingLoading || licenseLoading;
  const hasSubscription = billingData && hasActiveSubscription(billingData);
  const billing = hasSubscription ? (billingData as BillingInformation) : null;
  const isSelfHosted = !NEXT_PUBLIC_CLOUD_ENABLED;
  const onlineBillingEnabled =
    NEXT_PUBLIC_CLOUD_ENABLED || NEXT_PUBLIC_SELF_HOSTED_ONLINE_BILLING_ENABLED;

  const hasManualLicense = licenseData?.source === "manual_upload";
  const operationalState =
    billingData?.operational_state ?? licenseData?.operational_state ?? null;
  const operationalStateReason =
    billingData?.operational_state_reason ??
    licenseData?.operational_state_reason ??
    null;
  const operationalStateBanner =
    !isLoading && !isActivating
      ? getOperationalStateBanner(operationalState, operationalStateReason)
      : null;

  // Air-gapped: billing endpoint is unreachable (manual license + connectivity error)
  const isAirGapped = !!(hasManualLicense && billingError);

  // Stripe error: auto-fetched license but billing endpoint is unreachable
  const hasStripeError = !!(
    isSelfHosted &&
    licenseData?.has_license &&
    billingError &&
    !hasManualLicense
  );

  // Manual license without active Stripe subscription
  // Stripe-dependent actions (manage plan, update seats) won't work
  const isManualLicenseOnly = !!(hasManualLicense && !hasSubscription);

  // Set initial view based on subscription status (only once when data first loads)
  useEffect(() => {
    if (!isLoading && view === null) {
      const shouldShowDetails =
        hasSubscription || (isSelfHosted && licenseData?.has_license);
      setView(shouldShowDetails ? "details" : "plans");
    }
  }, [
    isLoading,
    hasSubscription,
    isSelfHosted,
    licenseData?.has_license,
    view,
  ]);

  // Read activating state from sessionStorage after mount (avoids SSR hydration mismatch)
  useEffect(() => {
    const raw = sessionStorage.getItem(BILLING_ACTIVATING_KEY);
    if (!raw) return;
    if (Number(raw) > Date.now()) {
      setIsActivating(true);
    } else {
      sessionStorage.removeItem(BILLING_ACTIVATING_KEY);
    }
  }, []);

  // Show license activation card when there's a Stripe error
  useEffect(() => {
    if (hasStripeError && !showLicenseActivationInput) {
      setLicenseCardAutoOpened(true);
      setShowLicenseActivationInput(true);
    }
  }, [hasStripeError, showLicenseActivationInput]);

  // Handle return from checkout or customer portal
  useEffect(() => {
    const sessionId = searchParams.get("session_id");
    const portalReturn = searchParams.get("portal_return");

    if (!sessionId && !portalReturn) return;

    router.replace("/admin/billing", { scroll: false });

    let cancelled = false;

    const handleBillingReturn = async () => {
      if (!NEXT_PUBLIC_CLOUD_ENABLED && onlineBillingEnabled) {
        // Retry up to 3 times with 2s backoff. The license may not be available
        // immediately if the Stripe webhook hasn't finished processing yet
        // (redirect and webhook fire nearly simultaneously).
        let lastError: Error | null = null;
        for (let attempt = 0; attempt < 3; attempt++) {
          if (cancelled) return;
          try {
            // After checkout, exchange session_id for license; after portal, re-sync license
            await claimLicense(sessionId ?? undefined);
            if (cancelled) return;
            refreshLicense();
            // Refresh the page to update settings (including ee_features_enabled)
            router.refresh();
            // Navigate to billing details now that the license is active
            changeView("details");
            lastError = null;
            break;
          } catch (err) {
            lastError = err instanceof Error ? err : new Error("Unknown error");
            if (attempt < 2) {
              await new Promise((resolve) => setTimeout(resolve, 2000));
            }
          }
        }
        if (cancelled) return;
        if (lastError) {
          console.error(
            "Failed to sync deployment access after billing return:",
            lastError
          );
          // Show an activating banner on the plans view and keep retrying in the background.
          sessionStorage.setItem(
            BILLING_ACTIVATING_KEY,
            String(Date.now() + 120_000)
          );
          setIsActivating(true);
          changeView("plans");
        }
      }
      if (!cancelled && onlineBillingEnabled) refreshBilling();
    };
    handleBillingReturn();

    return () => {
      cancelled = true;
    };
    // changeView intentionally omitted: it only calls stable state setters and the
    // effect runs at most once (when session_id/portal_return params are present).
  }, [searchParams, router, refreshBilling, refreshLicense, onlineBillingEnabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll every 15s while activating, up to 2 minutes, to detect when the license arrives.
  useEffect(() => {
    if (!isActivating) return;

    let requestInFlight = false;

    const intervalId = setInterval(async () => {
      if (requestInFlight) return;
      const raw = sessionStorage.getItem(BILLING_ACTIVATING_KEY);
      if (!raw || Number(raw) <= Date.now()) {
        // Expired — stop immediately without waiting for React cleanup
        clearInterval(intervalId);
        sessionStorage.removeItem(BILLING_ACTIVATING_KEY);
        setIsActivating(false);
        return;
      }
      requestInFlight = true;
      try {
        await claimLicense(undefined);
        sessionStorage.removeItem(BILLING_ACTIVATING_KEY);
        setIsActivating(false);
        refreshLicense();
        refreshBilling();
        router.refresh();
        changeView("details");
      } catch (err) {
        // License not ready yet — keep polling. Log so unexpected failures
        // (network errors, 500s) are distinguishable from expected 404s.
        console.debug("License activation poll: will retry", err);
      } finally {
        requestInFlight = false;
      }
    }, 15_000);

    return () => clearInterval(intervalId);
  }, [isActivating]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRefresh = async () => {
    await Promise.all([
      onlineBillingEnabled ? refreshBilling() : Promise.resolve(),
      isSelfHosted ? refreshLicense() : Promise.resolve(),
    ]);
  };

  // Hide license activation card when Stripe connection is restored (only if auto-opened)
  useEffect(() => {
    if (
      !hasStripeError &&
      !isAirGapped &&
      showLicenseActivationInput &&
      licenseCardAutoOpened &&
      !isLoading
    ) {
      if (billingData && hasActiveSubscription(billingData)) {
        setLicenseCardAutoOpened(false);
        setShowLicenseActivationInput(false);
      }
    }
  }, [
    hasStripeError,
    isAirGapped,
    showLicenseActivationInput,
    licenseCardAutoOpened,
    isLoading,
    billingData,
  ]);

  const handleLicenseActivated = () => {
    refreshLicense();
    if (onlineBillingEnabled) {
      refreshBilling();
    }
    // Refresh the page to update settings (including ee_features_enabled)
    router.refresh();
    // Navigate to billing details now that the license is active
    changeView("details");
  };

  // View configuration
  const getViewConfig = (): ViewConfig => {
    if (isLoading || view === null) {
      return {
        icon: SvgWallet,
        title: "Plans & Billing",
        showBackButton: false,
      };
    }
    switch (view) {
      case "checkout":
        return {
          icon: SvgArrowUpCircle,
          title: "Plan Checkout",
          showBackButton: false,
        };
      case "plans":
        return {
          icon: hasSubscription ? SvgWallet : SvgArrowUpCircle,
          title: hasSubscription ? "Plan Options" : "Plans & Billing",
          showBackButton: !!(
            hasSubscription ||
            (isSelfHosted && licenseData?.has_license)
          ),
        };
      case "details":
        return {
          icon: SvgWallet,
          title: "Plans & Billing",
          showBackButton: false,
        };
    }
  };

  const viewConfig = getViewConfig();

  // Handle view changes with transition
  const changeView = (newView: "plans" | "details" | "checkout") => {
    if (newView === view) return;
    if (newView === "checkout" && view === "plans") {
      setTransitionType("expand");
    } else if (newView === "plans" && view === "checkout") {
      setTransitionType("collapse");
    } else {
      setTransitionType("fade");
    }
    setViewChangeId((id) => id + 1);
    setView(newView);
  };

  const handleBack = () => {
    const hasEntitlement =
      hasSubscription || (isSelfHosted && licenseData?.has_license);
    if (view === "checkout") {
      changeView(hasEntitlement ? "details" : "plans");
    } else if (view === "plans" && hasEntitlement) {
      changeView("details");
    }
  };

  const renderContent = () => {
    if (isLoading || view === null) return null;

    const animationClass =
      transitionType === "expand"
        ? "billing-view-expand"
        : transitionType === "collapse"
          ? "billing-view-collapse"
          : "billing-view-enter";

    const views: Record<typeof view, React.ReactNode> = {
      checkout: <CheckoutView onAdjustPlan={() => changeView("plans")} />,
      plans: (
        <PlansView
          hasSubscription={!!hasSubscription}
          hasLicense={!!licenseData?.has_license}
          onCheckout={() => changeView("checkout")}
          hideFeatures={showLicenseActivationInput}
          onlineBillingEnabled={onlineBillingEnabled}
        />
      ),
      details: (
        <BillingDetailsView
          billing={billing ?? undefined}
          license={licenseData ?? undefined}
          onViewPlans={() => changeView("plans")}
          onRefresh={handleRefresh}
          isAirGapped={isAirGapped}
          isManualLicenseOnly={isManualLicenseOnly}
          hasStripeError={hasStripeError}
          licenseCard={
            isManualLicenseOnly ? (
              <LicenseActivationCard
                isOpen
                onSuccess={handleLicenseActivated}
                license={licenseData ?? undefined}
                onClose={() => {}}
                hideClose
              />
            ) : undefined
          }
        />
      ),
    };

    return (
      <div key={viewChangeId} className={`w-full ${animationClass}`}>
        {views[view]}
      </div>
    );
  };

  // Render footer
  const renderFooter = () => {
    if (isLoading || view === null) return null;
    return (
      <>
        {showLicenseActivationInput && !isManualLicenseOnly && (
          <div className="w-full billing-card-enter">
            <LicenseActivationCard
              isOpen={showLicenseActivationInput}
              onSuccess={handleLicenseActivated}
              license={licenseData ?? undefined}
              onClose={() => {
                setLicenseCardAutoOpened(false);
                setShowLicenseActivationInput(false);
              }}
            />
          </div>
        )}
        <FooterLinks
          hasSubscription={!!hasSubscription || !!licenseData?.has_license}
          onActivateLicense={
            isSelfHosted ? () => setShowLicenseActivationInput(true) : undefined
          }
          hideLicenseLink={
            isManualLicenseOnly ||
            showLicenseActivationInput ||
            (view === "plans" &&
              (!!hasSubscription || !!licenseData?.has_license))
          }
        />
      </>
    );
  };

  return (
    <SettingsLayouts.Root>
      <SettingsLayouts.Header
        icon={viewConfig.icon}
        title={viewConfig.title}
        backButton={viewConfig.showBackButton}
        onBack={handleBack}
        separator
      />
      <SettingsLayouts.Body>
        <div className="flex flex-col items-center gap-6">
          {isSelfHosted && !onlineBillingEnabled && (
            <Message
              static
              icon
              large
              text="Online billing is disabled for this deployment"
              description="This local deployment uses access keys and deployment-side provisioning. Enable NEXT_PUBLIC_SELF_HOSTED_ONLINE_BILLING_ENABLED and SELF_HOSTED_ONLINE_BILLING_ENABLED only if you intend to connect billing to an external control plane."
              className="w-full"
            />
          )}
          {operationalStateBanner && (
            <Message
              static
              icon
              large
              warning={operationalStateBanner.level === "warning"}
              error={operationalStateBanner.level === "error"}
              text={operationalStateBanner.text}
              description={operationalStateBanner.description}
              className="w-full"
            />
          )}
          {isActivating && (
            <Message
              static
              warning
              large
              text="Deployment access is still activating"
              description="Your access update is being processed. You'll be taken to billing details automatically once confirmed."
              icon
              close
              onClose={() => {
                sessionStorage.removeItem(BILLING_ACTIVATING_KEY);
                setIsActivating(false);
              }}
              className="w-full"
            />
          )}
          {renderContent()}
          {renderFooter()}
        </div>
      </SettingsLayouts.Body>
    </SettingsLayouts.Root>
  );
}
