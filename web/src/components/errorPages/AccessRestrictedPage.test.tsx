import React from "react";
import { render, screen } from "@tests/setup/test-utils";

import AccessRestrictedPage from "./AccessRestrictedPage";

jest.mock("@/components/errorPages/ErrorPageLayout", () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="error-layout">{children}</div>
  ),
}));

jest.mock("@/refresh-components/messages/Message", () => ({
  __esModule: true,
  default: ({
    text,
    description,
  }: {
    text: string;
    description?: string;
  }) => (
    <div data-testid="access-operational-message">
      <span>{text}</span>
      {description ? <span>{description}</span> : null}
    </div>
  ),
}));

jest.mock("@/hooks/useLicense", () => ({
  useLicense: jest.fn(),
}));

jest.mock("@/providers/SettingsProvider", () => ({
  useSettingsContext: jest.fn(),
}));

jest.mock("@/lib/constants", () => ({
  COMMUNITY_URL: "https://example.com/community",
  SUPPORT_EMAIL: "support@example.com",
  NEXT_PUBLIC_CLOUD_ENABLED: false,
}));

import { useLicense } from "@/hooks/useLicense";
import { useSettingsContext } from "@/providers/SettingsProvider";
import { ApplicationStatus } from "@/interfaces/settings";

describe("AccessRestrictedPage operational guidance", () => {
  beforeEach(() => {
    (useSettingsContext as jest.Mock).mockReturnValue({
      settings: {
        application_status: ApplicationStatus.GATED_ACCESS,
        used_seats: null,
        seat_count: null,
      },
    });
  });

  test("shows verification_failed recovery guidance", () => {
    (useLicense as jest.Mock).mockReturnValue({
      data: {
        has_license: true,
        operational_state: "verification_failed",
        operational_state_reason:
          "Stored access key signature verification failed.",
      },
    });

    render(<AccessRestrictedPage />);

    expect(
      screen.getByText("Deployment access key verification failed")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Stored access key signature verification failed.")
    ).toBeInTheDocument();
  });

  test("shows disconnected_cached guidance", () => {
    (useLicense as jest.Mock).mockReturnValue({
      data: {
        has_license: true,
        operational_state: "disconnected_cached",
        operational_state_reason:
          "Billing connection is unavailable; cached state is in use.",
      },
    });

    render(<AccessRestrictedPage />);

    expect(
      screen.getByText("Billing service is temporarily disconnected")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Billing connection is unavailable; cached state is in use.")
    ).toBeInTheDocument();
  });
});
