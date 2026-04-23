import React from "react";
import { render, screen } from "@tests/setup/test-utils";

import LicenseActivationCard from "./LicenseActivationCard";

jest.mock("@/lib/billing/svc", () => ({
  uploadLicense: jest.fn(),
}));

describe("LicenseActivationCard operational state notices", () => {
  test("shows verification_failed recovery notice in activation mode", () => {
    render(
      <LicenseActivationCard
        isOpen
        onClose={jest.fn()}
        onSuccess={jest.fn()}
        license={{
          has_license: false,
          seats: 0,
          used_seats: 0,
          plan_type: null,
          issued_at: null,
          expires_at: null,
          grace_period_end: null,
          status: null,
          source: null,
          operational_state: "verification_failed",
          operational_state_reason:
            "A local key exists but signature verification failed.",
        }}
      />
    );

    expect(screen.getByText("Access key verification failed")).toBeInTheDocument();
    expect(
      screen.getByText(
        "A local key exists but signature verification failed."
      )
    ).toBeInTheDocument();
  });

  test("shows disconnected_cached notice for active key status view", () => {
    render(
      <LicenseActivationCard
        isOpen
        onClose={jest.fn()}
        onSuccess={jest.fn()}
        license={{
          has_license: true,
          seats: 20,
          used_seats: 5,
          plan_type: "annual",
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: "2027-01-01T00:00:00Z",
          grace_period_end: null,
          status: "active",
          source: "auto_fetch",
          operational_state: "disconnected_cached",
          operational_state_reason:
            "Billing connection is temporarily unavailable; using cached state.",
        }}
      />
    );

    expect(
      screen.getByText("Billing service is temporarily disconnected")
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Billing connection is temporarily unavailable; using cached state."
      )
    ).toBeInTheDocument();
  });
});
