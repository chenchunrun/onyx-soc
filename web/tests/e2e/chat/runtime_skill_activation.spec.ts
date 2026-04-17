import { expect, test, type APIRequestContext, type Browser } from "@playwright/test";
import { loginAs } from "@tests/e2e/utils/auth";

const TEMP_AGENT_NAME = "E2E Runtime Skill Activation Agent";
const TEST_SKILL_KEY = "asset-discovery";
const CONFLICTING_SKILL_KEY = "conflicting-runtime-skill";
const TEST_TARGET = "example.com";
const TEST_APPROVAL = "CHG-1001";

type CapturedChatPayload = {
  message?: string;
  active_skill_keys?: string[];
  skill_targets?: string[];
  skill_approval_reference?: string | null;
  [key: string]: unknown;
};

async function exportSkillsRegistry(request: APIRequestContext): Promise<string> {
  const response = await request.get("/api/manage/admin/skills/export");
  expect(response.ok()).toBeTruthy();
  return await response.text();
}

async function exportAuthorizedTargets(request: APIRequestContext): Promise<string> {
  const response = await request.get(
    "/api/manage/admin/skills/scan-policy/targets/export"
  );
  expect(response.ok()).toBeTruthy();
  return await response.text();
}

async function restoreSkillsRegistry(
  request: APIRequestContext,
  yamlContent: string
): Promise<void> {
  const response = await request.post("/api/manage/admin/skills/import", {
    data: {
      yaml_content: yamlContent,
      mode: "replace",
    },
  });
  expect(response.ok()).toBeTruthy();
}

async function restoreAuthorizedTargets(
  request: APIRequestContext,
  yamlContent: string
): Promise<void> {
  const response = await request.post(
    "/api/manage/admin/skills/scan-policy/targets/import",
    {
      data: {
        yaml_content: yamlContent,
        mode: "replace",
      },
    }
  );
  expect(response.ok()).toBeTruthy();
}

async function configureRestrictedSkillFixture(
  request: APIRequestContext
): Promise<void> {
  const updateResponse = await request.put(
    `/api/manage/admin/skills/${TEST_SKILL_KEY}`,
    {
      data: {
        enabled: true,
        access_scope: "admin_only",
        execution_scope: "authorized_scan",
        requires_approval: true,
        requires_network_gateway: true,
        allowed_target_types: ["domain"],
        notes: "E2E temporary runtime skill activation fixture",
      },
    }
  );
  expect(updateResponse.ok()).toBeTruthy();

  const targetsResponse = await request.post(
    "/api/manage/admin/skills/scan-policy/targets/import",
    {
      data: {
        mode: "merge",
        yaml_content: `targets:\n  - target: ${TEST_TARGET}\n    target_type: domain\n    owner: e2e-suite\n    approval_reference: ${TEST_APPROVAL}\n    enabled: true\n    notes: Runtime skill activation fixture\n`,
      },
    }
  );
  expect(targetsResponse.ok()).toBeTruthy();
}

async function createRuntimeSkillAgent(
  request: APIRequestContext
): Promise<number> {
  const response = await request.post("/api/persona", {
    data: {
      name: TEMP_AGENT_NAME,
      description: "Agent used to verify runtime skill activation payloads.",
      document_set_ids: [],
      is_public: false,
      users: [],
      groups: [],
      tool_ids: [],
      remove_image: false,
      uploaded_image_id: null,
      icon_name: null,
      search_start_date: null,
      label_ids: [],
      is_featured: false,
      display_priority: null,
      user_file_ids: [],
      hierarchy_node_ids: [],
      document_ids: [],
      system_prompt: "",
      replace_base_system_prompt: false,
      task_prompt: "",
      datetime_aware: false,
      starter_messages: null,
      skill_keys: [TEST_SKILL_KEY],
      prompt_preset_id: null,
    },
  });
  expect(response.ok()).toBeTruthy();
  const data = await response.json();
  return data.id;
}

async function deleteAgentIfExists(
  request: APIRequestContext,
  agentId: number | null
): Promise<void> {
  if (!agentId) {
    return;
  }
  await request.delete(`/api/persona/${agentId}`);
}

test.describe("Runtime Skill Activation", () => {
  test.describe.configure({ mode: "serial" });

  let originalSkillsYaml = "";
  let originalTargetsYaml = "";
  let agentId: number | null = null;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await loginAs(page, "admin2");
      originalSkillsYaml = await exportSkillsRegistry(page.request);
      originalTargetsYaml = await exportAuthorizedTargets(page.request);
      await configureRestrictedSkillFixture(page.request);
      agentId = await createRuntimeSkillAgent(page.request);
    } finally {
      await context.close();
    }
  });

  test.afterAll(async ({ browser }: { browser: Browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await loginAs(page, "admin2");
      await deleteAgentIfExists(page.request, agentId);
      if (originalTargetsYaml) {
        await restoreAuthorizedTargets(page.request, originalTargetsYaml);
      }
      if (originalSkillsYaml) {
        await restoreSkillsRegistry(page.request, originalSkillsYaml);
      }
    } finally {
      await context.close();
    }
  });

  test("sends active runtime skills and policy inputs with the chat request @exclusive", async ({
    page,
  }) => {
    test.skip(!agentId, "Runtime skill agent fixture was not created");

    await loginAs(page, "admin2");

    let capturedPayload: CapturedChatPayload | null = null;
    await page.route("**/api/persona/*/runtime-profile", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({
        status: response.status(),
        headers: response.headers(),
        contentType: "application/json",
        body: JSON.stringify({
          ...payload,
          authorized_target_suggestions: [
            {
              target: TEST_TARGET,
              target_type: "domain",
              owner: "e2e-suite",
              approval_reference: TEST_APPROVAL,
              notes: "Runtime skill activation fixture",
            },
          ],
          approval_reference_suggestions: [TEST_APPROVAL],
        }),
      });
    });
    await page.route("**/api/chat/send-chat-message", async (route) => {
      capturedPayload = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body:
          [
            JSON.stringify({
              type: "message_start",
              id: "runtime-skill-e2e",
              content: "",
              final_documents: null,
            }),
            JSON.stringify({
              type: "message_delta",
              content: "Runtime skill activation verified.",
            }),
            JSON.stringify({ type: "message_end" }),
            JSON.stringify({ type: "stop", stop_reason: "finished" }),
          ].join("\n") + "\n",
      });
    });

    await page.goto(`/app?agentId=${agentId}`);
    await page.waitForLoadState("networkidle");

    await expect(
      page.getByText("Runtime Skill Activation", { exact: true })
    ).toBeVisible();
    await expect(page.getByText(TEST_SKILL_KEY, { exact: true })).toBeVisible();

    const skillCheckbox = page.getByLabel(
      `Activate runtime skill ${TEST_SKILL_KEY}`
    );
    await expect(skillCheckbox).toBeEnabled();
    await skillCheckbox.evaluate((element) => {
      (element as HTMLElement).click();
    });
    await expect(skillCheckbox).toHaveAttribute("aria-checked", "true");

    await expect(
      page.getByText("Authorized Targets", { exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Approval Reference", { exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Allowed target types: domain", { exact: true })
    ).toBeVisible();
    await expect(
      page.getByText(
        "Only domain targets are allowed here. Example: example.com",
        { exact: true }
      )
    ).toBeVisible();

    await expect(
      page.getByPlaceholder("Search authorized targets, owners, or approval refs")
    ).toBeVisible();
    await expect(page.getByText("domain (1)", { exact: true })).toBeVisible();

    const targetSearchInput = page.getByPlaceholder(
      "Search authorized targets, owners, or approval refs"
    );
    await targetSearchInput.fill("example");
    const targetSuggestion = page.getByText(TEST_TARGET, { exact: true });
    await expect(targetSuggestion).toBeVisible();
    await targetSuggestion.evaluate((element) => {
      (element as HTMLElement).click();
    });
    await expect(
      page.getByText("Selected authorized targets", { exact: true })
    ).toBeVisible();
    await expect(
      page.getByPlaceholder("One target per line, for example: example.com")
    ).toHaveValue(TEST_TARGET);

    const approvalInput = page.getByPlaceholder("For example: CHG-1001");
    await expect(approvalInput).toHaveValue(TEST_APPROVAL);
    await expect(
      page.getByText("Approval references for selected targets")
    ).toBeVisible();
    await expect(
      page.getByText(`Selected targets are linked to these approvals:`)
    ).toBeVisible();

    const chatInput = page.locator("#onyx-chat-input-textarea");
    await chatInput.evaluate(
      (element, value) => {
        const input = element as HTMLTextAreaElement;
        const descriptor = Object.getOwnPropertyDescriptor(
          window.HTMLTextAreaElement.prototype,
          "value"
        );
        descriptor?.set?.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      },
      "Run the approved scan."
    );
    await page.evaluate(
      () =>
        new Promise<void>((resolve) => {
          window.requestAnimationFrame(() => resolve());
        })
    );
    await page.locator("#onyx-chat-input-send-button").evaluate((element) => {
      (element as HTMLElement).click();
    });

    await expect
      .poll(() => capturedPayload, { timeout: 10000 })
      .not.toBeNull();

    if (!capturedPayload) {
      throw new Error("Expected chat request payload to be captured");
    }
    const payload: CapturedChatPayload = capturedPayload;

    expect(payload).toMatchObject({
      active_skill_keys: [TEST_SKILL_KEY],
      skill_targets: [TEST_TARGET],
      skill_approval_reference: TEST_APPROVAL,
    });
    expect(payload.message).toBe("Run the approved scan.");
  });

  test("blocks conflicting runtime skill combinations before sending @exclusive", async ({
    page,
  }) => {
    test.skip(!agentId, "Runtime skill agent fixture was not created");

    await loginAs(page, "admin2");

    let capturedPayload: CapturedChatPayload | null = null;
    await page.route("**/api/persona/*/runtime-profile", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({
        status: response.status(),
        headers: response.headers(),
        contentType: "application/json",
        body: JSON.stringify({
          ...payload,
          bound_skills: [
            ...payload.bound_skills,
            {
              key: CONFLICTING_SKILL_KEY,
              name: CONFLICTING_SKILL_KEY,
              description: "Conflicting execution policy fixture",
              risk_level: "high",
              access_scope: "admin_only",
              execution_scope: "manual_review",
              requires_approval: true,
              gateway_required: false,
              allowed_target_types: ["url"],
              notes: "Conflict fixture",
              enabled: true,
              accessible: true,
            },
          ],
          activation_required_skill_keys: [
            ...(payload.activation_required_skill_keys ?? []),
            CONFLICTING_SKILL_KEY,
          ],
          blocked_skill_reasons: payload.blocked_skill_reasons ?? {},
          authorized_target_suggestions: [
            {
              target: TEST_TARGET,
              target_type: "domain",
              owner: "e2e-suite",
              approval_reference: TEST_APPROVAL,
              notes: "Runtime skill activation fixture",
            },
          ],
          approval_reference_suggestions: [TEST_APPROVAL],
        }),
      });
    });
    await page.route("**/api/chat/send-chat-message", async (route) => {
      capturedPayload = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: "",
      });
    });

    await page.goto(`/app?agentId=${agentId}`);
    await page.waitForLoadState("networkidle");

    const primarySkillCheckbox = page.getByLabel(
      `Activate runtime skill ${TEST_SKILL_KEY}`
    );
    const conflictingSkillCheckbox = page.getByLabel(
      `Activate runtime skill ${CONFLICTING_SKILL_KEY}`
    );
    await primarySkillCheckbox.evaluate((element) => {
      (element as HTMLElement).click();
    });
    await conflictingSkillCheckbox.evaluate((element) => {
      (element as HTMLElement).click();
    });

    const chatInput = page.locator("#onyx-chat-input-textarea");
    await chatInput.evaluate(
      (element, value) => {
        const input = element as HTMLTextAreaElement;
        const descriptor = Object.getOwnPropertyDescriptor(
          window.HTMLTextAreaElement.prototype,
          "value"
        );
        descriptor?.set?.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      },
      "Try the conflicting runtime skills."
    );
    await page.locator("#onyx-chat-input-send-button").evaluate((element) => {
      (element as HTMLElement).click();
    });

    await expect(
      page.getByText(
        "Selected runtime skills use different execution scopes and cannot be activated together."
      )
    ).toBeVisible();
    await page.waitForTimeout(1000);
    expect(capturedPayload).toBeNull();
  });

  test("shows inline guidance for incompatible manual target input @exclusive", async ({
    page,
  }) => {
    test.skip(!agentId, "Runtime skill agent fixture was not created");

    await loginAs(page, "admin2");

    await page.route("**/api/persona/*/runtime-profile", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({
        status: response.status(),
        headers: response.headers(),
        contentType: "application/json",
        body: JSON.stringify({
          ...payload,
          authorized_target_suggestions: [
            {
              target: TEST_TARGET,
              target_type: "domain",
              owner: "e2e-suite",
              approval_reference: TEST_APPROVAL,
              notes: "Runtime skill activation fixture",
            },
          ],
          approval_reference_suggestions: [TEST_APPROVAL],
        }),
      });
    });

    await page.goto(`/app?agentId=${agentId}`);
    await page.waitForLoadState("networkidle");

    const skillCheckbox = page.getByLabel(
      `Activate runtime skill ${TEST_SKILL_KEY}`
    );
    await skillCheckbox.evaluate((element) => {
      (element as HTMLElement).click();
    });

    const targetsInput = page.getByPlaceholder(
      "One target per line, for example: example.com"
    );
    await targetsInput.evaluate(
      (element, value) => {
        const input = element as HTMLTextAreaElement;
        const descriptor = Object.getOwnPropertyDescriptor(
          window.HTMLTextAreaElement.prototype,
          "value"
        );
        descriptor?.set?.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      },
      "https://example.com"
    );

    await expect(
      page.getByText(
        "https://example.com -> url (not allowed for domain; try example.com)"
      )
    ).toBeVisible();
  });
});
