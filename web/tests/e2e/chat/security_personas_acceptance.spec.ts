import { expect, test, type Page } from "@playwright/test";
import { loginAs } from "@tests/e2e/utils/auth";
import { sendMessage, verifyAgentIsChosen } from "@tests/e2e/utils/chatActions";

type ExpectedPersona = {
  name: string;
  promptPresetId: string;
  skillKeys: string[];
  requiresActivationPanel?: boolean;
};

type PersonaSummary = {
  id: number;
  name: string;
  skill_keys?: string[];
  prompt_preset_id?: string | null;
};

type RuntimeProfile = {
  persona_name: string;
  prompt_preset?: {
    id: string;
    name: string;
  } | null;
  bound_skills: {
    key: string;
    name: string;
  }[];
  activation_required_skill_keys: string[];
};

const SECURITY_PERSONAS: ExpectedPersona[] = [
  {
    name: "安全事件分析师",
    promptPresetId: "report_mode",
    skillKeys: ["auth-log-analysis", "email-osint", "url-analysis"],
  },
  {
    name: "应急响应指挥官",
    promptPresetId: "intrusion_report_mode",
    skillKeys: ["asset-monitor", "ttp-extractor"],
  },
  {
    name: "漏洞评估专家",
    promptPresetId: "deep_analysis_mode",
    skillKeys: ["asset-discovery", "researching-vulnerabilities", "sca-analyzer"],
    requiresActivationPanel: true,
  },
  {
    name: "合规审计员",
    promptPresetId: "report_mode",
    skillKeys: ["data-desensitize", "rga-knowledge-search"],
  },
  {
    name: "威胁狩猎工程师",
    promptPresetId: "intrusion_deep_analysis_mode",
    skillKeys: ["asset-monitor", "dns-cache-detection", "ttp-extractor"],
  },
  {
    name: "恶意软件分析师",
    promptPresetId: "deep_analysis_mode",
    skillKeys: ["binary-reverse-engineering", "office-malware-analyzer", "pdf-analysis"],
  },
  {
    name: "检测工程师",
    promptPresetId: "deep_analysis_mode",
    skillKeys: ["auth-log-analysis", "prompt-injection-detect", "ttp-extractor"],
  },
];

function formatBindingLabel(value: string): string {
  return value
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

async function fetchSecurityPersonas(
  page: Page
): Promise<Map<string, PersonaSummary>> {
  const response = await page.request.get(
    "/api/admin/persona?include_deleted=false&get_editable=false"
  );
  expect(response.ok()).toBeTruthy();
  const personas = (await response.json()) as PersonaSummary[];
  return new Map(personas.map((persona) => [persona.name, persona]));
}

async function fetchRuntimeProfile(
  page: Page,
  personaId: number
): Promise<RuntimeProfile> {
  const response = await page.request.get(
    `/api/persona/${personaId}/runtime-profile`
  );
  expect(response.ok()).toBeTruthy();
  return (await response.json()) as RuntimeProfile;
}

async function ensureDisplayNameConfigured(page: Page): Promise<void> {
  const response = await page.request.patch("/api/user/personalization", {
    data: { name: "admin2" },
  });
  expect(response.ok()).toBeTruthy();
}

async function dismissWelcomeModalIfPresent(page: Page): Promise<void> {
  const startButton = page.getByRole("button", { name: "Start" });
  if (!(await startButton.isVisible().catch(() => false))) {
    return;
  }
  await startButton.click();
  await expect(startButton).toBeHidden();
}

test.describe("Security Personas Acceptance", () => {
  test.describe.configure({ mode: "serial" });

  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await loginAs(page, "admin2");
    await ensureDisplayNameConfigured(page);
  });

  test("formal security personas are present in admin data, chat UI, and runtime profile", async ({
    page,
  }) => {
    const personasByName = await fetchSecurityPersonas(page);

    for (const expectedPersona of SECURITY_PERSONAS) {
      const persona = personasByName.get(expectedPersona.name);
      expect(persona, `Missing persona ${expectedPersona.name}`).toBeTruthy();
      expect((persona?.skill_keys ?? []).sort()).toEqual(
        [...expectedPersona.skillKeys].sort()
      );
      expect(persona?.prompt_preset_id ?? null).toBe(
        expectedPersona.promptPresetId
      );

      const runtimeProfile = await fetchRuntimeProfile(page, persona!.id);
      expect(runtimeProfile.persona_name).toBe(expectedPersona.name);
      expect(runtimeProfile.prompt_preset?.id ?? null).toBe(
        expectedPersona.promptPresetId
      );
      expect(
        runtimeProfile.bound_skills.map((skill) => skill.key).sort()
      ).toEqual([...expectedPersona.skillKeys].sort());

      await page.goto(`/app?agentId=${persona!.id}`);
      await page.waitForLoadState("networkidle");
      await dismissWelcomeModalIfPresent(page);
      await verifyAgentIsChosen(page, expectedPersona.name, 10000);

      await expect(
        page
          .getByText(
            `Prompt: ${formatBindingLabel(expectedPersona.promptPresetId)}`,
            { exact: true }
          )
          .first()
      ).toBeVisible();

      for (const skillKey of expectedPersona.skillKeys.slice(0, 3)) {
        await expect(
          page
            .getByText(`Skill: ${formatBindingLabel(skillKey)}`, {
              exact: true,
            })
            .first()
        ).toBeVisible();
      }

      const runtimeProfileButton = page
        .getByText("View Runtime Profile", { exact: true })
        .first();
      await expect(runtimeProfileButton).toBeVisible();
      await runtimeProfileButton.evaluate((element) => {
        (element as HTMLElement).click();
      });

      await expect(page.getByText("Runtime Profile", { exact: true })).toBeVisible();
      await expect(
        page.getByText("Bound Skills", { exact: true })
      ).toBeVisible();
      await expect(page.getByText("Policy", { exact: true })).toBeVisible();

      for (const skill of runtimeProfile.bound_skills) {
        await expect(
          page.getByText(skill.name, { exact: true }).first()
        ).toBeVisible();
      }

      if (expectedPersona.requiresActivationPanel) {
        await page.keyboard.press("Escape");
        await expect(
          page.getByText("Runtime Profile", { exact: true })
        ).toBeHidden();
        await expect(
          page.getByText("Runtime Skill Activation", { exact: true })
        ).toBeVisible();
      } else {
        await page.keyboard.press("Escape");
        await expect(
          page.getByText("Runtime Profile", { exact: true })
        ).toBeHidden();
      }
    }
  });

  test("security incident analyst can complete a real chat round trip", async ({
    page,
  }) => {
    const personasByName = await fetchSecurityPersonas(page);
    const analystPersona = personasByName.get("安全事件分析师");
    expect(analystPersona).toBeTruthy();

    await page.goto(`/app?agentId=${analystPersona!.id}`);
    await page.waitForLoadState("networkidle");
    await dismissWelcomeModalIfPresent(page);
    await verifyAgentIsChosen(page, "安全事件分析师", 10000);

    await sendMessage(page, "请用一句中文说明你的职责。");

    const aiMessages = page.locator('[data-testid="onyx-ai-message"]');
    await expect(aiMessages).toHaveCount(1, { timeout: 30000 });
    await expect(aiMessages.first()).not.toHaveText("", { timeout: 30000 });
  });
});
