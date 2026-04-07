"use client";

import * as SettingsLayouts from "@/layouts/settings-layouts";
import { ADMIN_ROUTES } from "@/lib/admin-routes";
import { Card } from "@/components/ui/card";
import { ThreeDotsLoader } from "@/components/Loading";
import { Text } from "@opal/components";
import useSWR from "swr";
import { errorHandlingFetcher } from "@/lib/fetcher";

const route = ADMIN_ROUTES.SECURITY_PLATFORM;

interface SecurityPlatformRuntimeStatus {
  deployment_profile: string;
  expected_profiles: {
    threat_intel_source_profile: string;
    security_tools_profile: string;
  };
  required_env: string[];
  missing_required_env: string[];
  deployment_profile_issues: string[];
  threat_intel_source_profile: string;
  security_tools_profile: string;
  threat_intel_sync: {
    source_profile: string;
    last_sync_run_at: string | null;
    due_status: string;
    due_feeds: string[];
  };
  threat_intel_corpus: {
    governed: number;
    unmanaged: number;
    promotion_candidates: number;
    manual_review: number;
    keep_runtime_only: number;
  };
  playbooks: {
    count: number;
    with_examples: number;
    items: {
      name: string;
      display_name: string;
      has_example_inputs: boolean;
      step_count: number;
    }[];
  };
  health: {
    overall_status: string;
    failing_checks: number;
    warning_checks: number;
    checks: {
      name: string;
      status: string;
      summary: string;
      issues: string[];
      remediations: string[];
    }[];
  };
  recommended_next_actions: string[];
  remediation_commands: string[];
  document_set: {
    id: number | null;
    name: string;
    exists: boolean;
    is_public: boolean | null;
    shared_user_count: number;
  };
  personas: {
    id: number;
    name: string;
    is_public: boolean;
    tool_count: number;
    document_set_count: number;
    shared_user_count: number;
  }[];
  tools: {
    id: number;
    name: string;
    enabled: boolean;
    server_url: string | null;
    header_keys: string[];
    persona_names: string[];
  }[];
  security_users: {
    email: string;
    role: string;
    is_active: boolean;
  }[];
  rbac: {
    persona_user_links: number;
    document_set_user_links: number;
  };
}

function getHealthTone(status: string) {
  if (status === "failing") {
    return "border-red-200 bg-red-50 text-red-700";
  }
  if (status === "warning") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function HealthBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${getHealthTone(
        status
      )}`}
    >
      {status}
    </span>
  );
}

function SummaryCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="p-5">
      <div className="mb-3">
        <div className="text-sm font-medium text-muted-foreground">{title}</div>
      </div>
      {children}
    </Card>
  );
}

function ToolEndpoint({
  tool,
}: {
  tool: SecurityPlatformRuntimeStatus["tools"][number];
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">{tool.name}</div>
      <div className="mt-1 text-sm text-muted-foreground">
        {tool.server_url || "No server configured"}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        headers: {tool.header_keys.length > 0 ? tool.header_keys.join(", ") : "none"}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        personas: {tool.persona_names.length > 0 ? tool.persona_names.join(", ") : "none"}
      </div>
    </div>
  );
}

function Main() {
  const {
    data: runtimeData,
    isLoading: runtimeLoading,
    error: runtimeError,
  } = useSWR<SecurityPlatformRuntimeStatus>(
    "/api/manage/admin/security-platform/status",
    errorHandlingFetcher
  );
  if (runtimeLoading) {
    return <ThreeDotsLoader />;
  }

  if (runtimeError || !runtimeData) {
    return <Text>Failed to load security platform status.</Text>;
  }

  return (
    <div className="space-y-6">
      <Card className="p-5">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-sm font-medium text-muted-foreground">
              Platform Health
            </div>
            <div className="mt-2 flex items-center gap-3">
              <div className="text-2xl font-semibold">
                {runtimeData.health.overall_status}
              </div>
              <HealthBadge status={runtimeData.health.overall_status} />
            </div>
            <div className="mt-2 text-sm text-muted-foreground">
              failing={runtimeData.health.failing_checks} / warning=
              {runtimeData.health.warning_checks}
            </div>
          </div>

          <div className="grid gap-2 text-sm text-muted-foreground xl:min-w-[340px]">
            <div>
              expected profiles: tools=
              {runtimeData.expected_profiles.security_tools_profile} / threat-intel=
              {runtimeData.expected_profiles.threat_intel_source_profile}
            </div>
            <div>
              runtime profiles: tools={runtimeData.security_tools_profile} /
              threat-intel={runtimeData.threat_intel_source_profile}
            </div>
          </div>
        </div>

        <div className="mt-5 rounded-md border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium">Recommended Next Actions</div>
          <div className="mt-3 space-y-2 text-sm text-muted-foreground">
            {runtimeData.recommended_next_actions.length > 0 ? (
              runtimeData.recommended_next_actions.map((action) => (
                <div key={action}>{action}</div>
              ))
            ) : (
              <div>No immediate action required.</div>
            )}
          </div>
        </div>

        <div className="mt-5 rounded-md border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium">Remediation Commands</div>
          <div className="mt-3 space-y-2">
            {runtimeData.remediation_commands.length > 0 ? (
              runtimeData.remediation_commands.map((command) => (
                <pre
                  key={command}
                  className="overflow-x-auto rounded-md border bg-background p-3 text-xs text-foreground"
                >
                  <code>{command}</code>
                </pre>
              ))
            ) : (
              <div className="text-sm text-muted-foreground">
                No remediation commands required.
              </div>
            )}
          </div>
        </div>

        <div className="mt-5 grid gap-3 xl:grid-cols-2">
          {runtimeData.health.checks.map((check) => (
            <div key={check.name} className="rounded-md border p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="font-medium">{check.name}</div>
                <HealthBadge status={check.status} />
              </div>
              <div className="mt-2 text-sm text-muted-foreground">
                {check.summary}
              </div>
              <div className="mt-3 space-y-2 text-sm">
                <div>
                  issues:{" "}
                  {check.issues.length > 0 ? check.issues.join(" | ") : "none"}
                </div>
                <div className="text-muted-foreground">
                  remediation:{" "}
                  {check.remediations.length > 0
                    ? check.remediations.join(" | ")
                    : "none"}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard title="Deployment Profile">
          <div className="text-2xl font-semibold">
            {runtimeData.deployment_profile}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            tools={runtimeData.security_tools_profile || "n/a"} / threat-intel=
            {runtimeData.threat_intel_source_profile || "n/a"}
          </div>
        </SummaryCard>

        <SummaryCard title="Threat-Intel Sync">
          <div className="text-2xl font-semibold">
            {runtimeData.threat_intel_sync.due_status}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            profile={runtimeData.threat_intel_sync.source_profile}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            last run: {runtimeData.threat_intel_sync.last_sync_run_at || "never"}
          </div>
        </SummaryCard>

        <SummaryCard title="Threat-Intel Corpus">
          <div className="text-2xl font-semibold">
            {runtimeData.threat_intel_corpus.governed}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            unmanaged={runtimeData.threat_intel_corpus.unmanaged} / promotion=
            {runtimeData.threat_intel_corpus.promotion_candidates}
          </div>
        </SummaryCard>

        <SummaryCard title="Playbooks / RBAC">
          <div className="text-2xl font-semibold">{runtimeData.playbooks.count}</div>
          <div className="mt-2 text-sm text-muted-foreground">
            with examples={runtimeData.playbooks.with_examples}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            persona links={runtimeData.rbac.persona_user_links} / docset links=
            {runtimeData.rbac.document_set_user_links}
          </div>
        </SummaryCard>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <SummaryCard title="Security Personas">
          <div className="space-y-3">
            {runtimeData.personas.map((persona) => (
              <div key={persona.id} className="rounded-md border p-3">
                <div className="font-medium">{persona.name}</div>
                <div className="mt-1 text-sm text-muted-foreground">
                  tools={persona.tool_count} / document sets=
                  {persona.document_set_count}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  private={persona.is_public ? "no" : "yes"} / shared users=
                  {persona.shared_user_count}
                </div>
              </div>
            ))}
          </div>
        </SummaryCard>

        <SummaryCard title="Security Tools">
          <div className="space-y-3">
            {runtimeData.tools.map((tool) => (
              <ToolEndpoint key={tool.id} tool={tool} />
            ))}
          </div>
        </SummaryCard>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <SummaryCard title="Playbook Catalog">
          <div className="space-y-3">
            {runtimeData.playbooks.items.map((playbook) => (
              <div key={playbook.name} className="rounded-md border p-3">
                <div className="font-medium">{playbook.display_name}</div>
                <div className="mt-1 text-sm text-muted-foreground">
                  {playbook.name}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  steps={playbook.step_count} / example inputs=
                  {playbook.has_example_inputs ? "yes" : "no"}
                </div>
              </div>
            ))}
          </div>
        </SummaryCard>

        <SummaryCard title="Operational Checks">
          <div className="space-y-2 text-sm text-muted-foreground">
            <div>
              document set: {runtimeData.document_set.exists
                ? `${runtimeData.document_set.name} (#${runtimeData.document_set.id})`
                : "missing"}
            </div>
            <div>security users: {runtimeData.security_users.length}</div>
            <div>
              required env: {runtimeData.required_env.length > 0
                ? runtimeData.required_env.join(", ")
                : "none"}
            </div>
            <div>
              missing env: {runtimeData.missing_required_env.length > 0
                ? runtimeData.missing_required_env.join(", ")
                : "none"}
            </div>
            <div>
              due feeds: {runtimeData.threat_intel_sync.due_feeds.length > 0
                ? runtimeData.threat_intel_sync.due_feeds.join(", ")
                : "none"}
            </div>
            <div>
              deployment issues: {runtimeData.deployment_profile_issues.length > 0
                ? runtimeData.deployment_profile_issues.join(" | ")
                : "none"}
            </div>
            <div>
              runtime-only corpus: {runtimeData.threat_intel_corpus.keep_runtime_only}
            </div>
            <div>manual review: {runtimeData.threat_intel_corpus.manual_review}</div>
          </div>
        </SummaryCard>
      </div>
    </div>
  );
}

export default function SecurityPlatformPage() {
  return (
    <SettingsLayouts.Root width="full">
      <SettingsLayouts.Header
        icon={route.icon}
        title={route.title}
        description="Security-specific operational status, personas, tools, threat-intel, and playbook coverage."
        separator
      />
      <SettingsLayouts.Body>
        <Main />
      </SettingsLayouts.Body>
    </SettingsLayouts.Root>
  );
}
