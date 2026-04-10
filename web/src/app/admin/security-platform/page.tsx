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
  placeholder_required_env: string[];
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
  historical_packages: {
    package_count: number;
    total_item_count: number;
    total_size_bytes: number;
    package_ids: string[];
    packages: {
      batch_id: string;
      description: string;
      item_count: number;
      total_size_bytes: number;
      manifest_path: string;
      readme_path: string;
      recommended_action: string;
      source_counts: Record<string, number>;
      quality_counts: Record<string, number>;
      year_counts: Record<string, number>;
    }[];
    consistency: {
      ok: boolean;
      summary: {
        package_count: number;
        consistent_package_count: number;
        issue_count: number;
      };
      issues: string[];
      package_checks: {
        batch_id: string;
        ok: boolean;
        issue_count: number;
        issues: string[];
      }[];
    };
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
  tool_audit: {
    total_calls: number;
    recent_call_count: number;
    tool_counts: Record<string, number>;
    persona_counts: Record<string, number>;
    recent_calls: {
      tool_name: string;
      persona_name: string | null;
      user_email: string | null;
      time_sent: string | null;
      turn_number: number;
      is_nested: boolean;
    }[];
  };
  tool_drift: {
    mismatch_count: number;
    missing_declared_configs: string[];
    mismatched_tools: {
      tool_name: string;
      declared_persona_names: string[];
      actual_persona_names: string[];
      expected_server_url: string | null;
      actual_server_url: string | null;
      expected_header_keys: string[];
      actual_header_keys: string[];
      issues: string[];
    }[];
  };
  failure_summary: {
    total_failures: number;
    recent_failure_count: number;
    stage_counts: {
      label: string;
      count: number;
    }[];
    persona_counts: {
      label: string;
      count: number;
    }[];
    tool_counts: {
      label: string;
      count: number;
    }[];
    daily_counts: {
      day: string;
      count: number;
    }[];
    remediation_hints: string[];
    recent_failures: {
      persona_name: string | null;
      user_email: string | null;
      time_sent: string | null;
      stage: string;
      tool_name: string | null;
      error: string;
    }[];
  };
  permission_inheritance: {
    sync_cc_pair_count: number;
    docs_with_external_acl_count: number;
    docs_with_user_acl_count: number;
    docs_with_group_acl_count: number;
    recent_doc_sync_failure_count: number;
    recent_group_sync_failure_count: number;
    recent_doc_sync_attempts: {
      attempt_id: number;
      sync_type: string;
      cc_pair_id: number | null;
      status: string;
      error_message: string | null;
      time_created: string | null;
      time_finished: string | null;
    }[];
    recent_group_sync_attempts: {
      attempt_id: number;
      sync_type: string;
      cc_pair_id: number | null;
      status: string;
      error_message: string | null;
      time_created: string | null;
      time_finished: string | null;
    }[];
  };
  service_accounts: {
    api_key_count: number;
    service_account_user_count: number;
    ownerless_api_key_count: number;
    role_counts: Record<string, number>;
    recent_accounts: {
      api_key_id: number;
      api_key_name: string | null;
      api_key_display: string;
      role: string;
      owner_email: string | null;
      created_at: string | null;
    }[];
  };
  scim: {
    active_token_count: number;
    has_active_token: boolean;
    token_last_used_at: string | null;
    user_mapping_count: number;
    group_mapping_count: number;
    recent_group_sync_failure_count: number;
  };
  query_history_usage: {
    query_history_type: string;
    query_history_enabled: boolean;
    recent_query_count: number;
    recent_chat_session_count: number;
    recent_active_user_count: number;
    recent_like_count: number;
    recent_dislike_count: number;
    recent_export_count: number;
    recent_export_failure_count: number;
    recent_exports: {
      task_id: string;
      status: string;
      start_time: string | null;
    }[];
  };
  persona_usage: {
    recent_active_persona_count: number;
    recent_session_count: number;
    recent_message_count: number;
    recent_tool_call_count: number;
    persona_entries: {
      persona_id: number;
      persona_name: string;
      recent_session_count: number;
      recent_message_count: number;
      recent_tool_call_count: number;
      last_activity_at: string | null;
    }[];
  };
  custom_permissions: {
    default_group_count: number;
    custom_group_count: number;
    stale_custom_group_count: number;
    groups_with_custom_grants_count: number;
    custom_permission_count: number;
    manual_grant_count: number;
    scim_grant_count: number;
    admin_override_group_count: number;
    permission_counts: Record<string, number>;
  };
  usage_limits: {
    enabled: boolean;
    global_limit_count: number;
    enabled_global_limit_count: number;
    user_limit_count: number;
    enabled_user_limit_count: number;
    user_group_limit_count: number;
    enabled_user_group_limit_count: number;
    limited_user_group_count: number;
  };
  hooks: {
    hooks_enabled: boolean;
    supported_hook_point_count: number;
    configured_hook_count: number;
    active_hook_count: number;
    reachable_hook_count: number;
    recent_execution_count: number;
    recent_failure_count: number;
    hook_point_names: string[];
    recent_executions: {
      hook_name: string;
      hook_point: string;
      is_success: boolean;
      status_code: number | null;
      error_message: string | null;
      created_at: string | null;
    }[];
  };
  custom_theming: {
    branding_configured: boolean;
    application_name: string;
    application_name_is_default: boolean;
    use_custom_logo: boolean;
    use_custom_logotype: boolean;
    logo_display_style: string;
    custom_nav_item_count: number;
    custom_header_content_enabled: boolean;
    custom_lower_disclaimer_enabled: boolean;
    first_visit_notice_enabled: boolean;
    custom_popup_enabled: boolean;
    consent_screen_enabled: boolean;
    custom_greeting_enabled: boolean;
  };
  white_labeling: {
    branding_configured: boolean;
    custom_logo_enabled: boolean;
    custom_favicon_enabled: boolean;
    application_name_configured: boolean;
    white_label_ready: boolean;
    residual_branding_count: number;
    residual_external_link_count: number;
    residual_branding_examples: string[];
  };
  custom_deployments: {
    docker_compose_variant_count: number;
    helm_values_variant_count: number;
    has_install_script: boolean;
    has_multitenant_compose: boolean;
    has_lite_compose: boolean;
    has_prod_compose: boolean;
    has_security_platform_compose_overlay: boolean;
    has_security_platform_helm_overlay: boolean;
    supported_modes: string[];
    overlay_examples: string[];
  };
  region_processing: {
    aws_region_supported: boolean;
    object_store_endpoint_configurable: boolean;
    web_domain_configurable: boolean;
    tenant_aware_deployment_supported: boolean;
    cloud_deployment_supported: boolean;
    region_hint_count: number;
    region_hints: string[];
  };
  self_hosting: {
    self_hosted_mode: boolean;
    multi_tenant_mode: boolean;
    enterprise_features_enabled: boolean;
    license_enforcement_enabled: boolean;
    has_license: boolean;
    license_status: string | null;
    license_source: string | null;
    seat_count: number | null;
    used_seat_count: number | null;
    has_license_api: boolean;
    has_admin_billing_page: boolean;
    has_billing_service: boolean;
    has_cloud_proxy: boolean;
    cloud_data_plane_url_configured: boolean;
    has_install_script: boolean;
    has_docker_compose_path: boolean;
    has_helm_install_path: boolean;
  };
  security_users: {
    email: string;
    role: string;
    is_active: boolean;
  }[];
  rbac: {
    persona_user_links: number;
    document_set_user_links: number;
    all_user_role_counts: Record<string, number>;
    security_user_role_counts: Record<string, number>;
    user_group_count: number;
    groups_with_permission_grants_count: number;
    permission_grant_count: number;
    users_with_effective_permissions_count: number;
    curator_membership_count: number;
    top_permissions: Record<string, number>;
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

function SectionCard({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border border-border bg-background/60 p-4">
      <div className="text-sm font-medium text-foreground">{title}</div>
      {description ? (
        <div className="mt-1 text-xs text-muted-foreground">{description}</div>
      ) : null}
      <div className="mt-3">{children}</div>
    </div>
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

function HistoricalPackageDetail({
  item,
}: {
  item: SecurityPlatformRuntimeStatus["historical_packages"]["packages"][number];
}) {
  const sourceSummary =
    Object.entries(item.source_counts)
      .map(([name, count]) => `${name}=${count}`)
      .join(" / ") || "none";
  const qualitySummary =
    Object.entries(item.quality_counts)
      .map(([name, count]) => `${name}=${count}`)
      .join(" / ") || "none";
  const yearKeys = Object.keys(item.year_counts).sort();
  const yearRange =
    yearKeys.length > 0 ? `${yearKeys[0]}-${yearKeys[yearKeys.length - 1]}` : "n/a";

  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">{item.batch_id}</div>
      <div className="mt-1 text-sm text-muted-foreground">{item.description}</div>
      <div className="mt-2 text-xs text-muted-foreground">
        items={item.item_count} / size={item.total_size_bytes}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">sources: {sourceSummary}</div>
      <div className="mt-1 text-xs text-muted-foreground">quality: {qualitySummary}</div>
      <div className="mt-1 text-xs text-muted-foreground">years: {yearRange}</div>
      <div className="mt-2 text-xs text-muted-foreground">
        action: {item.recommended_action || "none"}
      </div>
    </div>
  );
}

function ToolAuditCall({
  item,
}: {
  item: SecurityPlatformRuntimeStatus["tool_audit"]["recent_calls"][number];
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">{item.tool_name}</div>
      <div className="mt-1 text-sm text-muted-foreground">
        persona={item.persona_name || "unknown"} / user={item.user_email || "unknown"}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        turn={item.turn_number} / nested={item.is_nested ? "yes" : "no"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        time={item.time_sent || "unknown"}
      </div>
    </div>
  );
}

function ToolDriftItem({
  item,
}: {
  item: SecurityPlatformRuntimeStatus["tool_drift"]["mismatched_tools"][number];
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">{item.tool_name}</div>
      <div className="mt-1 text-xs text-muted-foreground">
        expected personas:{" "}
        {item.declared_persona_names.length > 0
          ? item.declared_persona_names.join(", ")
          : "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        actual personas:{" "}
        {item.actual_persona_names.length > 0 ? item.actual_persona_names.join(", ") : "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        expected server: {item.expected_server_url || "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        actual server: {item.actual_server_url || "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        expected headers:{" "}
        {item.expected_header_keys.length > 0 ? item.expected_header_keys.join(", ") : "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        actual headers:{" "}
        {item.actual_header_keys.length > 0 ? item.actual_header_keys.join(", ") : "none"}
      </div>
      <div className="mt-2 text-xs text-amber-700">
        {item.issues.join(" | ")}
      </div>
    </div>
  );
}

function FailureItem({
  item,
}: {
  item: SecurityPlatformRuntimeStatus["failure_summary"]["recent_failures"][number];
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">{item.error}</div>
      <div className="mt-1 text-xs text-muted-foreground">
        persona={item.persona_name || "unknown"} / user={item.user_email || "unknown"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        stage={item.stage} / tool={item.tool_name || "none"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        time={item.time_sent || "unknown"}
      </div>
    </div>
  );
}

function PermissionSyncAttemptItem({
  item,
}: {
  item:
    | SecurityPlatformRuntimeStatus["permission_inheritance"]["recent_doc_sync_attempts"][number]
    | SecurityPlatformRuntimeStatus["permission_inheritance"]["recent_group_sync_attempts"][number];
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="font-medium">
        {item.sync_type} sync #{item.attempt_id}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        cc_pair={item.cc_pair_id ?? "unknown"} / status={item.status}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        created={item.time_created || "unknown"} / finished={item.time_finished || "unknown"}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        error={item.error_message || "none"}
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

  const failingChecks = runtimeData.health.checks.filter(
    (check) => check.status === "failing"
  );
  const warningChecks = runtimeData.health.checks.filter(
    (check) => check.status === "warning"
  );
  const healthyChecks = runtimeData.health.checks.filter(
    (check) => check.status !== "failing" && check.status !== "warning"
  );

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

        <div className="mt-5 grid gap-4 xl:grid-cols-3">
          <SectionCard
            title="Risk Items"
            description="These checks are currently failing and should be treated as immediate blockers."
          >
            <div className="space-y-3">
              {failingChecks.length > 0 ? (
                failingChecks.map((check) => (
                  <div key={check.name} className="rounded-md border p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{check.name}</div>
                      <HealthBadge status={check.status} />
                    </div>
                    <div className="mt-2 text-sm text-muted-foreground">
                      {check.summary}
                    </div>
                    <div className="mt-2 text-xs text-foreground">
                      {check.issues.length > 0 ? check.issues.join(" | ") : "none"}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">
                  No failing checks.
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Pending Configuration"
            description="These items are not blockers yet, but still need cleanup before treating the platform as production-ready."
          >
            <div className="space-y-3">
              {warningChecks.length > 0 ? (
                warningChecks.map((check) => (
                  <div key={check.name} className="rounded-md border p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{check.name}</div>
                      <HealthBadge status={check.status} />
                    </div>
                    <div className="mt-2 text-sm text-muted-foreground">
                      {check.summary}
                    </div>
                    <div className="mt-2 text-xs text-foreground">
                      {check.issues.length > 0 ? check.issues.join(" | ") : "none"}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">
                  No warning checks.
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Ready Areas"
            description="These checks are currently healthy and can be treated as ready baselines."
          >
            <div className="space-y-3">
              {healthyChecks.length > 0 ? (
                healthyChecks.map((check) => (
                  <div key={check.name} className="rounded-md border p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{check.name}</div>
                      <HealthBadge status={check.status} />
                    </div>
                    <div className="mt-2 text-sm text-muted-foreground">
                      {check.summary}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">
                  No healthy checks reported.
                </div>
              )}
            </div>
          </SectionCard>
        </div>

        <div className="mt-5 rounded-md border border-border bg-background/60 p-4">
          <div className="text-sm font-medium text-foreground">
            Recommended Next Actions
          </div>
          <div className="mt-3 space-y-2 text-sm text-foreground">
            {runtimeData.recommended_next_actions.length > 0 ? (
              runtimeData.recommended_next_actions.map((action) => (
                <div key={action}>{action}</div>
              ))
            ) : (
              <div className="text-muted-foreground">No immediate action required.</div>
            )}
          </div>
        </div>

        <div className="mt-5 rounded-md border border-border bg-background/60 p-4">
          <div className="text-sm font-medium text-foreground">
            Remediation Commands
          </div>
          <div className="mt-3 space-y-2">
            {runtimeData.remediation_commands.length > 0 ? (
              runtimeData.remediation_commands.map((command) => (
                <pre
                  key={command}
                  className="overflow-x-auto rounded-md border border-border bg-background p-3 text-xs text-foreground"
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

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
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

        <SummaryCard title="Historical Packages">
          <div className="text-2xl font-semibold">
            {runtimeData.historical_packages.package_count}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            items={runtimeData.historical_packages.total_item_count}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            size={runtimeData.historical_packages.total_size_bytes}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            consistency=
            {runtimeData.historical_packages.consistency.ok ? "ok" : "drift"}
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
          <div className="mt-1 text-xs text-muted-foreground">
            groups={runtimeData.rbac.user_group_count} / grants=
            {runtimeData.rbac.permission_grant_count}
          </div>
        </SummaryCard>

        <SummaryCard title="Tool Audit">
          <div className="text-2xl font-semibold">
            {runtimeData.tool_audit.total_calls}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            recent={runtimeData.tool_audit.recent_call_count}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            tools={Object.keys(runtimeData.tool_audit.tool_counts).length}
          </div>
        </SummaryCard>

        <SummaryCard title="Persona Activity">
          <div className="text-2xl font-semibold">
            {runtimeData.persona_usage.recent_active_persona_count}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            sessions={runtimeData.persona_usage.recent_session_count}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            messages={runtimeData.persona_usage.recent_message_count} / tool calls=
            {runtimeData.persona_usage.recent_tool_call_count}
          </div>
        </SummaryCard>

        <SummaryCard title="Config Drift">
          <div className="text-2xl font-semibold">
            {runtimeData.tool_drift.mismatch_count}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            undeclared={runtimeData.tool_drift.missing_declared_configs.length}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            mismatched tools={runtimeData.tool_drift.mismatched_tools.length}
          </div>
        </SummaryCard>

        <SummaryCard title="Recent Failures">
          <div className="text-2xl font-semibold">
            {runtimeData.failure_summary.total_failures}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            recent={runtimeData.failure_summary.recent_failure_count}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            top stage={runtimeData.failure_summary.stage_counts[0]?.label || "none"}
          </div>
        </SummaryCard>

        <SummaryCard title="Permission Inheritance">
          <div className="text-2xl font-semibold">
            {runtimeData.permission_inheritance.sync_cc_pair_count}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">
            docs with ACL={runtimeData.permission_inheritance.docs_with_external_acl_count}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            doc failures={runtimeData.permission_inheritance.recent_doc_sync_failure_count} /
            group failures={runtimeData.permission_inheritance.recent_group_sync_failure_count}
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

      <SummaryCard title="Persona Activity Detail">
        <div className="space-y-3">
          {runtimeData.persona_usage.persona_entries.map((item) => (
            <div key={item.persona_id} className="rounded-md border p-3">
              <div className="font-medium">{item.persona_name}</div>
              <div className="mt-1 text-sm text-muted-foreground">
                sessions={item.recent_session_count} / messages=
                {item.recent_message_count} / tool calls=
                {item.recent_tool_call_count}
              </div>
              <div className="mt-2 text-xs text-muted-foreground">
                last activity={item.last_activity_at || "none in 30d"}
              </div>
            </div>
          ))}
        </div>
      </SummaryCard>

      <div className="grid gap-4 xl:grid-cols-3">
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

        <SummaryCard title="Recent Tool Calls">
          <div className="space-y-3">
            {runtimeData.tool_audit.recent_calls.length > 0 ? (
              runtimeData.tool_audit.recent_calls.map((item, index) => (
                <ToolAuditCall
                  key={`${item.tool_name}-${item.time_sent || "unknown"}-${index}`}
                  item={item}
                />
              ))
            ) : (
              <div className="text-sm text-muted-foreground">
                No recent security tool calls recorded.
              </div>
            )}
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
              placeholder env: {runtimeData.placeholder_required_env.length > 0
                ? runtimeData.placeholder_required_env.join(", ")
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
            <div>
              historical packages: {runtimeData.historical_packages.package_count}
            </div>
            <div>
              historical ids: {runtimeData.historical_packages.package_ids.length > 0
                ? runtimeData.historical_packages.package_ids.join(", ")
                : "none"}
            </div>
            <div>
              historical consistency: {runtimeData.historical_packages.consistency.ok
                ? "ok"
                : runtimeData.historical_packages.consistency.issues.join(" | ")}
            </div>
            <div>
              tool counts: {Object.keys(runtimeData.tool_audit.tool_counts).length > 0
                ? Object.entries(runtimeData.tool_audit.tool_counts)
                    .map(([name, count]) => `${name}=${count}`)
                    .join(" | ")
                : "none"}
            </div>
            <div>
              config drift: {runtimeData.tool_drift.mismatch_count}
            </div>
            <div>
              undeclared tools: {runtimeData.tool_drift.missing_declared_configs.length > 0
                ? runtimeData.tool_drift.missing_declared_configs.join(", ")
                : "none"}
            </div>
            <div>
              permission sync cc-pairs: {runtimeData.permission_inheritance.sync_cc_pair_count}
            </div>
            <div>
              docs with external ACL: {runtimeData.permission_inheritance.docs_with_external_acl_count}
            </div>
            <div>
              docs with user ACL: {runtimeData.permission_inheritance.docs_with_user_acl_count}
            </div>
            <div>
              docs with group ACL: {runtimeData.permission_inheritance.docs_with_group_acl_count}
            </div>
            <div>
              permission sync failures: doc=
              {runtimeData.permission_inheritance.recent_doc_sync_failure_count} / group=
              {runtimeData.permission_inheritance.recent_group_sync_failure_count}
            </div>
          </div>
        </SummaryCard>
      </div>

      <SummaryCard title="Tool Config Drift">
        <div className="space-y-3">
          {runtimeData.tool_drift.mismatched_tools.length > 0 ? (
            runtimeData.tool_drift.mismatched_tools.map((item) => (
              <ToolDriftItem key={item.tool_name} item={item} />
            ))
          ) : (
            <div className="text-sm text-muted-foreground">
              No declared tool drift detected for the active profile.
            </div>
          )}
        </div>
      </SummaryCard>

      <SummaryCard title="Failure Summary">
        <div className="space-y-3">
          {runtimeData.failure_summary.recent_failures.length > 0 ? (
            runtimeData.failure_summary.recent_failures.map((item, index) => (
              <FailureItem
                key={`${item.error}-${item.time_sent || "unknown"}-${index}`}
                item={item}
              />
            ))
          ) : (
            <div className="text-sm text-muted-foreground">
              No recent assistant failures recorded.
            </div>
          )}
        </div>
      </SummaryCard>

      <SummaryCard title="Failure Breakdown">
        <div className="grid gap-4 xl:grid-cols-4">
          <div>
            <div className="text-sm font-medium">By Stage</div>
            <div className="mt-3 space-y-2">
              {runtimeData.failure_summary.stage_counts.length > 0 ? (
                runtimeData.failure_summary.stage_counts.map((item) => (
                  <div key={`stage-${item.label}`} className="rounded-md border p-3 text-sm">
                    <div className="font-medium">{item.label}</div>
                    <div className="mt-1 text-xs text-muted-foreground">count={item.count}</div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">No recent stage failures.</div>
              )}
            </div>
          </div>

          <div>
            <div className="text-sm font-medium">By Persona</div>
            <div className="mt-3 space-y-2">
              {runtimeData.failure_summary.persona_counts.length > 0 ? (
                runtimeData.failure_summary.persona_counts.map((item) => (
                  <div key={`persona-${item.label}`} className="rounded-md border p-3 text-sm">
                    <div className="font-medium">{item.label}</div>
                    <div className="mt-1 text-xs text-muted-foreground">count={item.count}</div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">No recent persona failures.</div>
              )}
            </div>
          </div>

          <div>
            <div className="text-sm font-medium">By Tool</div>
            <div className="mt-3 space-y-2">
              {runtimeData.failure_summary.tool_counts.length > 0 ? (
                runtimeData.failure_summary.tool_counts.map((item) => (
                  <div key={`tool-${item.label}`} className="rounded-md border p-3 text-sm">
                    <div className="font-medium">{item.label}</div>
                    <div className="mt-1 text-xs text-muted-foreground">count={item.count}</div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">No recent tool-linked failures.</div>
              )}
            </div>
          </div>


          <div>
            <div className="text-sm font-medium">7d Trend</div>
            <div className="mt-3 space-y-2">
              {runtimeData.failure_summary.daily_counts.map((item) => (
                <div key={`day-${item.day}`} className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{item.day}</div>
                  <div className="mt-1 text-xs text-muted-foreground">count={item.count}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </SummaryCard>

      <SummaryCard title="Failure Hints">
        <div className="space-y-3">
          {runtimeData.failure_summary.remediation_hints.length > 0 ? (
            runtimeData.failure_summary.remediation_hints.map((hint) => (
              <div key={hint} className="rounded-md border p-3 text-sm text-muted-foreground">
                {hint}
              </div>
            ))
          ) : (
            <div className="text-sm text-muted-foreground">
              No remediation hints generated from recent failure patterns.
            </div>
          )}
        </div>
      </SummaryCard>

      <SummaryCard title="Permission Sync Attempts">
        <div className="space-y-3">
          {[
            ...runtimeData.permission_inheritance.recent_doc_sync_attempts,
            ...runtimeData.permission_inheritance.recent_group_sync_attempts,
          ].length > 0 ? (
            [
              ...runtimeData.permission_inheritance.recent_doc_sync_attempts,
              ...runtimeData.permission_inheritance.recent_group_sync_attempts,
            ].map((item) => (
              <PermissionSyncAttemptItem
                key={`${item.sync_type}-${item.attempt_id}`}
                item={item}
              />
            ))
          ) : (
            <div className="text-sm text-muted-foreground">
              No recent permission sync attempts recorded.
            </div>
          )}
        </div>
      </SummaryCard>

      <SummaryCard title="Historical Package Details">
        <div className="space-y-3">
          {runtimeData.historical_packages.packages.length > 0 ? (
            runtimeData.historical_packages.packages.map((item) => (
              <HistoricalPackageDetail key={item.batch_id} item={item} />
            ))
          ) : (
            <div className="text-sm text-muted-foreground">
              No historical package details available.
            </div>
          )}
        </div>
      </SummaryCard>
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
