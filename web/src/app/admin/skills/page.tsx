"use client";

import { useEffect, useMemo, useState } from "react";
import useSWR, { mutate } from "swr";
import { errorHandlingFetcher } from "@/lib/fetcher";
import * as SettingsLayouts from "@/layouts/settings-layouts";
import { ADMIN_ROUTES } from "@/lib/admin-routes";
import { Button } from "@opal/components";
import { Section } from "@/layouts/general-layouts";
import SimpleLoader from "@/refresh-components/loaders/SimpleLoader";
import { toast } from "@/hooks/useToast";

type SkillRiskLevel = "low" | "medium" | "high" | "critical";
type SkillAccessScope =
  | "all_users"
  | "security_team"
  | "admin_only"
  | "quarantined";
type SkillExecutionScope = "standard" | "authorized_scan";
type AuthorizedTargetType = "domain" | "ip" | "cidr" | "url";

interface ManagedSkill {
  key: string;
  name: string;
  description: string;
  path: string;
  risk_level: SkillRiskLevel;
  access_scope: SkillAccessScope;
  enabled: boolean;
  builtin: boolean;
  has_scripts: boolean;
  has_references: boolean;
  has_tools: boolean;
  has_requirements: boolean;
  execution_scope: SkillExecutionScope;
  requires_approval: boolean;
  requires_network_gateway: boolean;
  allowed_target_types: AuthorizedTargetType[];
  notes: string | null;
}

interface SkillRegistrySyncSummary {
  discovered_count: number;
  added_count: number;
  managed_count: number;
}

interface SkillRegistryImportSummary {
  imported_count: number;
  managed_count: number;
  mode: "merge" | "replace";
}

interface SkillRolePreview {
  role: string;
  allowed_count: number;
  allowed_skill_keys: string[];
}

interface SkillRegistrySummary {
  discovered_count: number;
  managed_count: number;
  enabled_count: number;
  quarantined_count: number;
  all_users_count: number;
  security_team_count: number;
  admin_only_count: number;
  critical_count: number;
  authorized_scan_count: number;
  approval_required_count: number;
  gateway_enforced_count: number;
  role_previews: SkillRolePreview[];
}

interface AuthorizedScanTarget {
  target: string;
  target_type: AuthorizedTargetType;
  owner: string;
  approval_reference: string;
  enabled: boolean;
  expires_at: string | null;
  notes: string | null;
}

interface AuthorizedScanPolicySummary {
  managed_target_count: number;
  enabled_target_count: number;
  expired_target_count: number;
  authorized_scan_skill_count: number;
  approval_required_skill_count: number;
  gateway_enforced_skill_count: number;
}

interface AuthorizedScanTargetsImportSummary {
  imported_count: number;
  managed_count: number;
  mode: "merge" | "replace";
}

interface AuthorizedScanAuthorizationResult {
  allowed: boolean;
  skill_key: string;
  execution_scope: SkillExecutionScope;
  gateway_required: boolean;
  allowed_targets: string[];
  denied_targets: string[];
  reasons: string[];
}

interface SkillDraft {
  enabled: boolean;
  risk_level: SkillRiskLevel;
  access_scope: SkillAccessScope;
  execution_scope: SkillExecutionScope;
  requires_approval: boolean;
  requires_network_gateway: boolean;
  allowed_target_types: AuthorizedTargetType[];
  notes: string;
}

const route = ADMIN_ROUTES.SKILLS;
const SKILLS_API = "/api/manage/admin/skills";
const SKILLS_SUMMARY_API = "/api/manage/admin/skills/summary";
const AUTHORIZED_SCAN_SUMMARY_API = "/api/manage/admin/skills/scan-policy/summary";
const AUTHORIZED_SCAN_TARGETS_API = "/api/manage/admin/skills/scan-policy/targets";

const RISK_LABELS: Record<SkillRiskLevel, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

const SCOPE_LABELS: Record<SkillAccessScope, string> = {
  all_users: "All Users",
  security_team: "Security Team",
  admin_only: "Admin Only",
  quarantined: "Quarantined",
};

const EXECUTION_SCOPE_LABELS: Record<SkillExecutionScope, string> = {
  standard: "Standard",
  authorized_scan: "Authorized Scan",
};

function RiskBadge({ riskLevel }: { riskLevel: SkillRiskLevel }) {
  const classes: Record<SkillRiskLevel, string> = {
    low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    medium: "border-sky-500/40 bg-sky-500/10 text-sky-300",
    high: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    critical: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  };

  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${classes[riskLevel]}`}
    >
      {RISK_LABELS[riskLevel]}
    </span>
  );
}

function ScopeBadge({ scope }: { scope: SkillAccessScope }) {
  const classes: Record<SkillAccessScope, string> = {
    all_users: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    security_team: "border-violet-500/40 bg-violet-500/10 text-violet-300",
    admin_only: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    quarantined: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  };

  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${classes[scope]}`}
    >
      {SCOPE_LABELS[scope]}
    </span>
  );
}

export default function SkillsPage() {
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<SkillRiskLevel | "all">("all");
  const [scopeFilter, setScopeFilter] = useState<SkillAccessScope | "all">("all");
  const [enabledFilter, setEnabledFilter] = useState<"all" | "enabled" | "disabled">(
    "all"
  );
  const [importMode, setImportMode] = useState<"merge" | "replace">("merge");
  const [importYaml, setImportYaml] = useState("");
  const [importing, setImporting] = useState(false);

  const skillsApiUrl = useMemo(() => {
    const params = new URLSearchParams();
    if (query.trim()) {
      params.set("query", query.trim());
    }
    if (riskFilter !== "all") {
      params.set("risk_level", riskFilter);
    }
    if (scopeFilter !== "all") {
      params.set("access_scope", scopeFilter);
    }
    if (enabledFilter !== "all") {
      params.set("enabled", String(enabledFilter === "enabled"));
    }
    const serialized = params.toString();
    return serialized ? `${SKILLS_API}?${serialized}` : SKILLS_API;
  }, [enabledFilter, query, riskFilter, scopeFilter]);

  const { data, error, isLoading } = useSWR<ManagedSkill[]>(
    skillsApiUrl,
    errorHandlingFetcher
  );
  const { data: summary } = useSWR<SkillRegistrySummary>(
    SKILLS_SUMMARY_API,
    errorHandlingFetcher
  );
  const { data: scanPolicySummary } = useSWR<AuthorizedScanPolicySummary>(
    AUTHORIZED_SCAN_SUMMARY_API,
    errorHandlingFetcher
  );
  const { data: authorizedTargets } = useSWR<AuthorizedScanTarget[]>(
    AUTHORIZED_SCAN_TARGETS_API,
    errorHandlingFetcher
  );
  const [drafts, setDrafts] = useState<Record<string, SkillDraft>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [targetImportMode, setTargetImportMode] = useState<"merge" | "replace">(
    "merge"
  );
  const [targetImportYaml, setTargetImportYaml] = useState("");
  const [targetImporting, setTargetImporting] = useState(false);
  const [authorizationSkillKey, setAuthorizationSkillKey] = useState("");
  const [authorizationTargets, setAuthorizationTargets] = useState("");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [authorizationResult, setAuthorizationResult] =
    useState<AuthorizedScanAuthorizationResult | null>(null);
  const [authorizing, setAuthorizing] = useState(false);

  useEffect(() => {
    if (!data) {
      return;
    }

    setDrafts(
      Object.fromEntries(
        data.map((skill) => [
          skill.key,
          {
            enabled: skill.enabled,
            risk_level: skill.risk_level,
            access_scope: skill.access_scope,
            execution_scope: skill.execution_scope,
            requires_approval: skill.requires_approval,
            requires_network_gateway: skill.requires_network_gateway,
            allowed_target_types: skill.allowed_target_types,
            notes: skill.notes ?? "",
          },
        ])
      )
    );
  }, [data]);

  const groupedCounts = useMemo(() => {
    const skills = data ?? [];
    return {
      enabled: skills.filter((skill) => skill.enabled).length,
      quarantined: skills.filter(
        (skill) => skill.access_scope === "quarantined"
      ).length,
      securityTeam: skills.filter(
        (skill) => skill.access_scope === "security_team"
      ).length,
      allUsers: skills.filter((skill) => skill.access_scope === "all_users").length,
    };
  }, [data]);

  const updateDraft = (
    skillKey: string,
    field: keyof SkillDraft,
    value: string | boolean | AuthorizedTargetType[]
  ) => {
    setDrafts((current) => {
      const baseDraft: SkillDraft = current[skillKey] ?? {
        enabled: false,
        risk_level: "medium",
        access_scope: "quarantined",
        execution_scope: "standard",
        requires_approval: false,
        requires_network_gateway: false,
        allowed_target_types: [],
        notes: "",
      };
      const nextDraft: SkillDraft = {
        ...baseDraft,
        [field]: value,
      } as SkillDraft;
      return {
        ...current,
        [skillKey]: nextDraft,
      };
    });
  };

  const handleSave = async (skill: ManagedSkill) => {
    const draft = drafts[skill.key];
    if (!draft) {
      return;
    }

    setSavingKey(skill.key);
    try {
      const response = await fetch(`${SKILLS_API}/${skill.key}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(draft),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      await mutate(skillsApiUrl);
      await mutate(SKILLS_SUMMARY_API);
      await mutate(AUTHORIZED_SCAN_SUMMARY_API);
      toast.success(`Updated ${skill.name}`);
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : `Failed to update ${skill.name}`
      );
    } finally {
      setSavingKey(null);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const response = await fetch(`${SKILLS_API}/sync`, {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const result = (await response.json()) as SkillRegistrySyncSummary;
      await mutate(skillsApiUrl);
      await mutate(SKILLS_SUMMARY_API);
      await mutate(AUTHORIZED_SCAN_SUMMARY_API);
      toast.success(
        `Skills synced. Discovered ${result.discovered_count}, added ${result.added_count}.`
      );
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to sync skill registry"
      );
    } finally {
      setSyncing(false);
    }
  };

  const handleExport = async () => {
    try {
      const response = await fetch(`${SKILLS_API}/export`);
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const yamlContent = await response.text();
      const blob = new Blob([yamlContent], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "skills-registry.yaml";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      toast.success("Exported skills registry");
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to export skills registry"
      );
    }
  };

  const handleImport = async () => {
    if (!importYaml.trim()) {
      toast.error("Paste a registry YAML payload before importing");
      return;
    }

    setImporting(true);
    try {
      const response = await fetch(`${SKILLS_API}/import`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          yaml_content: importYaml,
          mode: importMode,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const result = (await response.json()) as SkillRegistryImportSummary;
      await mutate(skillsApiUrl);
      await mutate(SKILLS_SUMMARY_API);
      await mutate(AUTHORIZED_SCAN_SUMMARY_API);
      toast.success(
        `Imported ${result.imported_count} skills in ${result.mode} mode.`
      );
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to import skills registry"
      );
    } finally {
      setImporting(false);
    }
  };

  const handleExportTargets = async () => {
    try {
      const response = await fetch(`${SKILLS_API}/scan-policy/targets/export`);
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const yamlContent = await response.text();
      const blob = new Blob([yamlContent], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "authorized-scan-targets.yaml";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      toast.success("Exported authorized scan targets");
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to export authorized scan targets"
      );
    }
  };

  const handleImportTargets = async () => {
    if (!targetImportYaml.trim()) {
      toast.error("Paste an authorized target YAML payload before importing");
      return;
    }

    setTargetImporting(true);
    try {
      const response = await fetch(`${SKILLS_API}/scan-policy/targets/import`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          yaml_content: targetImportYaml,
          mode: targetImportMode,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const result =
        (await response.json()) as AuthorizedScanTargetsImportSummary;
      await mutate(AUTHORIZED_SCAN_TARGETS_API);
      await mutate(AUTHORIZED_SCAN_SUMMARY_API);
      toast.success(
        `Imported ${result.imported_count} authorized targets in ${result.mode} mode.`
      );
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to import authorized scan targets"
      );
    } finally {
      setTargetImporting(false);
    }
  };

  const handleAuthorizeDryRun = async () => {
    if (!authorizationSkillKey) {
      toast.error("Select an authorized scan skill first");
      return;
    }
    const targets = authorizationTargets
      .split("\n")
      .map((target) => target.trim())
      .filter(Boolean);
    if (!targets.length) {
      toast.error("Provide at least one target");
      return;
    }

    setAuthorizing(true);
    try {
      const response = await fetch(`${SKILLS_API}/scan-policy/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          skill_key: authorizationSkillKey,
          targets,
          approval_reference: authorizationReference || null,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      setAuthorizationResult(
        (await response.json()) as AuthorizedScanAuthorizationResult
      );
    } catch (fetchError) {
      toast.error(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to evaluate authorized scan request"
      );
    } finally {
      setAuthorizing(false);
    }
  };

  return (
    <SettingsLayouts.Root>
      <SettingsLayouts.Header
        title={route.title}
        icon={route.icon}
        description="Review imported skills, assign risk, control visibility, and decide which skills are dynamically loaded into sandbox sessions."
        separator
      />
      <SettingsLayouts.Body>
        <Section className="gap-4" alignItems="stretch">
          <div className="grid gap-3 md:grid-cols-4">
            <div className="rounded-xl border border-border bg-background-100 p-4">
              <div className="text-sm font-medium text-text-03">Enabled</div>
              <div className="text-2xl font-semibold text-text-01">
                {String(summary?.enabled_count ?? groupedCounts.enabled)}
              </div>
            </div>
            <div className="rounded-xl border border-border bg-background-100 p-4">
              <div className="text-sm font-medium text-text-03">All Users</div>
              <div className="text-2xl font-semibold text-text-01">
                {String(summary?.all_users_count ?? groupedCounts.allUsers)}
              </div>
            </div>
            <div className="rounded-xl border border-border bg-background-100 p-4">
              <div className="text-sm font-medium text-text-03">
                Security Team
              </div>
              <div className="text-2xl font-semibold text-text-01">
                {String(
                  summary?.security_team_count ?? groupedCounts.securityTeam
                )}
              </div>
            </div>
            <div className="rounded-xl border border-border bg-background-100 p-4">
              <div className="text-sm font-medium text-text-03">
                Quarantined
              </div>
              <div className="text-2xl font-semibold text-text-01">
                {String(
                  summary?.quarantined_count ?? groupedCounts.quarantined
                )}
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-background-100 p-4">
            <div className="text-sm font-medium text-text-01">
              Import Status
            </div>
            <div className="mt-2 grid gap-3 md:grid-cols-4">
              <div className="rounded-lg border border-border px-3 py-2">
                <div className="text-xs text-text-03">Discovered</div>
                <div className="text-lg font-semibold text-text-01">
                  {String(summary?.discovered_count ?? data?.length ?? 0)}
                </div>
              </div>
              <div className="rounded-lg border border-border px-3 py-2">
                <div className="text-xs text-text-03">Managed</div>
                <div className="text-lg font-semibold text-text-01">
                  {String(summary?.managed_count ?? data?.length ?? 0)}
                </div>
              </div>
              <div className="rounded-lg border border-border px-3 py-2">
                <div className="text-xs text-text-03">Critical Risk</div>
                <div className="text-lg font-semibold text-text-01">
                  {String(summary?.critical_count ?? 0)}
                </div>
              </div>
              <div className="rounded-lg border border-border px-3 py-2">
                <div className="text-xs text-text-03">Admin Only</div>
                <div className="text-lg font-semibold text-text-01">
                  {String(summary?.admin_only_count ?? 0)}
                </div>
              </div>
            </div>
          </div>

          {scanPolicySummary ? (
            <div className="grid gap-3 md:grid-cols-3">
              <div className="rounded-xl border border-border bg-background-100 p-4">
                <div className="text-sm font-medium text-text-03">
                  Authorized Scan Skills
                </div>
                <div className="text-2xl font-semibold text-text-01">
                  {String(scanPolicySummary.authorized_scan_skill_count)}
                </div>
              </div>
              <div className="rounded-xl border border-border bg-background-100 p-4">
                <div className="text-sm font-medium text-text-03">
                  Allowlisted Targets
                </div>
                <div className="text-2xl font-semibold text-text-01">
                  {String(scanPolicySummary.enabled_target_count)}
                </div>
              </div>
              <div className="rounded-xl border border-border bg-background-100 p-4">
                <div className="text-sm font-medium text-text-03">
                  Approval Required
                </div>
                <div className="text-2xl font-semibold text-text-01">
                  {String(scanPolicySummary.approval_required_skill_count)}
                </div>
              </div>
            </div>
          ) : null}

          {summary ? (
            <div className="rounded-xl border border-border bg-background-100 p-4">
              <div className="text-sm font-medium text-text-01">
                Dynamic Load Preview
              </div>
              <div className="mt-3 grid gap-3 lg:grid-cols-3">
                {summary.role_previews.map((preview) => (
                  <div
                    key={preview.role}
                    className="rounded-lg border border-border p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm font-medium text-text-01">
                        {preview.role}
                      </div>
                      <div className="text-xs text-text-03">
                        {preview.allowed_count} loaded
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {preview.allowed_skill_keys.length ? (
                        preview.allowed_skill_keys.map((skillKey) => (
                          <span
                            key={skillKey}
                            className="rounded-full border border-border px-2 py-0.5 text-xs text-text-03"
                          >
                            {skillKey}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-text-03">
                          No skills loaded
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-background-100 p-4">
            <div className="space-y-1">
              <div className="text-sm font-medium text-text-01">
                Skill Registry
              </div>
              <p className="text-sm text-text-03">
                Skills are discovered from the repository, classified here, and
                only allowed skills are loaded into sandbox sessions.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleExport}>Export YAML</Button>
              <Button onClick={handleSync} disabled={syncing}>
                {syncing ? "Syncing..." : "Sync Skills"}
              </Button>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-background-100 p-4">
            <div className="grid gap-3 lg:grid-cols-4">
              <label className="flex flex-col gap-2">
                <div className="text-sm font-medium text-text-01">Query</div>
                <input
                  className="rounded-lg border border-border bg-background px-3 py-2"
                  placeholder="Search key, description, path, or notes"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>

              <label className="flex flex-col gap-2">
                <div className="text-sm font-medium text-text-01">Risk</div>
                <select
                  className="rounded-lg border border-border bg-background px-3 py-2"
                  value={riskFilter}
                  onChange={(event) =>
                    setRiskFilter(event.target.value as SkillRiskLevel | "all")
                  }
                >
                  <option value="all">All</option>
                  {(Object.keys(RISK_LABELS) as SkillRiskLevel[]).map((risk) => (
                    <option key={risk} value={risk}>
                      {RISK_LABELS[risk]}
                    </option>
                  ))}
                </select>
              </label>

              <label className="flex flex-col gap-2">
                <div className="text-sm font-medium text-text-01">Scope</div>
                <select
                  className="rounded-lg border border-border bg-background px-3 py-2"
                  value={scopeFilter}
                  onChange={(event) =>
                    setScopeFilter(event.target.value as SkillAccessScope | "all")
                  }
                >
                  <option value="all">All</option>
                  {(Object.keys(SCOPE_LABELS) as SkillAccessScope[]).map((scope) => (
                    <option key={scope} value={scope}>
                      {SCOPE_LABELS[scope]}
                    </option>
                  ))}
                </select>
              </label>

              <label className="flex flex-col gap-2">
                <div className="text-sm font-medium text-text-01">Enabled</div>
                <select
                  className="rounded-lg border border-border bg-background px-3 py-2"
                  value={enabledFilter}
                  onChange={(event) =>
                    setEnabledFilter(
                      event.target.value as "all" | "enabled" | "disabled"
                    )
                  }
                >
                  <option value="all">All</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </label>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-background-100 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-text-01">
                  Import Registry YAML
                </div>
                <p className="text-sm text-text-03">
                  Merge updates into the current registry, or replace the entire
                  registry payload.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select
                  className="rounded-lg border border-border bg-background px-3 py-2"
                  value={importMode}
                  onChange={(event) =>
                    setImportMode(event.target.value as "merge" | "replace")
                  }
                >
                  <option value="merge">Merge</option>
                  <option value="replace">Replace</option>
                </select>
                <Button onClick={handleImport} disabled={importing}>
                  {importing ? "Importing..." : "Import YAML"}
                </Button>
              </div>
            </div>
            <textarea
              className="mt-3 min-h-40 w-full rounded-xl border border-border bg-background px-3 py-2 font-mono text-sm"
              placeholder={"skills:\n  example-skill:\n    enabled: true\n    risk_level: medium\n    access_scope: security_team\n    notes: Imported registry entry"}
              value={importYaml}
              onChange={(event) => setImportYaml(event.target.value)}
            />
          </div>

          <div className="rounded-xl border border-border bg-background-100 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-text-01">
                  Authorized Scan Controls
                </div>
                <p className="text-sm text-text-03">
                  Keep high-risk scanning skills disabled by default, then gate
                  execution behind a target allowlist, approval reference, and
                  gateway requirement.
                </p>
              </div>
              <Button onClick={handleExportTargets}>Export Targets</Button>
            </div>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              <div className="rounded-xl border border-border p-4">
                <div className="text-sm font-medium text-text-01">
                  Authorized Targets
                </div>
                <div className="mt-3 max-h-64 space-y-2 overflow-auto">
                  {(authorizedTargets ?? []).length ? (
                    authorizedTargets?.map((target) => (
                      <div
                        key={`${target.target_type}:${target.target}`}
                        className="rounded-lg border border-border px-3 py-2"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="text-sm font-medium text-text-01">
                            {target.target}
                          </div>
                          <span className="text-xs text-text-03">
                            {target.target_type}
                          </span>
                        </div>
                        <div className="mt-1 text-xs text-text-03">
                          owner: {target.owner || "n/a"} | approval:{" "}
                          {target.approval_reference || "n/a"}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-text-03">
                      No authorized scan targets configured yet.
                    </div>
                  )}
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <select
                    className="rounded-lg border border-border bg-background px-3 py-2"
                    value={targetImportMode}
                    onChange={(event) =>
                      setTargetImportMode(event.target.value as "merge" | "replace")
                    }
                  >
                    <option value="merge">Merge</option>
                    <option value="replace">Replace</option>
                  </select>
                  <Button onClick={handleImportTargets} disabled={targetImporting}>
                    {targetImporting ? "Importing..." : "Import Targets YAML"}
                  </Button>
                </div>
                <textarea
                  className="mt-3 min-h-32 w-full rounded-xl border border-border bg-background px-3 py-2 font-mono text-sm"
                  placeholder={"targets:\n  - target: example.com\n    target_type: domain\n    owner: Security Engineering\n    approval_reference: CHG-2026-001\n    enabled: true"}
                  value={targetImportYaml}
                  onChange={(event) => setTargetImportYaml(event.target.value)}
                />
              </div>

              <div className="rounded-xl border border-border p-4">
                <div className="text-sm font-medium text-text-01">
                  Authorization Dry Run
                </div>
                <div className="mt-3 grid gap-3">
                  <select
                    className="rounded-lg border border-border bg-background px-3 py-2"
                    value={authorizationSkillKey}
                    onChange={(event) => setAuthorizationSkillKey(event.target.value)}
                  >
                    <option value="">Select authorized scan skill</option>
                    {(data ?? [])
                      .filter(
                        (skill) => skill.execution_scope === "authorized_scan"
                      )
                      .map((skill) => (
                        <option key={skill.key} value={skill.key}>
                          {skill.key}
                        </option>
                      ))}
                  </select>
                  <input
                    className="rounded-lg border border-border bg-background px-3 py-2"
                    placeholder="Approval reference (for example CHG-2026-001)"
                    value={authorizationReference}
                    onChange={(event) =>
                      setAuthorizationReference(event.target.value)
                    }
                  />
                  <textarea
                    className="min-h-32 rounded-xl border border-border bg-background px-3 py-2 font-mono text-sm"
                    placeholder={"example.com\n1.2.3.4\nhttps://target.example.com"}
                    value={authorizationTargets}
                    onChange={(event) =>
                      setAuthorizationTargets(event.target.value)
                    }
                  />
                  <Button onClick={handleAuthorizeDryRun} disabled={authorizing}>
                    {authorizing ? "Evaluating..." : "Evaluate Authorization"}
                  </Button>
                </div>
                {authorizationResult ? (
                  <div className="mt-4 rounded-xl border border-border p-4">
                    <div className="flex items-center gap-2">
                      <div className="text-sm font-medium text-text-01">
                        Result
                      </div>
                      <span
                        className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${
                          authorizationResult.allowed
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                            : "border-rose-500/40 bg-rose-500/10 text-rose-300"
                        }`}
                      >
                        {authorizationResult.allowed ? "Allowed" : "Denied"}
                      </span>
                    </div>
                    <div className="mt-2 text-sm text-text-03">
                      gateway required:{" "}
                      {authorizationResult.gateway_required ? "yes" : "no"}
                    </div>
                    <div className="mt-3 text-sm text-text-01">
                      Allowed targets:{" "}
                      {authorizationResult.allowed_targets.length
                        ? authorizationResult.allowed_targets.join(", ")
                        : "none"}
                    </div>
                    <div className="mt-2 text-sm text-text-01">
                      Denied targets:{" "}
                      {authorizationResult.denied_targets.length
                        ? authorizationResult.denied_targets.join(", ")
                        : "none"}
                    </div>
                    <div className="mt-3 text-sm text-text-03">
                      {authorizationResult.reasons.length
                        ? authorizationResult.reasons.join(" | ")
                        : "No policy violations detected"}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          {isLoading ? <SimpleLoader /> : null}

          {error ? (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4">
              <div className="text-sm text-rose-200">
                Failed to load managed skills.
              </div>
            </div>
          ) : null}

          <div className="space-y-4">
            {(data ?? []).map((skill) => {
              const draft = drafts[skill.key];
              if (!draft) {
                return null;
              }

              return (
                <div
                  key={skill.key}
                  className="rounded-2xl border border-border bg-background-100 p-5"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="text-lg font-semibold text-text-01">
                          {skill.name}
                        </div>
                        <RiskBadge riskLevel={draft.risk_level} />
                        <ScopeBadge scope={draft.access_scope} />
                        {draft.enabled ? (
                          <span className="inline-flex rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300">
                            Enabled
                          </span>
                        ) : (
                          <span className="inline-flex rounded-full border border-border px-2 py-0.5 text-xs font-medium text-text-03">
                            Disabled
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-text-03">{skill.description}</p>
                      <div className="text-xs text-text-04">
                        {skill.path}
                      </div>
                    </div>
                    <Button
                      onClick={() => handleSave(skill)}
                      disabled={savingKey === skill.key}
                    >
                      {savingKey === skill.key ? "Saving..." : "Save"}
                    </Button>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2 text-xs text-text-03">
                    <span>builtin: {skill.builtin ? "yes" : "no"}</span>
                    <span>scripts: {skill.has_scripts ? "yes" : "no"}</span>
                    <span>references: {skill.has_references ? "yes" : "no"}</span>
                    <span>tools: {skill.has_tools ? "yes" : "no"}</span>
                    <span>
                      requirements: {skill.has_requirements ? "yes" : "no"}
                    </span>
                  </div>

                  <div className="mt-4 grid gap-4 lg:grid-cols-3">
                    <label className="flex items-center gap-2 rounded-xl border border-border p-3">
                      <input
                        type="checkbox"
                        checked={draft.enabled}
                        onChange={(event) =>
                          updateDraft(skill.key, "enabled", event.target.checked)
                        }
                      />
                      <div>
                        <div className="text-sm font-medium text-text-01">
                          Enabled
                        </div>
                        <p className="text-sm text-text-03">
                          Disabled or quarantined skills are excluded from new
                          sandbox sessions.
                        </p>
                      </div>
                    </label>

                    <label className="flex flex-col gap-2 rounded-xl border border-border p-3">
                      <div className="text-sm font-medium text-text-01">
                        Risk Level
                      </div>
                      <select
                        className="rounded-lg border border-border bg-background px-3 py-2"
                        value={draft.risk_level}
                        onChange={(event) =>
                          updateDraft(
                            skill.key,
                            "risk_level",
                            event.target.value as SkillRiskLevel
                          )
                        }
                      >
                        {(
                          Object.keys(RISK_LABELS) as Array<keyof typeof RISK_LABELS>
                        ).map((riskLevel) => (
                          <option key={riskLevel} value={riskLevel}>
                            {RISK_LABELS[riskLevel]}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="flex flex-col gap-2 rounded-xl border border-border p-3">
                      <div className="text-sm font-medium text-text-01">
                        Access Scope
                      </div>
                      <select
                        className="rounded-lg border border-border bg-background px-3 py-2"
                        value={draft.access_scope}
                        onChange={(event) =>
                          updateDraft(
                            skill.key,
                            "access_scope",
                            event.target.value as SkillAccessScope
                          )
                        }
                      >
                        {(
                          Object.keys(
                            SCOPE_LABELS
                          ) as Array<keyof typeof SCOPE_LABELS>
                        ).map((scope) => (
                          <option key={scope} value={scope}>
                            {SCOPE_LABELS[scope]}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>

                  <div className="mt-4 grid gap-4 lg:grid-cols-3">
                    <label className="flex flex-col gap-2 rounded-xl border border-border p-3">
                      <div className="text-sm font-medium text-text-01">
                        Execution Scope
                      </div>
                      <select
                        className="rounded-lg border border-border bg-background px-3 py-2"
                        value={draft.execution_scope}
                        onChange={(event) =>
                          updateDraft(
                            skill.key,
                            "execution_scope",
                            event.target.value as SkillExecutionScope
                          )
                        }
                      >
                        {(Object.keys(
                          EXECUTION_SCOPE_LABELS
                        ) as SkillExecutionScope[]).map((scope) => (
                          <option key={scope} value={scope}>
                            {EXECUTION_SCOPE_LABELS[scope]}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="flex items-center gap-2 rounded-xl border border-border p-3">
                      <input
                        type="checkbox"
                        checked={draft.requires_approval}
                        onChange={(event) =>
                          updateDraft(
                            skill.key,
                            "requires_approval",
                            event.target.checked
                          )
                        }
                      />
                      <div>
                        <div className="text-sm font-medium text-text-01">
                          Requires Approval
                        </div>
                        <p className="text-sm text-text-03">
                          Block execution unless an approval reference is supplied.
                        </p>
                      </div>
                    </label>

                    <label className="flex items-center gap-2 rounded-xl border border-border p-3">
                      <input
                        type="checkbox"
                        checked={draft.requires_network_gateway}
                        onChange={(event) =>
                          updateDraft(
                            skill.key,
                            "requires_network_gateway",
                            event.target.checked
                          )
                        }
                      />
                      <div>
                        <div className="text-sm font-medium text-text-01">
                          Requires Gateway
                        </div>
                        <p className="text-sm text-text-03">
                          Force network egress through the authorized scan gateway.
                        </p>
                      </div>
                    </label>
                  </div>

                  <label className="mt-4 flex flex-col gap-2">
                    <div className="text-sm font-medium text-text-01">
                      Allowed Target Types
                    </div>
                    <input
                      className="rounded-xl border border-border bg-background px-3 py-2"
                      value={draft.allowed_target_types.join(", ")}
                      onChange={(event) =>
                        updateDraft(
                          skill.key,
                          "allowed_target_types",
                          event.target.value
                            .split(",")
                            .map((value) => value.trim())
                            .filter(Boolean) as AuthorizedTargetType[]
                        )
                      }
                      placeholder="domain, ip, cidr, url"
                    />
                  </label>

                  <label className="mt-4 flex flex-col gap-2">
                    <div className="text-sm font-medium text-text-01">Notes</div>
                    <textarea
                      className="min-h-24 rounded-xl border border-border bg-background px-3 py-2"
                      value={draft.notes}
                      onChange={(event) =>
                        updateDraft(skill.key, "notes", event.target.value)
                      }
                    />
                  </label>
                </div>
              );
            })}
          </div>
        </Section>
      </SettingsLayouts.Body>
    </SettingsLayouts.Root>
  );
}
