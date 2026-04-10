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
  notes: string | null;
}

interface SkillRegistrySyncSummary {
  discovered_count: number;
  added_count: number;
  managed_count: number;
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
  role_previews: SkillRolePreview[];
}

interface SkillDraft {
  enabled: boolean;
  risk_level: SkillRiskLevel;
  access_scope: SkillAccessScope;
  notes: string;
}

const route = ADMIN_ROUTES.SKILLS;
const SKILLS_API = "/api/manage/admin/skills";
const SKILLS_SUMMARY_API = "/api/manage/admin/skills/summary";

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
  const { data, error, isLoading } = useSWR<ManagedSkill[]>(
    SKILLS_API,
    errorHandlingFetcher
  );
  const { data: summary } = useSWR<SkillRegistrySummary>(
    SKILLS_SUMMARY_API,
    errorHandlingFetcher
  );
  const [drafts, setDrafts] = useState<Record<string, SkillDraft>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);

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
    value: string | boolean
  ) => {
    setDrafts((current) => {
      const baseDraft: SkillDraft = current[skillKey] ?? {
        enabled: false,
        risk_level: "medium",
        access_scope: "quarantined",
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
      await mutate(SKILLS_API);
      await mutate(SKILLS_SUMMARY_API);
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
      await mutate(SKILLS_API);
      await mutate(SKILLS_SUMMARY_API);
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
            <Button onClick={handleSync} disabled={syncing}>
              {syncing ? "Syncing..." : "Sync Skills"}
            </Button>
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
