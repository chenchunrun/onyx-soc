"use client";

import { useMemo, useState } from "react";
import useSWR, { mutate } from "swr";
import * as SettingsLayouts from "@/layouts/settings-layouts";
import { Section } from "@/layouts/general-layouts";
import { ADMIN_ROUTES } from "@/lib/admin-routes";
import { errorHandlingFetcher } from "@/lib/fetcher";
import { Button } from "@opal/components";
import SimpleLoader from "@/refresh-components/loaders/SimpleLoader";
import { toast } from "@/hooks/useToast";

interface ManagedPromptPreset {
  id: string;
  name: string;
  description: string;
  content: string;
  category: string;
  agent_type: string;
  source_file: string;
  shortcut_name: string;
  imported: boolean;
  input_prompt_id: number | null;
  active: boolean;
}

interface PromptPresetSummary {
  discovered_count: number;
  imported_count: number;
  active_count: number;
  agent_type_counts: Record<string, number>;
  category_counts: Record<string, number>;
}

interface PromptPresetSyncSummary {
  discovered_count: number;
  created_count: number;
  updated_count: number;
  imported_count: number;
}

const route = ADMIN_ROUTES.PROMPT_PRESETS;
const PROMPT_PRESETS_API = "/api/manage/admin/prompt-presets";
const PROMPT_PRESETS_SUMMARY_API = "/api/manage/admin/prompt-presets/summary";

export default function PromptPresetsPage() {
  const [query, setQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [agentTypeFilter, setAgentTypeFilter] = useState("all");
  const [importedFilter, setImportedFilter] = useState<
    "all" | "imported" | "not_imported"
  >("all");
  const [syncing, setSyncing] = useState(false);

  const presetsApiUrl = useMemo(() => {
    const params = new URLSearchParams();
    if (query.trim()) {
      params.set("query", query.trim());
    }
    if (categoryFilter !== "all") {
      params.set("category", categoryFilter);
    }
    if (agentTypeFilter !== "all") {
      params.set("agent_type", agentTypeFilter);
    }
    if (importedFilter !== "all") {
      params.set("imported", String(importedFilter === "imported"));
    }
    const serialized = params.toString();
    return serialized ? `${PROMPT_PRESETS_API}?${serialized}` : PROMPT_PRESETS_API;
  }, [agentTypeFilter, categoryFilter, importedFilter, query]);

  const { data, error, isLoading } = useSWR<ManagedPromptPreset[]>(
    presetsApiUrl,
    errorHandlingFetcher
  );
  const { data: summary } = useSWR<PromptPresetSummary>(
    PROMPT_PRESETS_SUMMARY_API,
    errorHandlingFetcher
  );

  const categoryOptions = useMemo(
    () => ["all", ...Object.keys(summary?.category_counts ?? {}).sort()],
    [summary]
  );
  const agentTypeOptions = useMemo(
    () => ["all", ...Object.keys(summary?.agent_type_counts ?? {}).sort()],
    [summary]
  );

  const handleSync = async () => {
    setSyncing(true);
    try {
      const response = await fetch(`${PROMPT_PRESETS_API}/sync`, {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error("Failed to sync prompt presets");
      }
      const result = (await response.json()) as PromptPresetSyncSummary;
      await Promise.all([
        mutate(presetsApiUrl),
        mutate(PROMPT_PRESETS_SUMMARY_API),
        mutate("/api/input_prompt"),
      ]);
      toast.success(
        `已同步 ${result.imported_count} 个样板，新增 ${result.created_count}，更新 ${result.updated_count}`
      );
    } catch {
      toast.error("同步 Prompt Presets 失败");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <SettingsLayouts.Root>
      <SettingsLayouts.Header
        title={route.title}
        description="管理 prompts/ 下的智能体样板，并同步为公共 Prompt Shortcuts。"
        icon={route.icon}
        rightChildren={
          <Button onClick={handleSync} disabled={syncing}>
            {syncing ? "Syncing..." : "Sync To Public Prompts"}
          </Button>
        }
        separator
      />

      <SettingsLayouts.Body>
      <Section gap={16}>
        <div className="grid gap-4 md:grid-cols-3">
          <SummaryCard title="Discovered" value={summary?.discovered_count ?? 0} />
          <SummaryCard title="Imported" value={summary?.imported_count ?? 0} />
          <SummaryCard title="Active" value={summary?.active_count ?? 0} />
        </div>

        <div className="rounded-xl border border-border bg-background-100 p-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="grid flex-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
              <FilterField
                label="Query"
                value={query}
                onChange={setQuery}
                placeholder="搜索名称、分类、agentType"
              />
              <SelectField
                label="Category"
                value={categoryFilter}
                onChange={setCategoryFilter}
                options={categoryOptions}
              />
              <SelectField
                label="Agent Type"
                value={agentTypeFilter}
                onChange={setAgentTypeFilter}
                options={agentTypeOptions}
              />
              <SelectField
                label="Imported"
                value={importedFilter}
                onChange={(value) =>
                  setImportedFilter(value as "all" | "imported" | "not_imported")
                }
                options={["all", "imported", "not_imported"]}
              />
            </div>
          </div>
        </div>

        {isLoading && <SimpleLoader />}
        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
            无法加载 Prompt Presets。
          </div>
        )}

        <div className="grid gap-4">
          {(data ?? []).map((preset) => (
            <div
              key={preset.id}
              className="rounded-xl border border-border bg-background-100 p-4"
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-lg font-semibold">{preset.name}</h3>
                    <Badge label={preset.agent_type} />
                    <Badge label={preset.category} subtle />
                    <StatusBadge imported={preset.imported} active={preset.active} />
                  </div>
                  <p className="text-sm text-subtle">{preset.description}</p>
                  <div className="text-xs text-subtle">
                    <span>{preset.shortcut_name}</span>
                    <span className="mx-2">·</span>
                    <span>{preset.source_file}</span>
                  </div>
                </div>
              </div>
              <pre className="mt-4 overflow-x-auto rounded-lg border border-border bg-background px-3 py-2 text-xs text-foreground whitespace-pre-wrap">
                {preset.content}
              </pre>
            </div>
          ))}
        </div>
      </Section>
      </SettingsLayouts.Body>
    </SettingsLayouts.Root>
  );
}

function SummaryCard({ title, value }: { title: string; value: number }) {
  return (
    <div className="rounded-xl border border-border bg-background-100 p-4">
      <div className="text-sm text-subtle">{title}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
    </div>
  );
}

function FilterField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-subtle">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="rounded-lg border border-border bg-background px-3 py-2 text-sm outline-none"
      />
    </label>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
}) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-subtle">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-border bg-background px-3 py-2 text-sm outline-none"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function Badge({ label, subtle = false }: { label: string; subtle?: boolean }) {
  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 text-xs ${
        subtle
          ? "border-border bg-background text-subtle"
          : "border-sky-500/30 bg-sky-500/10 text-sky-300"
      }`}
    >
      {label}
    </span>
  );
}

function StatusBadge({
  imported,
  active,
}: {
  imported: boolean;
  active: boolean;
}) {
  if (!imported) {
    return (
      <span className="inline-flex rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">
        Not Imported
      </span>
    );
  }

  return (
    <span className="inline-flex rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-300">
      {active ? "Imported" : "Imported (Inactive)"}
    </span>
  );
}
