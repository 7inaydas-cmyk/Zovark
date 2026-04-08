import { useState, useEffect, useCallback } from "react";
import {
  ChevronDown,
  FileText,
  Loader2,
  RefreshCw,
  Search,
  Trash2,
} from "lucide-react";

// API response uses skill_slug, skill_name — map to our interface
interface AutoTemplate {
  skill_slug: string;
  skill_name: string;
  task_types: string[];
  auto_promoted: boolean;
  source_task_id: string | null;
  promoted_at: string | null;
  promoted_by: string | null;
  promotion_status: string;
  created_at: string;
}

interface AutoTemplatesProps {
  token: string;
}

export default function AutoTemplates({ token }: AutoTemplatesProps) {
  const [templates, setTemplates] = useState<AutoTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [expandedSlug, setExpandedSlug] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const fetchTemplates = useCallback(async () => {
    try {
      const res = await fetch(
        `${window.location.origin}/api/v1/auto-templates`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error(`API ${res.status}`);
      const data = await res.json();
      // API may return {items: [...]} or [...] directly
      const items = Array.isArray(data) ? data : data.items ?? data.templates ?? [];
      setTemplates(items);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch templates");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchTemplates();
  }, [fetchTemplates]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(fetchTemplates, 30000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchTemplates]);

  async function handleDelete(slug: string) {
    setDeleting(true);
    try {
      const res = await fetch(
        `${window.location.origin}/api/v1/auto-templates/${slug}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Failed to disable template");
      setTemplates((prev) => prev.filter((t) => t.skill_slug !== slug));
      setConfirmDelete(null);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeleting(false);
    }
  }

  // Filtering
  const filtered = templates.filter((t) => {
    if (statusFilter !== "all" && t.promotion_status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        t.skill_slug.toLowerCase().includes(q) ||
        t.skill_name.toLowerCase().includes(q) ||
        t.task_types?.some((tt) => tt.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const activeCount = templates.filter((t) => t.promotion_status === "active").length;
  const pendingCount = templates.filter((t) => t.promotion_status !== "active" && t.promotion_status !== "disabled").length;

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading auto templates...
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-zinc-100">Auto Templates</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Templates promoted from Path C investigations via analyst confirmation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="badge-green">{activeCount} active</span>
            {pendingCount > 0 && <span className="badge-yellow">{pendingCount} pending</span>}
            <span className="badge-zinc">{templates.length} total</span>
          </div>
          <button
            onClick={fetchTemplates}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center justify-between">
          <span>{error}</span>
          <button onClick={fetchTemplates} className="btn-secondary text-xs py-1 px-2">
            Retry
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search slug, name, or task type..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field pl-9 text-xs py-2"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input-field w-auto text-xs py-2 pr-8"
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="retired">Retired</option>
        </select>
        <label className="flex items-center gap-1.5 text-xs text-zinc-500 cursor-pointer ml-auto">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="rounded border-zinc-600 bg-zinc-800 text-emerald-500 focus:ring-emerald-500/30"
          />
          Auto-refresh
        </label>
      </div>

      {/* Template list */}
      {filtered.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="w-8 h-8 text-zinc-600 mx-auto mb-3" />
          <p className="text-sm text-zinc-400">
            {templates.length === 0
              ? "No auto templates yet."
              : "No templates match the current filters."}
          </p>
          {templates.length === 0 && (
            <p className="text-xs text-zinc-600 mt-1">
              Templates are created when Path C investigations are confirmed by analysts.
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((t) => {
            const isExpanded = expandedSlug === t.skill_slug;
            return (
              <div
                key={t.skill_slug}
                className="card p-0 overflow-hidden"
              >
                {/* Card header */}
                <div
                  className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-zinc-800/30 transition-colors"
                  onClick={() => setExpandedSlug(isExpanded ? null : t.skill_slug)}
                >
                  <ChevronDown
                    className={`w-3.5 h-3.5 text-zinc-500 flex-shrink-0 transition-transform duration-150 ${
                      isExpanded ? "" : "-rotate-90"
                    }`}
                  />

                  {/* Status dot */}
                  <div
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      t.promotion_status === "active"
                        ? "bg-emerald-400"
                        : t.promotion_status === "disabled"
                          ? "bg-red-400"
                          : "bg-yellow-400"
                    }`}
                  />

                  {/* Slug */}
                  <code className="text-sm font-medium text-zinc-200 truncate min-w-0">
                    {t.skill_slug || t.skill_name || "-"}
                  </code>

                  {/* Task type pills */}
                  <div className="flex items-center gap-1 flex-shrink-0 overflow-hidden max-w-[300px]">
                    {(t.task_types ?? []).slice(0, 3).map((tt) => (
                      <span
                        key={tt}
                        className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/15 truncate"
                      >
                        {tt}
                      </span>
                    ))}
                    {(t.task_types?.length ?? 0) > 3 && (
                      <span className="text-[10px] text-zinc-500">
                        +{t.task_types.length - 3}
                      </span>
                    )}
                  </div>

                  {/* Status badge */}
                  <span
                    className={`ml-auto flex-shrink-0 ${
                      t.promotion_status === "active"
                        ? "badge-green"
                        : t.promotion_status === "disabled"
                          ? "badge-red"
                          : "badge-yellow"
                    } text-[10px]`}
                  >
                    {t.promotion_status?.toUpperCase() ?? "UNKNOWN"}
                  </span>

                  {/* Promoted info */}
                  <span className="text-[10px] text-zinc-500 flex-shrink-0 w-24 text-right truncate">
                    {t.promoted_at
                      ? timeAgo(t.promoted_at)
                      : "-"}
                  </span>

                  {/* Delete */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDelete(t.skill_slug);
                    }}
                    className="text-zinc-600 hover:text-red-400 transition-colors flex-shrink-0"
                    title="Disable template"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="px-4 py-3 border-t border-zinc-800/50 bg-zinc-900/50 space-y-3">
                    <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
                      <div>
                        <span className="text-zinc-500">Name:</span>{" "}
                        <span className="text-zinc-200">{t.skill_name || "-"}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Slug:</span>{" "}
                        <code className="text-zinc-300">{t.skill_slug}</code>
                      </div>
                      <div>
                        <span className="text-zinc-500">Promoted by:</span>{" "}
                        <span className="text-zinc-200">{t.promoted_by || "-"}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Promoted at:</span>{" "}
                        <span className="text-zinc-200">
                          {t.promoted_at
                            ? new Date(t.promoted_at).toLocaleString()
                            : "-"}
                        </span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Source task:</span>{" "}
                        <code className="text-cyan-400 text-[11px]">
                          {t.source_task_id?.slice(0, 12) || "-"}
                        </code>
                      </div>
                      <div>
                        <span className="text-zinc-500">Created:</span>{" "}
                        <span className="text-zinc-200">
                          {t.created_at
                            ? new Date(t.created_at).toLocaleString()
                            : "-"}
                        </span>
                      </div>
                    </div>

                    {/* Task types */}
                    {t.task_types?.length > 0 && (
                      <div>
                        <span className="text-xs text-zinc-500 block mb-1.5">Task Types:</span>
                        <div className="flex flex-wrap gap-1.5">
                          {t.task_types.map((tt) => (
                            <span
                              key={tt}
                              className="px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/15"
                            >
                              {tt}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Delete confirmation modal */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="card max-w-md w-full mx-4 space-y-4 border-red-500/30">
            <div className="flex items-center gap-2 text-red-400">
              <Trash2 className="w-5 h-5" />
              <h3 className="text-sm font-bold">Disable Template</h3>
            </div>
            <p className="text-sm text-zinc-400">
              Disable <code className="text-zinc-200">{confirmDelete}</code>?
              Future alerts matching this template will fall through to Path C
              (full LLM tool selection).
            </p>
            <div className="flex justify-end gap-3 pt-2 border-t border-zinc-800">
              <button
                onClick={() => setConfirmDelete(null)}
                className="btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(confirmDelete)}
                disabled={deleting}
                className="btn-danger flex items-center gap-2 text-sm"
              >
                {deleting && <Loader2 className="w-4 h-4 animate-spin" />}
                Disable
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}
