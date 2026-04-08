import { useState, useEffect, useCallback, useRef, Component, type ReactNode, type ErrorInfo } from "react";
import {
  Settings,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Pencil,
  Save,
  X,
  Clock,
  User,
} from "lucide-react";
import {
  getSystemHealth,
  getConfig,
  upsertConfig,
  getConfigAudit,
} from "../lib/api";
import type {
  SystemHealth,
  ConfigEntry,
  ConfigAuditEntry,
} from "../lib/api";
import Sidebar, { type Page } from "./Sidebar";
import ZvadminPanel from "./ZvadminPanel";
import AlertForge from "./AlertForge";
import AnalyticsPanel from "./AnalyticsPanel";
import PipelineMonitor from "./PipelineMonitor";
import AutoTemplates from "./AutoTemplates";

// Error boundary to catch and display React crashes instead of blank screen
class TabErrorBoundary extends Component<
  { children: ReactNode; tabName: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[${this.props.tabName}] React crash:`, error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="p-6 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 space-y-2">
          <div className="text-sm font-semibold">Tab crashed: {this.props.tabName}</div>
          <pre className="text-xs text-red-300 whitespace-pre-wrap">{this.state.error.message}</pre>
          <button onClick={() => this.setState({ error: null })} className="btn-secondary text-xs mt-2">
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

interface AdminDashboardProps {
  token: string;
  onLogout: () => void;
}

export default function AdminDashboard({
  token,
  onLogout,
}: AdminDashboardProps) {
  const [page, setPage] = useState<Page>("health");

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <Sidebar activePage={page} onNavigate={setPage} onLogout={onLogout} />

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <TabErrorBoundary key={page} tabName={page}>
            {page === "health" && <HealthTab token={token} />}
            {page === "siem" && <SIEMTab token={token} />}
            {page === "config" && <ConfigTab token={token} />}
            {page === "zvadmin" && <ZvadminPanel token={token} />}
            {page === "forge" && <AlertForge token={token} />}
            {page === "analytics" && <AnalyticsPanel token={token} />}
            {page === "pipeline" && <PipelineMonitor token={token} />}
            {page === "auto-templates" && <AutoTemplates token={token} />}
          </TabErrorBoundary>
        </div>
      </main>
    </div>
  );
}

// --- Tab 1: System Health ---

function HealthTab({ token }: { token: string }) {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      const data = await getSystemHealth(token);
      setHealth(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch health");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchHealth();
    intervalRef.current = setInterval(fetchHealth, 30000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchHealth]);

  if (loading && !health) {
    return (
      <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading system health...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-zinc-100">Service Status</h2>
        <div className="flex items-center gap-3">
          {health?.gpu_tier && (
            <span className="badge-zinc">GPU: {health.gpu_tier}</span>
          )}
          {health?.uptime_seconds !== undefined && (
            <span className="text-xs text-zinc-500">
              Uptime: {formatUptime(health.uptime_seconds)}
            </span>
          )}
          <button
            onClick={fetchHealth}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
            title="Refresh now"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {health && (
        <>
          {/* Overall banner */}
          <div
            className={`card flex items-center gap-3 ${
              health.status === "healthy"
                ? "border-emerald-500/30 bg-emerald-500/5"
                : health.status === "degraded"
                  ? "border-yellow-500/30 bg-yellow-500/5"
                  : "border-red-500/30 bg-red-500/5"
            }`}
          >
            {health.status === "healthy" ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            ) : health.status === "degraded" ? (
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            ) : (
              <XCircle className="w-5 h-5 text-red-400" />
            )}
            <span
              className={`text-sm font-semibold ${
                health.status === "healthy"
                  ? "text-emerald-400"
                  : health.status === "degraded"
                    ? "text-yellow-400"
                    : "text-red-400"
              }`}
            >
              System {health.status.charAt(0).toUpperCase() + health.status.slice(1)}
            </span>
            <span className="text-xs text-zinc-500 ml-auto">
              Auto-refresh: 30s
            </span>
          </div>

          {/* Service grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {health.services.map((svc) => (
              <div
                key={svc.name}
                className={`card flex items-center gap-3 ${
                  svc.status === "healthy"
                    ? "border-emerald-500/15"
                    : svc.status === "degraded"
                      ? "border-yellow-500/15"
                      : "border-red-500/15"
                }`}
              >
                <div
                  className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                    svc.status === "healthy"
                      ? "bg-emerald-400"
                      : svc.status === "degraded"
                        ? "bg-yellow-400"
                        : "bg-red-400"
                  }`}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-zinc-200 truncate">
                    {svc.name}
                  </div>
                  {svc.details && (
                    <div className="text-xs text-zinc-500 truncate">
                      {svc.details}
                    </div>
                  )}
                </div>
                {svc.latency_ms !== undefined && (
                  <span className="text-xs text-zinc-500 flex-shrink-0">
                    {svc.latency_ms}ms
                  </span>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// --- Tab 2: SIEM & Ingestion ---

function SIEMTab({ token }: { token: string }) {
  const [cbActive, setCbActive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const configs = await getConfig(token);
        const cb = configs.find(
          (c) => c.config_key === "ingest.circuit_breaker_active"
        );
        setCbActive(cb?.config_value === "true");
      } catch {
        // config may not exist yet
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [token]);

  async function toggleCircuitBreaker(activate: boolean) {
    setSaving(true);
    try {
      await upsertConfig(
        token,
        "ingest.circuit_breaker_active",
        activate ? "true" : "false",
        false
      );
      setCbActive(activate);
    } catch {
      // revert visual state
    } finally {
      setSaving(false);
      setShowModal(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading ingestion config...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-bold text-zinc-100">
        SIEM & Ingestion Controls
      </h2>

      {/* Circuit Breaker Card */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200">
              Ingest Circuit Breaker
            </h3>
            <p className="text-xs text-zinc-500 mt-0.5">
              When active, all incoming alerts are held until the breaker is
              deactivated. Use during maintenance or incident response.
            </p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <span
              className={`badge-${cbActive ? "red" : "green"}`}
            >
              {cbActive ? "ACTIVE" : "INACTIVE"}
            </span>
          </div>
        </div>

        <div className="flex gap-3">
          {!cbActive ? (
            <button
              onClick={() => setShowModal(true)}
              disabled={saving}
              className="btn-danger flex items-center gap-2 text-sm"
            >
              <AlertTriangle className="w-4 h-4" />
              Activate Circuit Breaker
            </button>
          ) : (
            <button
              onClick={() => toggleCircuitBreaker(false)}
              disabled={saving}
              className="btn-primary flex items-center gap-2 text-sm"
            >
              {saving && <Loader2 className="w-4 h-4 animate-spin" />}
              Deactivate Circuit Breaker
            </button>
          )}
        </div>
      </div>

      {/* Ingestion endpoints reference */}
      <div className="card space-y-3">
        <h3 className="text-sm font-semibold text-zinc-200">
          Ingestion Endpoints
        </h3>
        <div className="space-y-2 text-xs">
          <EndpointRow
            method="POST"
            path="/api/v1/ingest/splunk"
            desc="Splunk HEC format"
          />
          <EndpointRow
            method="POST"
            path="/api/v1/ingest/elastic"
            desc="Elastic SIEM webhook"
          />
          <EndpointRow
            method="POST"
            path="/api/v1/tasks"
            desc="Direct task submission"
          />
        </div>
      </div>

      {/* Confirmation Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="card max-w-md w-full mx-4 space-y-4 border-red-500/30">
            <div className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-bold">Confirm Circuit Breaker Activation</h3>
            </div>
            <p className="text-sm text-zinc-400">
              This will immediately halt all alert ingestion. Incoming SIEM
              alerts will be queued but not processed until the breaker is
              deactivated. This action is audited.
            </p>
            <div className="flex justify-end gap-3 pt-2 border-t border-zinc-800">
              <button
                onClick={() => setShowModal(false)}
                className="btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => toggleCircuitBreaker(true)}
                disabled={saving}
                className="btn-danger flex items-center gap-2 text-sm"
              >
                {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                Activate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function EndpointRow({
  method,
  path,
  desc,
}: {
  method: string;
  path: string;
  desc: string;
}) {
  return (
    <div className="flex items-center gap-3 py-1.5 border-b border-zinc-800/50 last:border-0">
      <span className="badge-green font-mono text-[10px]">{method}</span>
      <code className="text-zinc-300 font-mono">{path}</code>
      <span className="text-zinc-500 ml-auto">{desc}</span>
    </div>
  );
}

// --- Tab 3: Configuration ---

function ConfigTab({ token }: { token: string }) {
  const [configs, setConfigs] = useState<ConfigEntry[]>([]);
  const [audit, setAudit] = useState<ConfigAuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [saving, setSaving] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [cfgs, auditLog] = await Promise.all([
        getConfig(token),
        getConfigAudit(token),
      ]);
      setConfigs(cfgs);
      setAudit(auditLog);
    } catch {
      // may not exist yet
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function handleSave(key: string, isSecret: boolean) {
    setSaving(true);
    try {
      await upsertConfig(token, key, editValue, isSecret);
      setEditingKey(null);
      await loadData();
    } catch {
      // error handling
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading configuration...
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Config entries */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-zinc-100">Configuration</h2>
          <button
            onClick={loadData}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {configs.length === 0 ? (
          <div className="card text-center py-8">
            <Settings className="w-8 h-8 text-zinc-600 mx-auto mb-2" />
            <p className="text-sm text-zinc-500">
              No configuration entries found. They will appear here as settings
              are created.
            </p>
          </div>
        ) : (
          <div className="card divide-y divide-zinc-800/50 p-0 overflow-hidden">
            {configs.map((cfg) => (
              <div
                key={cfg.config_key}
                className="flex items-center gap-4 px-4 py-3 hover:bg-zinc-800/30 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="text-sm text-zinc-200 font-mono">
                      {cfg.config_key}
                    </code>
                    {cfg.is_secret && (
                      <span className="badge-yellow text-[10px]">SECRET</span>
                    )}
                  </div>
                  <div className="text-xs text-zinc-500 mt-0.5">
                    Updated{" "}
                    {new Date(cfg.updated_at).toLocaleString()} by{" "}
                    {cfg.updated_by}
                  </div>
                </div>

                {editingKey === cfg.config_key ? (
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <input
                      type="text"
                      value={editValue}
                      onChange={(e) => setEditValue(e.target.value)}
                      className="input-field w-48 text-xs py-1.5"
                      autoFocus
                    />
                    <button
                      onClick={() => handleSave(cfg.config_key, cfg.is_secret)}
                      disabled={saving}
                      className="text-emerald-400 hover:text-emerald-300 transition-colors"
                    >
                      {saving ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Save className="w-4 h-4" />
                      )}
                    </button>
                    <button
                      onClick={() => setEditingKey(null)}
                      className="text-zinc-500 hover:text-zinc-300 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <code className="text-xs text-zinc-400 font-mono max-w-[200px] truncate">
                      {cfg.is_secret ? "********" : cfg.config_value}
                    </code>
                    {!cfg.is_secret && (
                      <button
                        onClick={() => {
                          setEditingKey(cfg.config_key);
                          setEditValue(cfg.config_value);
                        }}
                        className="text-zinc-600 hover:text-zinc-400 transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Audit log */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-zinc-100">Audit Log</h2>

        {audit.length === 0 ? (
          <div className="card text-center py-8">
            <Clock className="w-8 h-8 text-zinc-600 mx-auto mb-2" />
            <p className="text-sm text-zinc-500">
              No audit entries yet. Changes to configuration will be logged here.
            </p>
          </div>
        ) : (
          <div className="card divide-y divide-zinc-800/50 p-0 overflow-hidden max-h-[400px] overflow-y-auto">
            {audit.map((entry) => (
              <div
                key={entry.id}
                className="px-4 py-3 hover:bg-zinc-800/30 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <code className="text-xs font-semibold text-zinc-200 font-mono">
                    {entry.config_key}
                  </code>
                  <span className="text-xs text-zinc-600">
                    <span className="line-through text-zinc-600">
                      {entry.old_value || "(empty)"}
                    </span>
                    {" -> "}
                    <span className="text-zinc-300">{entry.new_value}</span>
                  </span>
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-zinc-500">
                  <span className="flex items-center gap-1">
                    <User className="w-3 h-3" />
                    {entry.changed_by}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(entry.changed_at).toLocaleString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
