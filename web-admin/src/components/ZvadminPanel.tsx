import { useState } from "react";
import {
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Stethoscope,
  Bell,
  Cpu,
  Copy,
  Database,
  Server,
} from "lucide-react";
import {
  adminDiagnose,
  adminAlerts,
  adminModelCheck,
  adminDedupHealth,
  adminSystemStats,
} from "../lib/api";

interface ZvadminPanelProps {
  token: string;
}

type Command =
  | "diagnose"
  | "alerts"
  | "model-check"
  | "dedup-health"
  | "system-stats";

interface CommandDef {
  id: Command;
  label: string;
  icon: typeof Stethoscope;
  description: string;
}

const COMMANDS: CommandDef[] = [
  {
    id: "diagnose",
    label: "Diagnose",
    icon: Stethoscope,
    description: "Run 8-check health diagnostic",
  },
  {
    id: "alerts",
    label: "Alert Analytics",
    icon: Bell,
    description: "Pipeline stats (last 24h)",
  },
  {
    id: "model-check",
    label: "Model Check",
    icon: Cpu,
    description: "Risk calibration report",
  },
  {
    id: "dedup-health",
    label: "Dedup Health",
    icon: Copy,
    description: "Dedup decision distribution",
  },
  {
    id: "system-stats",
    label: "System Stats",
    icon: Server,
    description: "Task count + Redis memory",
  },
];

export default function ZvadminPanel({ token }: ZvadminPanelProps) {
  const [activeCommand, setActiveCommand] = useState<Command | null>(null);
  const [loading, setLoading] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  async function runCommand(cmd: Command) {
    setActiveCommand(cmd);
    setLoading(true);
    setResult(null);
    setError("");

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let data: any;
      switch (cmd) {
        case "diagnose":
          data = await adminDiagnose(token);
          break;
        case "alerts":
          data = await adminAlerts(token, 24);
          break;
        case "model-check":
          data = await adminModelCheck(token);
          break;
        case "dedup-health":
          data = await adminDedupHealth(token);
          break;
        case "system-stats":
          data = await adminSystemStats(token);
          break;
      }
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Command failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-zinc-100">
          Zvadmin Command Center
        </h2>
        <p className="text-xs text-zinc-500 mt-1">
          Run diagnostic commands against the live Zovark instance
        </p>
      </div>

      {/* Command grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {COMMANDS.map((cmd) => {
          const Icon = cmd.icon;
          const isActive = activeCommand === cmd.id;
          const isLoading = isActive && loading;
          return (
            <button
              key={cmd.id}
              onClick={() => runCommand(cmd.id)}
              disabled={loading}
              className={`card flex flex-col items-start gap-2 text-left transition-all ${
                isActive
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "hover:border-zinc-600"
              } disabled:opacity-60`}
            >
              <div className="flex items-center gap-2">
                {isLoading ? (
                  <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
                ) : (
                  <Icon className="w-4 h-4 text-emerald-400" />
                )}
                <span className="text-sm font-semibold text-zinc-200">
                  {cmd.label}
                </span>
              </div>
              <span className="text-xs text-zinc-500">{cmd.description}</span>
            </button>
          );
        })}
      </div>

      {/* Error */}
      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Results terminal */}
      {result && activeCommand && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-zinc-800 flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
              {activeCommand.replace("-", " ")} result
            </span>
          </div>
          <div className="p-4 font-mono text-sm">
            {activeCommand === "diagnose" && <DiagnoseResult data={result} />}
            {activeCommand === "alerts" && <AlertsResult data={result} />}
            {activeCommand === "model-check" && (
              <ModelCheckResult data={result} />
            )}
            {activeCommand === "dedup-health" && (
              <DedupHealthResult data={result} />
            )}
            {activeCommand === "system-stats" && (
              <SystemStatsResult data={result} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Result renderers ---

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function DiagnoseResult({ data }: { data: any }) {
  const typed = data as {
    checks: Array<{ name: string; status: string; detail: string }>;
    overall: string;
  };
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pb-2 border-b border-zinc-800">
        <span className="text-xs text-zinc-500">Overall:</span>
        <span
          className={`badge-${typed.overall === "healthy" ? "green" : typed.overall === "degraded" ? "yellow" : "red"}`}
        >
          {typed.overall.toUpperCase()}
        </span>
      </div>
      {typed.checks.map((check, i) => (
        <div key={i} className="flex items-start gap-2 py-1">
          {check.status === "pass" || check.status === "healthy" ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
          ) : check.status === "warn" || check.status === "degraded" ? (
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          ) : (
            <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          )}
          <div className="min-w-0">
            <span className="text-zinc-200">{check.name}</span>
            {check.detail && (
              <p className="text-xs text-zinc-500 mt-0.5">{check.detail}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function AlertsResult({ data }: { data: any }) {
  const typed = data as {
    verdicts: Record<string, number>;
    top_types: Array<{ type: string; count: number }>;
    avg_latency_ms: number;
    total: number;
  };
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div>
          <span className="text-xs text-zinc-500">Total Alerts</span>
          <p className="text-lg font-bold text-zinc-100">{typed.total}</p>
        </div>
        <div>
          <span className="text-xs text-zinc-500">Avg Latency</span>
          <p className="text-lg font-bold text-zinc-100">
            {typed.avg_latency_ms}ms
          </p>
        </div>
      </div>

      <div>
        <span className="text-xs text-zinc-500 block mb-2">
          Verdict Distribution
        </span>
        <div className="space-y-1.5">
          {Object.entries(typed.verdicts).map(([verdict, count]) => (
            <div key={verdict} className="flex items-center gap-3">
              <span className="text-xs text-zinc-400 w-32 truncate">
                {verdict}
              </span>
              <div className="flex-1 bg-zinc-800 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-full rounded-full ${verdictColor(verdict)}`}
                  style={{
                    width: `${typed.total > 0 ? (count / typed.total) * 100 : 0}%`,
                  }}
                />
              </div>
              <span className="text-xs text-zinc-400 w-10 text-right">
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>

      {typed.top_types.length > 0 && (
        <div>
          <span className="text-xs text-zinc-500 block mb-2">
            Top Alert Types
          </span>
          <div className="space-y-1">
            {typed.top_types.map((t, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-zinc-300">{t.type}</span>
                <span className="text-zinc-500">{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ModelCheckResult({ data }: { data: any }) {
  const typed = data as {
    types: Array<{
      name: string;
      avg_risk: number;
      attack_count: number;
      benign_count: number;
    }>;
    separation_gap: number;
  };
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-xs text-zinc-500">Separation Gap:</span>
        <span
          className={`text-sm font-bold ${typed.separation_gap >= 40 ? "text-emerald-400" : typed.separation_gap >= 20 ? "text-yellow-400" : "text-red-400"}`}
        >
          {typed.separation_gap.toFixed(1)}
        </span>
        <span
          className={`badge-${typed.separation_gap >= 40 ? "green" : typed.separation_gap >= 20 ? "yellow" : "red"}`}
        >
          {typed.separation_gap >= 40
            ? "GOOD"
            : typed.separation_gap >= 20
              ? "MARGINAL"
              : "POOR"}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-800 text-zinc-500">
              <th className="text-left py-2 pr-4">Type</th>
              <th className="text-right py-2 px-2">Avg Risk</th>
              <th className="text-right py-2 px-2">Attacks</th>
              <th className="text-right py-2 pl-2">Benign</th>
            </tr>
          </thead>
          <tbody>
            {typed.types.map((t, i) => (
              <tr key={i} className="border-b border-zinc-800/50">
                <td className="py-1.5 pr-4 text-zinc-300">{t.name}</td>
                <td className="py-1.5 px-2 text-right">
                  <span
                    className={
                      t.avg_risk >= 70
                        ? "text-red-400"
                        : t.avg_risk >= 40
                          ? "text-yellow-400"
                          : "text-emerald-400"
                    }
                  >
                    {t.avg_risk.toFixed(0)}
                  </span>
                </td>
                <td className="py-1.5 px-2 text-right text-zinc-400">
                  {t.attack_count}
                </td>
                <td className="py-1.5 pl-2 text-right text-zinc-400">
                  {t.benign_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function DedupHealthResult({ data }: { data: any }) {
  const typed = data as {
    decisions: Record<string, number>;
    total: number;
    efficiency: number;
  };
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div>
          <span className="text-xs text-zinc-500">Total Decisions</span>
          <p className="text-lg font-bold text-zinc-100">{typed.total}</p>
        </div>
        <div>
          <span className="text-xs text-zinc-500">Efficiency</span>
          <p className="text-lg font-bold text-emerald-400">
            {(typed.efficiency * 100).toFixed(1)}%
          </p>
        </div>
      </div>

      <div>
        <span className="text-xs text-zinc-500 block mb-2">Decisions</span>
        <div className="space-y-1.5">
          {Object.entries(typed.decisions).map(([decision, count]) => (
            <div key={decision} className="flex items-center gap-3">
              <span className="text-xs text-zinc-400 w-36 truncate">
                {decision}
              </span>
              <div className="flex-1 bg-zinc-800 rounded-full h-2 overflow-hidden">
                <div
                  className="h-full rounded-full bg-emerald-500"
                  style={{
                    width: `${typed.total > 0 ? (count / typed.total) * 100 : 0}%`,
                  }}
                />
              </div>
              <span className="text-xs text-zinc-400 w-10 text-right">
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function SystemStatsResult({ data }: { data: any }) {
  const typed = data as { task_count: number; redis_memory_mb: number };
  return (
    <div className="grid grid-cols-2 gap-4">
      <div className="card">
        <div className="flex items-center gap-2 mb-1">
          <Database className="w-4 h-4 text-emerald-400" />
          <span className="text-xs text-zinc-500">Total Tasks</span>
        </div>
        <p className="text-2xl font-bold text-zinc-100">{typed.task_count}</p>
      </div>
      <div className="card">
        <div className="flex items-center gap-2 mb-1">
          <Server className="w-4 h-4 text-emerald-400" />
          <span className="text-xs text-zinc-500">Redis Memory</span>
        </div>
        <p className="text-2xl font-bold text-zinc-100">
          {typed.redis_memory_mb.toFixed(1)}
          <span className="text-sm text-zinc-500 ml-1">MB</span>
        </p>
      </div>
    </div>
  );
}

function verdictColor(verdict: string): string {
  switch (verdict) {
    case "true_positive":
      return "bg-red-500";
    case "false_positive":
      return "bg-yellow-500";
    case "benign":
      return "bg-emerald-500";
    case "suspicious":
      return "bg-orange-500";
    case "needs_manual_review":
      return "bg-blue-500";
    default:
      return "bg-zinc-500";
  }
}
