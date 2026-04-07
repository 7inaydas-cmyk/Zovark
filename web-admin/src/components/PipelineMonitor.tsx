import { useState, useEffect, useRef, useCallback } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
} from "recharts";
import { pipelineStatus } from "../lib/api";
import type { PipelineStatus } from "../lib/api";

interface PipelineMonitorProps {
  token: string;
  isForgeRunning?: boolean;
}

const VERDICT_COLORS: Record<string, string> = {
  true_positive: "#ef4444",
  benign: "#10b981",
  suspicious: "#f59e0b",
  needs_manual_review: "#6366f1",
  pending: "#8b5cf6",
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#10b981",
};

const STAGES = ["ingest", "analyze", "execute", "assess", "govern", "store"];

const DARK_TOOLTIP = {
  contentStyle: {
    backgroundColor: "#18181b",
    border: "1px solid #3f3f46",
    borderRadius: "6px",
    fontSize: "11px",
  },
  labelStyle: { color: "#e4e4e7" },
};

function stageBadgeColor(count: number): string {
  if (count === 0) return "bg-zinc-700 text-zinc-500";
  if (count <= 3) return "bg-emerald-500/20 text-emerald-400";
  if (count <= 10) return "bg-yellow-500/20 text-yellow-400";
  return "bg-red-500/20 text-red-400";
}

function fmtLat(ms: number): string {
  return (ms / 1000).toFixed(1) + "s";
}

function fmtNum(n: number): string {
  return n.toLocaleString();
}

function timeAgo(ts: string): string {
  const d = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (d < 5) return "just now";
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}

function riskColor(avg: number): string {
  if (avg >= 85) return "text-emerald-400";
  if (avg >= 65) return "text-yellow-400";
  return "text-red-400";
}

function stddevColor(s: number): string {
  if (s < 5) return "text-emerald-400";
  if (s <= 15) return "text-yellow-400";
  return "text-red-400";
}

function latColor(s: number): string {
  if (s < 2) return "text-emerald-400";
  if (s <= 5) return "text-yellow-400";
  return "text-red-400";
}

export default function PipelineMonitor({
  token,
  isForgeRunning = false,
}: PipelineMonitorProps) {
  const [data, setData] = useState<PipelineStatus | null>(null);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const result = await pipelineStatus(token);
      setData(result);
      setLastUpdated(new Date());
      setError("");
    } catch {
      setError("Connection lost");
    }
  }, [token]);

  useEffect(() => {
    fetchStatus();
    const ms = isForgeRunning || (data && data.active > 0) ? 3000 : 10000;
    intervalRef.current = setInterval(fetchStatus, ms);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchStatus, isForgeRunning, data?.active]);

  if (!data) {
    return (
      <div className="card flex items-center justify-center py-12 text-xs text-zinc-500">
        Loading pipeline status...
      </div>
    );
  }

  const verdictData = Object.entries(data.verdict_distribution)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({
      name: name.replace(/_/g, " "),
      value,
      fill: VERDICT_COLORS[name] || "#71717a",
    }));

  const riskData = ["critical", "high", "medium", "low"]
    .map((level) => ({
      name: level.charAt(0).toUpperCase() + level.slice(1),
      value: data.risk_distribution[level] || 0,
      fill: RISK_COLORS[level],
    }))
    .filter((d) => d.value > 0);

  const dedupPct = data.dedup_stats?.dedup_rate
    ? (data.dedup_stats.dedup_rate * 100).toFixed(0)
    : "0";

  return (
    <div className="space-y-3">
      {/* Row 1: Status bar */}
      <div className="card flex items-center justify-between py-2 px-3">
        <div className="flex items-center gap-2">
          {error ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span className="text-xs text-red-400">{error}</span>
            </>
          ) : data.errors > 0 ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
              <span className="text-xs text-red-400">
                Pipeline Errors — {data.errors} failed
              </span>
            </>
          ) : data.active > 0 ? (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs text-emerald-400">
                Pipeline Active — {data.active} processing
              </span>
            </>
          ) : (
            <>
              <span className="w-2.5 h-2.5 rounded-full bg-zinc-600" />
              <span className="text-xs text-zinc-500">Pipeline Idle</span>
            </>
          )}
        </div>
        {lastUpdated && (
          <span className="text-[10px] text-zinc-600">
            {timeAgo(lastUpdated.toISOString())}
          </span>
        )}
      </div>

      {/* Row 2: 6 metric cards */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        <MetricCard label="Throughput" value={`${data.throughput_per_min.toFixed(1)}/min`} />
        <MetricCard label="Avg Latency" value={fmtLat(data.avg_latency_ms)} />
        <MetricCard label="P95 Latency" value={fmtLat(data.p95_latency_ms)} />
        <MetricCard label="24h Total" value={fmtNum(data.total_24h)} />
        <MetricCard
          label="Queue"
          value={String(data.queue_depth)}
          color={data.queue_depth > 50 ? "text-red-400" : data.queue_depth > 20 ? "text-yellow-400" : undefined}
        />
        <MetricCard
          label="Dedup"
          value={`${dedupPct}%`}
          sub={`${data.dedup_stats?.blocked_last_5m ?? 0} blocked`}
        />
      </div>

      {/* Row 3: Pipeline stages */}
      <div className="card py-3 px-2">
        <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2 px-1">
          Pipeline Stages
        </h3>
        <div className="flex items-center justify-between gap-1 overflow-x-auto">
          {STAGES.map((stage, idx) => {
            const count =
              data.active > 0 && idx < 4
                ? Math.max(
                    0,
                    Math.floor(data.active / STAGES.length) +
                      (idx < data.active % STAGES.length ? 1 : 0)
                  )
                : 0;
            return (
              <div key={stage} className="flex items-center gap-1 flex-shrink-0">
                <div className={`rounded px-2 py-1 text-center min-w-[55px] ${stageBadgeColor(count)}`}>
                  <div className="text-[9px] uppercase tracking-wider">{stage}</div>
                  <div className="text-sm font-bold font-mono">{count}</div>
                </div>
                {idx < STAGES.length - 1 && (
                  <span className="text-zinc-700 text-xs">&#x2192;</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Row 3.5: Sparkline charts */}
      {(data.throughput_series?.length > 0 || data.latency_series?.length > 0) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {data.throughput_series?.length > 0 && (
            <div className="card py-2 px-3">
              <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
                Throughput (30m)
              </h3>
              <ResponsiveContainer width="100%" height={100}>
                <AreaChart data={data.throughput_series} margin={{ top: 5, right: 5, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="tpFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Tooltip {...DARK_TOOLTIP} formatter={(v: number) => [`${v}`, "Completed"]} />
                  <Area type="monotone" dataKey="value" stroke="#10b981" fill="url(#tpFill)" strokeWidth={1.5} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
          {data.latency_series?.length > 0 && (
            <div className="card py-2 px-3">
              <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
                Latency (30m)
              </h3>
              <ResponsiveContainer width="100%" height={100}>
                <LineChart data={data.latency_series} margin={{ top: 5, right: 5, bottom: 0, left: 0 }}>
                  <Tooltip
                    {...DARK_TOOLTIP}
                    formatter={(v: number, name: string) => [
                      `${(v / 1000).toFixed(1)}s`,
                      name === "avg_ms" ? "Avg" : "P95",
                    ]}
                  />
                  <Line type="monotone" dataKey="avg_ms" stroke="#10b981" strokeWidth={1.5} dot={false} />
                  <Line type="monotone" dataKey="p95_ms" stroke="#ef4444" strokeWidth={1} strokeDasharray="4 2" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* Row 4: Verdict donut + Risk bars */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="card">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
            Verdicts ({data.completed} in window)
          </h3>
          {verdictData.length > 0 ? (
            <ResponsiveContainer width="100%" height={120}>
              <PieChart>
                <Pie data={verdictData} cx="50%" cy="50%" innerRadius={25} outerRadius={48} dataKey="value" paddingAngle={2} stroke="#18181b" strokeWidth={2}>
                  {verdictData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Pie>
                <Tooltip {...DARK_TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[120px] text-xs text-zinc-600">No completions</div>
          )}
        </div>
        <div className="card">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
            Risk Distribution
          </h3>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={riskData} layout="vertical" margin={{ left: 0, right: 10 }}>
                <XAxis type="number" tick={{ fill: "#71717a", fontSize: 9 }} stroke="#3f3f46" />
                <YAxis type="category" dataKey="name" width={55} tick={{ fill: "#a1a1aa", fontSize: 9 }} stroke="#3f3f46" />
                <Tooltip {...DARK_TOOLTIP} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {riskData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[120px] text-xs text-zinc-600">No attack data</div>
          )}
        </div>
      </div>

      {/* Row 4.5: Attack breakdown table */}
      {data.attack_breakdown?.length > 0 && (
        <div className="card py-2 px-3">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">
            Attack Type Breakdown (30m)
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500">
                  <th className="text-left py-1 pr-2">Type</th>
                  <th className="text-right py-1 px-2">Count</th>
                  <th className="text-right py-1 px-2">Avg Risk</th>
                  <th className="text-right py-1 px-2">Min</th>
                  <th className="text-right py-1 px-2">Max</th>
                  <th className="text-right py-1 px-2">Stddev</th>
                  <th className="text-right py-1 pl-2">Latency</th>
                </tr>
              </thead>
              <tbody>
                {data.attack_breakdown.map((a) => (
                  <tr key={a.type} className="border-b border-zinc-800/30">
                    <td className="py-1 pr-2 text-zinc-300">{a.type.replace(/_/g, " ")}</td>
                    <td className="py-1 px-2 text-right text-zinc-400">{a.count}</td>
                    <td className={`py-1 px-2 text-right font-bold ${riskColor(a.avg_risk)}`}>
                      {a.avg_risk.toFixed(1)}
                    </td>
                    <td className="py-1 px-2 text-right text-zinc-500">{a.min_risk}</td>
                    <td className="py-1 px-2 text-right text-zinc-500">{a.max_risk}</td>
                    <td className={`py-1 px-2 text-right ${stddevColor(a.stddev)}`}>
                      {a.stddev.toFixed(1)}
                    </td>
                    <td className={`py-1 pl-2 text-right ${latColor(a.avg_latency_ms / 1000)}`}>
                      {fmtLat(a.avg_latency_ms)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Row 5: Recent investigations */}
      {data.recent.length > 0 && (
        <div className="card py-2 px-3">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">
            Recent Investigations
          </h3>
          <div className="space-y-0.5 max-h-[180px] overflow-y-auto font-mono text-[11px]">
            {data.recent.map((r, i) => {
              const ts = new Date(r.completed_at).toLocaleTimeString("en-US", { hour12: false });
              const vColor = VERDICT_COLORS[r.verdict] || "#71717a";
              return (
                <div key={i} className="flex items-center gap-2 py-0.5 border-b border-zinc-800/30 last:border-0">
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: vColor }} />
                  <span className="text-zinc-600 flex-shrink-0">{ts}</span>
                  <span className="text-zinc-400 truncate max-w-[100px]">{r.task_type}</span>
                  <span className="text-zinc-700">&#x2192;</span>
                  <span className="flex-shrink-0" style={{ color: vColor }}>
                    {r.verdict.replace(/_/g, " ")}
                  </span>
                  <span className="text-zinc-500 flex-shrink-0">risk:{r.risk_score}</span>
                  <span className={`flex-shrink-0 ml-auto ${latColor(r.latency_s)}`}>{r.latency_s}s</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Row 6: Error panel */}
      {data.recent_errors?.length > 0 && (
        <div className="card border-red-500/20 py-2 px-3">
          <button
            onClick={() => setShowErrors(!showErrors)}
            className="flex items-center justify-between w-full"
          >
            <span className="text-xs text-red-400 font-semibold">
              {data.recent_errors.length} Error{data.recent_errors.length > 1 ? "s" : ""}
            </span>
            {showErrors ? (
              <ChevronUp className="w-3.5 h-3.5 text-zinc-500" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
            )}
          </button>
          {showErrors && (
            <div className="mt-2 space-y-1 font-mono text-[11px]">
              {data.recent_errors.map((e, i) => {
                const ts = new Date(e.created_at).toLocaleTimeString("en-US", { hour12: false });
                return (
                  <div key={i} className="text-red-400/80">
                    <span className="text-zinc-600">{ts}</span> — {e.task_type} — {e.error}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  color,
  sub,
}: {
  label: string;
  value: string;
  color?: string;
  sub?: string;
}) {
  return (
    <div className="card py-2 px-2">
      <span className="text-[9px] text-zinc-500 block">{label}</span>
      <span className={`text-base font-bold font-mono transition-all duration-300 ${color || "text-zinc-100"}`}>
        {value}
      </span>
      {sub && <span className="text-[9px] text-zinc-600 block">{sub}</span>}
    </div>
  );
}
