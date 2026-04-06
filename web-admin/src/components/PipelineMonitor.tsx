import { useState, useEffect, useRef, useCallback } from "react";
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

function stageBadgeColor(count: number): string {
  if (count === 0) return "bg-zinc-700 text-zinc-500";
  if (count <= 3) return "bg-emerald-500/20 text-emerald-400";
  if (count <= 10) return "bg-yellow-500/20 text-yellow-400";
  return "bg-red-500/20 text-red-400";
}

function formatLatency(ms: number): string {
  return (ms / 1000).toFixed(1) + "s";
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

function timeAgo(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function PipelineMonitor({
  token,
  isForgeRunning = false,
}: PipelineMonitorProps) {
  const [data, setData] = useState<PipelineStatus | null>(null);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
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

  return (
    <div className="space-y-4">
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
            Updated {timeAgo(lastUpdated.toISOString())}
          </span>
        )}
      </div>

      {/* Row 2: Key metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <MetricCard
          label="Throughput"
          value={`${data.throughput_per_min.toFixed(1)}/min`}
        />
        <MetricCard
          label="Avg Latency"
          value={formatLatency(data.avg_latency_ms)}
        />
        <MetricCard
          label="P95 Latency"
          value={formatLatency(data.p95_latency_ms)}
        />
        <MetricCard label="24h Total" value={formatNumber(data.total_24h)} />
      </div>

      {/* Row 3: Pipeline stage flow */}
      <div className="card py-3 px-2">
        <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2 px-1">
          Pipeline Stages
        </h3>
        <div className="flex items-center justify-between gap-1 overflow-x-auto">
          {STAGES.map((stage, idx) => {
            const count = data.active > 0 && idx < 4 ? Math.max(0, Math.floor(data.active / STAGES.length) + (idx < (data.active % STAGES.length) ? 1 : 0)) : 0;
            return (
              <div key={stage} className="flex items-center gap-1 flex-shrink-0">
                <div
                  className={`rounded px-2 py-1 text-center min-w-[60px] ${stageBadgeColor(count)}`}
                >
                  <div className="text-[10px] uppercase tracking-wider">
                    {stage}
                  </div>
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

      {/* Row 4: Verdict donut + Risk bars */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="card">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
            Verdicts ({data.completed} in window)
          </h3>
          {verdictData.length > 0 ? (
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie
                  data={verdictData}
                  cx="50%"
                  cy="50%"
                  innerRadius={30}
                  outerRadius={55}
                  dataKey="value"
                  paddingAngle={2}
                  stroke="#18181b"
                  strokeWidth={2}
                >
                  {verdictData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#18181b",
                    border: "1px solid #3f3f46",
                    borderRadius: "6px",
                    fontSize: "11px",
                  }}
                  labelStyle={{ color: "#e4e4e7" }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[140px] text-xs text-zinc-600">
              No completions
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
            Risk Distribution
          </h3>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height={140}>
              <BarChart
                data={riskData}
                layout="vertical"
                margin={{ left: 0, right: 10 }}
              >
                <XAxis
                  type="number"
                  tick={{ fill: "#71717a", fontSize: 9 }}
                  stroke="#3f3f46"
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={55}
                  tick={{ fill: "#a1a1aa", fontSize: 9 }}
                  stroke="#3f3f46"
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#18181b",
                    border: "1px solid #3f3f46",
                    borderRadius: "6px",
                    fontSize: "11px",
                  }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {riskData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[140px] text-xs text-zinc-600">
              No attack data
            </div>
          )}
        </div>
      </div>

      {/* Row 5: Activity log */}
      {data.recent.length > 0 && (
        <div className="card py-2 px-3">
          <h3 className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">
            Recent Investigations
          </h3>
          <div className="space-y-0.5 max-h-[200px] overflow-y-auto font-mono text-[11px]">
            {data.recent.map((r, i) => {
              const t = new Date(r.completed_at);
              const ts = t.toLocaleTimeString("en-US", { hour12: false });
              const vColor =
                r.verdict === "true_positive"
                  ? "text-red-400"
                  : r.verdict === "benign"
                    ? "text-emerald-400"
                    : r.verdict === "suspicious"
                      ? "text-yellow-400"
                      : "text-blue-400";
              return (
                <div
                  key={i}
                  className="flex items-center gap-2 py-0.5 border-b border-zinc-800/30 last:border-0"
                >
                  <span className="text-zinc-600 flex-shrink-0">{ts}</span>
                  <span className="text-zinc-400 truncate max-w-[110px]">
                    {r.task_type}
                  </span>
                  <span className="text-zinc-700">&#x2192;</span>
                  <span className={`${vColor} flex-shrink-0`}>
                    {r.verdict.replace(/_/g, " ")}
                  </span>
                  <span className="text-zinc-500 flex-shrink-0">
                    risk:{r.risk_score}
                  </span>
                  <span className="text-zinc-600 flex-shrink-0 ml-auto">
                    {r.latency_s}s
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="card py-2 px-3">
      <span className="text-[10px] text-zinc-500 block">{label}</span>
      <span className="text-lg font-bold text-zinc-100 font-mono transition-all duration-300">
        {value}
      </span>
    </div>
  );
}
