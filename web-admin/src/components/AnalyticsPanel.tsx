import { useState, useEffect, useCallback } from "react";
import {
  Loader2,
  AlertTriangle,
  RefreshCw,
  TrendingUp,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { analyticsSummary, pipelineStatus } from "../lib/api";
import type { PipelineStatus } from "../lib/api";

interface AnalyticsPanelProps {
  token: string;
}

const VERDICT_COLORS: Record<string, string> = {
  true_positive: "#ef4444",
  false_positive: "#eab308",
  benign: "#10b981",
  suspicious: "#f97316",
  needs_manual_review: "#3b82f6",
};

const FALLBACK_COLORS = [
  "#8b5cf6",
  "#ec4899",
  "#06b6d4",
  "#84cc16",
  "#f59e0b",
];

interface SummaryData {
  verdicts: Record<string, number>;
  risk_buckets: Record<string, number>;
  top_attacks: Array<{ name: string; count: number; avg_risk: number }>;
  avg_attack_risk: number;
  avg_benign_risk: number;
  separation_gap: number;
  hours: number;
  exclude_forge: boolean;
}

const TIME_RANGES = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];

export default function AnalyticsPanel({ token }: AnalyticsPanelProps) {
  const [hours, setHours] = useState(24);
  const [excludeForge, setExcludeForge] = useState(false);
  const [data, setData] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [pipeline, setPipeline] = useState<PipelineStatus | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await analyticsSummary(token, hours, excludeForge);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load analytics");
    } finally {
      setLoading(false);
    }
  }, [token, hours, excludeForge]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Pipeline status polling (10s)
  useEffect(() => {
    const fetchPipeline = () => {
      pipelineStatus(token).then(setPipeline).catch(() => {});
    };
    fetchPipeline();
    const id = setInterval(fetchPipeline, 10000);
    return () => clearInterval(id);
  }, [token]);

  const verdictPieData = data?.verdicts
    ? Object.entries(data.verdicts).map(([name, value]) => ({
        name: name.replace(/_/g, " "),
        value,
        fill: VERDICT_COLORS[name] || FALLBACK_COLORS[0],
      }))
    : [];

  const typeBarData = data?.top_attacks
    ? data.top_attacks.slice(0, 10).map((t) => ({
        name: t.name.replace(/_/g, " "),
        risk: Math.round(t.avg_risk * 10) / 10,
        count: t.count,
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-emerald-400" />
            Analytics
          </h2>
          <p className="text-xs text-zinc-500 mt-1">
            Investigation pipeline performance and verdict distribution
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Time range */}
          <div className="flex bg-zinc-900 border border-zinc-800 rounded-md overflow-hidden">
            {TIME_RANGES.map((tr) => (
              <button
                key={tr.hours}
                onClick={() => setHours(tr.hours)}
                className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                  hours === tr.hours
                    ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {tr.label}
              </button>
            ))}
          </div>

          {/* Exclude forge */}
          <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
            <input
              type="checkbox"
              checked={excludeForge}
              onChange={(e) => setExcludeForge(e.target.checked)}
              className="accent-emerald-500"
            />
            Exclude Forge
          </label>

          {/* Refresh */}
          <button
            onClick={fetchData}
            disabled={loading}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <RefreshCw
              className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
            />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Pipeline status indicator */}
      {pipeline && (
        <div className="card flex items-center gap-4 py-2 px-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                pipeline.active > 0
                  ? "bg-emerald-500 animate-pulse"
                  : "bg-zinc-600"
              }`}
            />
            <span className="text-zinc-400">Pipeline</span>
          </div>
          <span className="text-zinc-300">
            Active: <strong>{pipeline.active}</strong>
          </span>
          <span className="text-zinc-300">
            Completed: <strong>{pipeline.completed}</strong>
            <span className="text-zinc-600"> (5m)</span>
          </span>
          {pipeline.errors > 0 && (
            <span className="text-red-400">
              Errors: <strong>{pipeline.errors}</strong>
            </span>
          )}
          <span className="text-zinc-300">
            Throughput:{" "}
            <strong>{pipeline.throughput_per_min.toFixed(1)}/min</strong>
          </span>
        </div>
      )}

      {loading && !data ? (
        <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading analytics...
        </div>
      ) : data ? (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <SummaryCard label="Total Investigations" value={String(data.verdicts ? Object.values(data.verdicts).reduce((a, b) => a + b, 0) : 0)} />
            <SummaryCard
              label="Separation Gap"
              value={data.separation_gap.toFixed(1)}
              badge={
                data.separation_gap >= 40
                  ? "green"
                  : data.separation_gap >= 20
                    ? "yellow"
                    : "red"
              }
              badgeLabel={
                data.separation_gap >= 40
                  ? "GOOD"
                  : data.separation_gap >= 20
                    ? "MARGINAL"
                    : "POOR"
              }
            />
            <SummaryCard
              label="Attack Count"
              value={String(
                (data.verdicts["true_positive"] || 0) +
                  (data.verdicts["suspicious"] || 0)
              )}
            />
            <SummaryCard
              label="Benign Count"
              value={String(data.verdicts["benign"] || 0)}
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Verdict pie chart */}
            <div className="card">
              <h3 className="text-sm font-semibold text-zinc-200 mb-4">
                Verdict Distribution
              </h3>
              {verdictPieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie
                      data={verdictPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={90}
                      dataKey="value"
                      paddingAngle={2}
                      stroke="#18181b"
                      strokeWidth={2}
                    >
                      {verdictPieData.map((entry, idx) => (
                        <Cell key={idx} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#18181b",
                        border: "1px solid #3f3f46",
                        borderRadius: "6px",
                        fontSize: "12px",
                      }}
                      labelStyle={{ color: "#e4e4e7" }}
                      itemStyle={{ color: "#a1a1aa" }}
                    />
                    <Legend
                      verticalAlign="bottom"
                      height={36}
                      formatter={(value: string) => (
                        <span className="text-xs text-zinc-400">{value}</span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <EmptyChart message="No verdict data available" />
              )}
            </div>

            {/* Risk by attack type bar chart */}
            <div className="card">
              <h3 className="text-sm font-semibold text-zinc-200 mb-4">
                Avg Risk by Attack Type
              </h3>
              {typeBarData.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart
                    data={typeBarData}
                    layout="vertical"
                    margin={{ left: 10 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#27272a"
                      horizontal={false}
                    />
                    <XAxis
                      type="number"
                      domain={[0, 100]}
                      tick={{ fill: "#a1a1aa", fontSize: 10 }}
                      stroke="#3f3f46"
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={120}
                      tick={{ fill: "#a1a1aa", fontSize: 10 }}
                      stroke="#3f3f46"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#18181b",
                        border: "1px solid #3f3f46",
                        borderRadius: "6px",
                        fontSize: "12px",
                      }}
                      labelStyle={{ color: "#e4e4e7" }}
                      itemStyle={{ color: "#a1a1aa" }}
                      formatter={(value: number) => [
                        `${value.toFixed(1)}`,
                        "Avg Risk",
                      ]}
                    />
                    <Bar dataKey="risk" fill="#10b981" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyChart message="No attack type data available" />
              )}
            </div>
          </div>

          {/* Risk distribution buckets */}
          {data.risk_buckets &&
            Object.keys(data.risk_buckets).length > 0 && (
              <div className="card">
                <h3 className="text-sm font-semibold text-zinc-200 mb-3">
                  Risk Score Distribution
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-500">
                        <th className="text-left py-2 pr-4">Risk Range</th>
                        <th className="text-right py-2 pr-4">Count</th>
                        <th className="text-left py-2" style={{ width: "50%" }}>
                          &nbsp;
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {["0-20", "21-40", "41-60", "61-80", "81-100"].map(
                        (bucket) => {
                          const count = data.risk_buckets[bucket] || 0;
                          const maxCount = Math.max(
                            ...Object.values(data.risk_buckets)
                          );
                          const pct =
                            maxCount > 0 ? (count / maxCount) * 100 : 0;
                          const color =
                            bucket === "81-100"
                              ? "bg-red-500"
                              : bucket === "61-80"
                                ? "bg-orange-500"
                                : bucket === "41-60"
                                  ? "bg-yellow-500"
                                  : bucket === "21-40"
                                    ? "bg-blue-500"
                                    : "bg-emerald-500";
                          return (
                            <tr
                              key={bucket}
                              className="border-b border-zinc-800/50"
                            >
                              <td className="py-2 pr-4">
                                <code className="text-zinc-300 font-mono">
                                  {bucket}
                                </code>
                              </td>
                              <td className="py-2 pr-4 text-right text-zinc-400">
                                {count}
                              </td>
                              <td className="py-2">
                                <div className="w-full bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                                  <div
                                    className={`h-full ${color} rounded-full`}
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                              </td>
                            </tr>
                          );
                        }
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
        </>
      ) : null}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  badge,
  badgeLabel,
}: {
  label: string;
  value: string;
  badge?: "green" | "yellow" | "red";
  badgeLabel?: string;
}) {
  return (
    <div className="card">
      <span className="text-xs text-zinc-500">{label}</span>
      <div className="flex items-center gap-2 mt-1">
        <span className="text-xl font-bold text-zinc-100">{value}</span>
        {badge && badgeLabel && (
          <span className={`badge-${badge}`}>{badgeLabel}</span>
        )}
      </div>
    </div>
  );
}

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center h-[240px] text-xs text-zinc-600">
      {message}
    </div>
  );
}
