import { useState, useEffect, useRef, useCallback } from "react";
import {
  Zap,
  Square,
  AlertTriangle,
  Activity,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  forgeStart,
  forgeStatus,
  forgeStop,
  forgeHistory,
} from "../lib/api";
import type { ForgeConfig, ForgeJob } from "../lib/api";

interface AlertForgeProps {
  token: string;
}

const VERDICT_COLORS: Record<string, string> = {
  true_positive: "#ef4444",
  false_positive: "#eab308",
  benign: "#10b981",
  suspicious: "#f97316",
  needs_manual_review: "#3b82f6",
};

const DEFAULT_CONFIG: ForgeConfig = {
  total_alerts: 500,
  attack_ratio: 70,
  novelty_rate: 10,
  campaign_mode: false,
  rate_per_second: 5,
  include_benign: true,
};

export default function AlertForge({ token }: AlertForgeProps) {
  const [config, setConfig] = useState<ForgeConfig>({ ...DEFAULT_CONFIG });
  const [running, setRunning] = useState(false);
  const [currentJob, setCurrentJob] = useState<ForgeJob | null>(null);
  const [history, setHistory] = useState<ForgeJob[]>([]);
  const [error, setError] = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sseRef = useRef<EventSource | null>(null);

  // Load history on mount
  useEffect(() => {
    loadHistory();
  }, [token]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (sseRef.current) sseRef.current.close();
    };
  }, []);

  async function loadHistory() {
    try {
      const jobs = await forgeHistory(token);
      setHistory(jobs);
    } catch {
      // History may not be available
    }
  }

  const pollJob = useCallback(
    async (jobId: string) => {
      try {
        const job = await forgeStatus(token, jobId);
        setCurrentJob(job);
        if (
          job.status === "completed" ||
          job.status === "stopped" ||
          job.status === "error"
        ) {
          setRunning(false);
          if (pollRef.current) clearInterval(pollRef.current);
          if (sseRef.current) sseRef.current.close();
          loadHistory();
        }
      } catch {
        // Retry on next tick
      }
    },
    [token]
  );

  async function handleStart() {
    setError("");
    setRunning(true);
    setCurrentJob(null);

    try {
      const resp = await forgeStart(token, {
        ...config,
        attack_ratio: config.attack_ratio / 100,
        novelty_rate: config.novelty_rate / 100,
      });
      const jobId = resp.job_id;

      // Start SSE connection for real-time updates
      const baseUrl =
        import.meta.env.VITE_API_URL || window.location.origin;
      let reconnectAttempts = 0;
      const connectSSE = () => {
        const sseUrl = `${baseUrl}/api/v1/admin/forge/${jobId}/stream?token=${encodeURIComponent(token)}`;
        sseRef.current = new EventSource(sseUrl);

        sseRef.current.onmessage = (event) => {
          reconnectAttempts = 0; // Reset on successful message
          try {
            const parsed = JSON.parse(event.data) as ForgeJob;
            setCurrentJob(parsed);
            if (
              parsed.status === "completed" ||
              parsed.status === "stopped" ||
              parsed.status === "error"
            ) {
              setRunning(false);
              if (pollRef.current) clearInterval(pollRef.current);
              sseRef.current?.close();
              loadHistory();
            }
          } catch {
            // Ignore parse errors
          }
        };

        sseRef.current.onerror = () => {
          sseRef.current?.close();
          // Reconnect with exponential backoff, max 5 attempts
          if (reconnectAttempts < 5) {
            reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 10000);
            setTimeout(() => connectSSE(), delay);
          }
        };
      };
      connectSSE();

      // Polling fallback (always runs alongside SSE for reliability)
      pollRef.current = setInterval(() => pollJob(jobId), 2000);

      // Initial poll
      pollJob(jobId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start forge");
      setRunning(false);
    }
  }

  async function handleStop() {
    if (!currentJob) return;
    try {
      await forgeStop(token, currentJob.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop forge");
    }
  }

  function updateConfig<K extends keyof ForgeConfig>(
    key: K,
    value: ForgeConfig[K]
  ) {
    setConfig((prev) => ({ ...prev, [key]: value }));
  }

  const results = currentJob?.results;
  const verdictChartData = results?.verdicts
    ? Object.entries(results.verdicts).map(([name, value]) => ({
        name,
        value,
        fill: VERDICT_COLORS[name] || "#71717a",
      }))
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
          <Zap className="w-5 h-5 text-emerald-400" />
          Alert Forge
        </h2>
        <p className="text-xs text-zinc-500 mt-1">
          Generate synthetic alert loads to stress-test the investigation
          pipeline
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LEFT: Config controls */}
        <div className="space-y-4">
          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-zinc-200">
              Configuration
            </h3>

            {/* Total Alerts */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-zinc-400">Total Alerts</label>
                <span className="text-xs font-bold text-zinc-200">
                  {config.total_alerts}
                </span>
              </div>
              <input
                type="range"
                min={100}
                max={10000}
                step={100}
                value={config.total_alerts}
                onChange={(e) =>
                  updateConfig("total_alerts", Number(e.target.value))
                }
                disabled={running}
                className="w-full accent-emerald-500"
              />
              <div className="flex justify-between text-[10px] text-zinc-600">
                <span>100</span>
                <span>10,000</span>
              </div>
            </div>

            {/* Attack Ratio */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-zinc-400">Attack Ratio</label>
                <span className="text-xs font-bold text-zinc-200">
                  {config.attack_ratio}%
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={config.attack_ratio}
                onChange={(e) =>
                  updateConfig("attack_ratio", Number(e.target.value))
                }
                disabled={running}
                className="w-full accent-emerald-500"
              />
              <div className="flex justify-between text-[10px] text-zinc-600">
                <span>0% (all benign)</span>
                <span>100% (all attack)</span>
              </div>
            </div>

            {/* Novelty Rate */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-zinc-400">Novelty Rate</label>
                <span className="text-xs font-bold text-zinc-200">
                  {config.novelty_rate}%
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={config.novelty_rate}
                onChange={(e) =>
                  updateConfig("novelty_rate", Number(e.target.value))
                }
                disabled={running}
                className="w-full accent-emerald-500"
              />
              <div className="flex justify-between text-[10px] text-zinc-600">
                <span>0% (known types)</span>
                <span>100% (novel)</span>
              </div>
            </div>

            {/* Rate per second */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-zinc-400">Rate / sec</label>
                <span className="text-xs font-bold text-zinc-200">
                  {config.rate_per_second}
                </span>
              </div>
              <input
                type="range"
                min={1}
                max={10}
                step={1}
                value={config.rate_per_second}
                onChange={(e) =>
                  updateConfig("rate_per_second", Number(e.target.value))
                }
                disabled={running}
                className="w-full accent-emerald-500"
              />
              <div className="flex justify-between text-[10px] text-zinc-600">
                <span>1/s</span>
                <span>10/s</span>
              </div>
            </div>

            {/* Checkboxes */}
            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.campaign_mode}
                  onChange={(e) =>
                    updateConfig("campaign_mode", e.target.checked)
                  }
                  disabled={running}
                  className="accent-emerald-500"
                />
                Campaign Mode
              </label>
              <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.include_benign}
                  onChange={(e) =>
                    updateConfig("include_benign", e.target.checked)
                  }
                  disabled={running}
                  className="accent-emerald-500"
                />
                Include Benign
              </label>
            </div>

            {/* Action buttons */}
            <div className="flex gap-3 pt-2 border-t border-zinc-800">
              {!running ? (
                <button
                  onClick={handleStart}
                  className="btn-primary flex items-center gap-2 text-sm flex-1"
                >
                  <Zap className="w-4 h-4" />
                  Start Forge
                </button>
              ) : (
                <button
                  onClick={handleStop}
                  className="btn-danger flex items-center gap-2 text-sm flex-1"
                >
                  <Square className="w-4 h-4" />
                  Stop
                </button>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: Progress + results */}
        <div className="space-y-4">
          {currentJob ? (
            <>
              {/* Job header */}
              <div className="card space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-zinc-500">Job</span>
                    <code className="text-xs text-zinc-300 font-mono">
                      {currentJob.id.slice(0, 8)}
                    </code>
                  </div>
                  <span
                    className={`badge-${
                      currentJob.status === "completed"
                        ? "green"
                        : currentJob.status === "running"
                          ? "yellow"
                          : currentJob.status === "error"
                            ? "red"
                            : "zinc"
                    }`}
                  >
                    {currentJob.status.toUpperCase()}
                  </span>
                </div>

                {/* Progress bar */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-zinc-500">Progress</span>
                    <span className="text-xs font-bold text-zinc-200">
                      {Math.round(currentJob.progress)}%
                    </span>
                  </div>
                  <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full transition-all duration-300"
                      style={{ width: `${currentJob.progress}%` }}
                    />
                  </div>
                </div>

                {/* Verdict counters */}
                {results?.verdicts && (
                  <div className="grid grid-cols-3 gap-2 pt-2 border-t border-zinc-800">
                    {Object.entries(results.verdicts).map(
                      ([verdict, count]) => (
                        <div key={verdict} className="text-center">
                          <p
                            className="text-sm font-bold"
                            style={{
                              color: VERDICT_COLORS[verdict] || "#a1a1aa",
                            }}
                          >
                            {count}
                          </p>
                          <p className="text-[10px] text-zinc-500 truncate">
                            {verdict.replace(/_/g, " ")}
                          </p>
                        </div>
                      )
                    )}
                  </div>
                )}
              </div>

              {/* Stats */}
              {results && (
                <div className="card">
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <StatItem
                      label="Submitted"
                      value={String(results.total_submitted)}
                    />
                    <StatItem
                      label="Completed"
                      value={String(results.total_completed)}
                    />
                    <StatItem
                      label="Avg Latency"
                      value={`${results.avg_latency_ms}ms`}
                    />
                    <StatItem
                      label="P95 Latency"
                      value={`${results.p95_latency_ms}ms`}
                    />
                    <StatItem
                      label="Separation Gap"
                      value={results.separation_gap.toFixed(1)}
                      highlight={results.separation_gap >= 40}
                    />
                    <StatItem
                      label="Dedup Count"
                      value={String(results.dedup_count)}
                    />
                    <StatItem
                      label="Novel Variants"
                      value={String(results.novel_variants)}
                    />
                    <StatItem
                      label="Errors"
                      value={String(results.error_count)}
                      danger={results.error_count > 0}
                    />
                    {results.duration && (
                      <StatItem
                        label="Duration"
                        value={results.duration}
                        colSpan2
                      />
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="card flex flex-col items-center justify-center py-12 text-center">
              <Activity className="w-8 h-8 text-zinc-700 mb-3" />
              <p className="text-sm text-zinc-500">
                Configure and start a forge run to see results here
              </p>
              <p className="text-xs text-zinc-600 mt-1">
                Alerts will be injected through the full investigation pipeline
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Bottom: Verdict chart */}
      {verdictChartData.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-zinc-200 mb-4">
            Verdict Distribution
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={verdictChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis
                dataKey="name"
                tick={{ fill: "#a1a1aa", fontSize: 10 }}
                tickFormatter={(v: string) => v.replace(/_/g, " ")}
                stroke="#3f3f46"
              />
              <YAxis tick={{ fill: "#a1a1aa", fontSize: 10 }} stroke="#3f3f46" />
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
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {verdictChartData.map((entry, idx) => (
                  <Cell key={idx} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="card">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center justify-between w-full"
          >
            <h3 className="text-sm font-semibold text-zinc-200">
              Recent Jobs ({history.length})
            </h3>
            {showHistory ? (
              <ChevronUp className="w-4 h-4 text-zinc-500" />
            ) : (
              <ChevronDown className="w-4 h-4 text-zinc-500" />
            )}
          </button>
          {showHistory && (
            <div className="mt-3 space-y-2">
              {history.slice(0, 5).map((job) => (
                <div
                  key={job.id}
                  className="flex items-center justify-between py-2 border-b border-zinc-800/50 last:border-0 text-xs"
                >
                  <div className="flex items-center gap-2">
                    <code className="text-zinc-400 font-mono">
                      {job.id.slice(0, 8)}
                    </code>
                    <span
                      className={`badge-${
                        job.status === "completed"
                          ? "green"
                          : job.status === "error"
                            ? "red"
                            : "zinc"
                      }`}
                    >
                      {job.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-zinc-500">
                    {job.results && (
                      <>
                        <span>{job.results.total_completed} alerts</span>
                        <span>{job.results.duration}</span>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatItem({
  label,
  value,
  highlight,
  danger,
  colSpan2,
}: {
  label: string;
  value: string;
  highlight?: boolean;
  danger?: boolean;
  colSpan2?: boolean;
}) {
  return (
    <div className={colSpan2 ? "col-span-2" : ""}>
      <span className="text-zinc-500 block">{label}</span>
      <span
        className={`font-bold ${
          danger
            ? "text-red-400"
            : highlight
              ? "text-emerald-400"
              : "text-zinc-200"
        }`}
      >
        {value}
      </span>
    </div>
  );
}
