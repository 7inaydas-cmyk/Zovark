import { useState, useEffect } from "react";
import {
  Loader2,
  AlertTriangle,
  X,
  Shield,
  Clock,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Wrench,
  Bug,
  FileText,
} from "lucide-react";
import { getTaskDetail } from "../lib/api";

interface InvestigationDetailProps {
  token: string;
  taskId: string;
  onClose: () => void;
}

interface TaskDetail {
  id: string;
  task_type: string;
  status: string;
  created_at: string;
  verdict: string;
  risk_score: number;
  path_taken: string;
  tools_executed: Array<{ name: string; result_summary: string }>;
  findings: string[];
  iocs: Array<{ type: string; value: string }>;
  mitre_attack: Array<{ technique: string; tactic: string; name: string }>;
  summary: string;
  siem_event: Record<string, unknown>;
}

function verdictBadgeClass(verdict: string): string {
  switch (verdict) {
    case "true_positive":
      return "badge-red";
    case "false_positive":
      return "badge-yellow";
    case "benign":
      return "badge-green";
    case "suspicious":
      return "badge-yellow";
    case "needs_manual_review":
      return "badge-zinc";
    default:
      return "badge-zinc";
  }
}

function riskColor(risk: number): string {
  if (risk >= 70) return "bg-red-500";
  if (risk >= 40) return "bg-yellow-500";
  return "bg-emerald-500";
}

function riskTextColor(risk: number): string {
  if (risk >= 70) return "text-red-400";
  if (risk >= 40) return "text-yellow-400";
  return "text-emerald-400";
}

export default function InvestigationDetail({
  token,
  taskId,
  onClose,
}: InvestigationDetailProps) {
  const [detail, setDetail] = useState<TaskDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError("");
      try {
        const data = await getTaskDetail(token, taskId);
        setDetail(data);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load investigation"
        );
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [token, taskId]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/80 p-4 pt-12 pb-12">
      <div className="card max-w-3xl w-full space-y-5 border-zinc-700 relative">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 pr-8">
          <Shield className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <div>
            <h2 className="text-sm font-bold text-zinc-100">
              Investigation Detail
            </h2>
            <code className="text-xs text-zinc-500 font-mono">{taskId}</code>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 text-zinc-400 text-sm py-8 justify-center">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading investigation...
          </div>
        ) : error ? (
          <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        ) : detail ? (
          <>
            {/* Verdict + Risk row */}
            <div className="flex items-center gap-4 flex-wrap">
              <span className={verdictBadgeClass(detail.verdict)}>
                {detail.verdict.replace(/_/g, " ").toUpperCase()}
              </span>

              {/* Risk bar */}
              <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                <span className="text-xs text-zinc-500">Risk</span>
                <div className="flex-1 bg-zinc-800 rounded-full h-2.5 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${riskColor(detail.risk_score)}`}
                    style={{ width: `${detail.risk_score}%` }}
                  />
                </div>
                <span
                  className={`text-sm font-bold ${riskTextColor(detail.risk_score)}`}
                >
                  {detail.risk_score}
                </span>
              </div>
            </div>

            {/* Meta row */}
            <div className="flex items-center gap-4 flex-wrap text-xs text-zinc-500">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(detail.created_at).toLocaleString()}
              </span>
              <span>
                Type:{" "}
                <code className="text-zinc-300 font-mono">
                  {detail.task_type}
                </code>
              </span>
              <span>
                Path:{" "}
                <code className="text-zinc-300 font-mono">
                  {detail.path_taken || "unknown"}
                </code>
              </span>
              <span
                className={`badge-${detail.status === "completed" ? "green" : detail.status === "error" ? "red" : "yellow"}`}
              >
                {detail.status}
              </span>
            </div>

            {/* Summary */}
            {detail.summary && (
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-md p-3">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                    Summary
                  </span>
                </div>
                <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">
                  {detail.summary}
                </p>
              </div>
            )}

            {/* Tools executed */}
            {detail.tools_executed && detail.tools_executed.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Wrench className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                    Tools Executed ({detail.tools_executed.length})
                  </span>
                </div>
                <div className="space-y-1.5">
                  {detail.tools_executed.map((tool, i) => (
                    <div
                      key={i}
                      className="bg-zinc-900/50 border border-zinc-800/50 rounded-md px-3 py-2 text-xs"
                    >
                      <code className="text-emerald-400 font-mono">
                        {tool.name}
                      </code>
                      {tool.result_summary && (
                        <span className="text-zinc-500 ml-2">
                          {tool.result_summary}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Findings */}
            {detail.findings && detail.findings.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Bug className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                    Findings ({detail.findings.length})
                  </span>
                </div>
                <ul className="space-y-1 text-xs">
                  {detail.findings.map((finding, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-2 text-zinc-300"
                    >
                      <span className="text-emerald-500 mt-0.5">-</span>
                      {finding}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* IOCs */}
            {detail.iocs && detail.iocs.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Crosshair className="w-4 h-4 text-red-400" />
                  <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                    Indicators of Compromise ({detail.iocs.length})
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-500">
                        <th className="text-left py-1.5 pr-4">Type</th>
                        <th className="text-left py-1.5">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.iocs.map((ioc, i) => (
                        <tr key={i} className="border-b border-zinc-800/50">
                          <td className="py-1.5 pr-4">
                            <span className="badge-zinc">{ioc.type}</span>
                          </td>
                          <td className="py-1.5">
                            <code className="text-zinc-300 font-mono break-all">
                              {ioc.value}
                            </code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {detail.mitre_attack && detail.mitre_attack.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-orange-400" />
                  <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                    MITRE ATT&CK ({detail.mitre_attack.length})
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {detail.mitre_attack.map((m, i) => (
                    <div
                      key={i}
                      className="bg-zinc-900/50 border border-zinc-800/50 rounded-md px-3 py-1.5 text-xs"
                    >
                      <code className="text-orange-400 font-mono">
                        {m.technique}
                      </code>
                      {m.name && (
                        <span className="text-zinc-400 ml-2">{m.name}</span>
                      )}
                      {m.tactic && (
                        <span className="text-zinc-600 ml-1">({m.tactic})</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw SIEM Event */}
            {detail.siem_event &&
              Object.keys(detail.siem_event).length > 0 && (
                <div>
                  <button
                    onClick={() => setShowRaw(!showRaw)}
                    className="flex items-center gap-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    {showRaw ? (
                      <ChevronUp className="w-3 h-3" />
                    ) : (
                      <ChevronDown className="w-3 h-3" />
                    )}
                    Raw SIEM Event
                  </button>
                  {showRaw && (
                    <pre className="mt-2 bg-zinc-950 border border-zinc-800 rounded-md p-3 text-xs text-zinc-400 overflow-x-auto max-h-[300px] overflow-y-auto">
                      {JSON.stringify(detail.siem_event, null, 2)}
                    </pre>
                  )}
                </div>
              )}
          </>
        ) : null}
      </div>
    </div>
  );
}
