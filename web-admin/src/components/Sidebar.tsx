import { useState } from "react";
import {
  Activity,
  BarChart2,
  ChevronDown,
  FileText,
  Layers,
  LogOut,
  Plug,
  Settings,
  Shield,
  Terminal,
  Zap,
} from "lucide-react";

export type Page =
  | "health"
  | "siem"
  | "config"
  | "zvadmin"
  | "forge"
  | "analytics"
  | "auto-templates"
  | "pipeline";

interface NavGroup {
  label: string;
  items: { id: Page; label: string; icon: typeof Activity }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: "OPERATIONS",
    items: [
      { id: "health", label: "System Health", icon: Activity },
      { id: "pipeline", label: "Pipeline Monitor", icon: Layers },
      { id: "forge", label: "Alert Forge", icon: Zap },
      { id: "siem", label: "SIEM & Ingestion", icon: Plug },
    ],
  },
  {
    label: "INTELLIGENCE",
    items: [
      { id: "auto-templates", label: "Auto Templates", icon: FileText },
    ],
  },
  {
    label: "ANALYTICS",
    items: [
      { id: "analytics", label: "Analytics", icon: BarChart2 },
    ],
  },
  {
    label: "ADMIN",
    items: [
      { id: "zvadmin", label: "Zvadmin", icon: Terminal },
      { id: "config", label: "Configuration", icon: Settings },
    ],
  },
];

interface SidebarProps {
  activePage: Page;
  onNavigate: (page: Page) => void;
  onLogout: () => void;
}

export default function Sidebar({ activePage, onNavigate, onLogout }: SidebarProps) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  function toggleGroup(label: string) {
    setCollapsed((prev) => ({ ...prev, [label]: !prev[label] }));
  }

  return (
    <aside className="w-56 flex-shrink-0 border-r border-zinc-800 bg-[#080C15] flex flex-col min-h-screen">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-zinc-800">
        <div className="flex items-center gap-2.5">
          <Shield className="w-5 h-5 text-emerald-400" />
          <span className="text-sm font-bold text-zinc-100 tracking-tight">
            Zovark
          </span>
          <span className="badge-green text-[9px] py-0 leading-4">v3.3</span>
        </div>
      </div>

      {/* Nav groups */}
      <nav className="flex-1 overflow-y-auto py-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-1">
            <button
              onClick={() => toggleGroup(group.label)}
              className="w-full flex items-center justify-between px-4 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-zinc-500 hover:text-zinc-400 transition-colors"
            >
              {group.label}
              <ChevronDown
                className={`w-3 h-3 transition-transform duration-150 ${
                  collapsed[group.label] ? "-rotate-90" : ""
                }`}
              />
            </button>

            {!collapsed[group.label] && (
              <div className="mt-0.5 space-y-0.5">
                {group.items.map((item) => {
                  const isActive = activePage === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onNavigate(item.id)}
                      className={`w-full flex items-center gap-2.5 px-4 py-2 text-xs transition-colors ${
                        isActive
                          ? "text-emerald-400 bg-emerald-500/8 border-l-2 border-emerald-400"
                          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 border-l-2 border-transparent"
                      }`}
                    >
                      <item.icon className="w-3.5 h-3.5 flex-shrink-0" />
                      {item.label}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </nav>

      {/* Bottom */}
      <div className="border-t border-zinc-800 px-4 py-3">
        <button
          onClick={onLogout}
          className="flex items-center gap-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors w-full"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
