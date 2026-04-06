import { useState, useEffect, useCallback } from "react";
import LoginForm from "./components/LoginForm";
import BootstrapWizard from "./components/BootstrapWizard";
import AdminDashboard from "./components/AdminDashboard";
import { getConfig } from "./lib/api";

export default function App() {
  const [token, setToken] = useState<string | null>(() =>
    sessionStorage.getItem("zovark_admin_token")
  );
  const [bootstrapComplete, setBootstrapComplete] = useState<boolean | null>(
    null
  );
  const [checking, setChecking] = useState(false);

  const checkBootstrap = useCallback(async (jwt: string) => {
    setChecking(true);
    try {
      const configs = await getConfig(jwt);
      const entry = configs.find(
        (c) => c.config_key === "bootstrap.completed"
      );
      setBootstrapComplete(entry?.config_value === "true");
    } catch {
      // If config fails, skip wizard — system is operational if health passes
      setBootstrapComplete(true);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    if (token) {
      checkBootstrap(token);
    }
  }, [token, checkBootstrap]);

  function handleLogin(jwt: string) {
    sessionStorage.setItem("zovark_admin_token", jwt);
    setToken(jwt);
  }

  function handleLogout() {
    sessionStorage.removeItem("zovark_admin_token");
    setToken(null);
    setBootstrapComplete(null);
  }

  // --- No token: Login ---
  if (!token) {
    return <LoginForm onLogin={handleLogin} />;
  }

  // --- Checking bootstrap status ---
  if (checking || bootstrapComplete === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex items-center gap-3 text-zinc-400 text-sm">
          <div className="w-5 h-5 border-2 border-zinc-600 border-t-emerald-400 rounded-full animate-spin" />
          Initializing control plane...
        </div>
      </div>
    );
  }

  // --- Not bootstrapped: Wizard ---
  if (!bootstrapComplete) {
    return (
      <BootstrapWizard
        token={token}
        onComplete={() => setBootstrapComplete(true)}
      />
    );
  }

  // --- Bootstrapped: Dashboard ---
  return <AdminDashboard token={token} onLogout={handleLogout} />;
}
