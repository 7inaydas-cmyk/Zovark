import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";

const execFileAsync = promisify(execFile);

const PROJECT_DIR =
  process.env.ZOVARK_PROJECT_DIR ||
  "."; // Set ZOVARK_PROJECT_DIR env var to your project root

export async function dockerComposeExec(
  service: string,
  command: string[],
  timeoutMs: number = 30000
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(
      "docker",
      ["compose", "exec", "-T", service, ...command],
      {
        cwd: resolve(PROJECT_DIR),
        timeout: timeoutMs,
        maxBuffer: 1024 * 1024,
      }
    );
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || e.message || "exec failed",
    };
  }
}

export async function dockerComposeLogs(
  service: string,
  lines: number = 50,
  filter?: string
): Promise<string> {
  const args =
    service === "all"
      ? ["compose", "logs", "--tail", String(lines)]
      : ["compose", "logs", service, "--tail", String(lines)];

  try {
    const result = await execFileAsync("docker", args, {
      cwd: resolve(PROJECT_DIR),
      timeout: 15000,
      maxBuffer: 2 * 1024 * 1024,
    });
    let output = result.stdout || result.stderr || "";
    if (filter) {
      output = output
        .split("\n")
        .filter((line) => line.toLowerCase().includes(filter.toLowerCase()))
        .join("\n");
    }
    return output;
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return e.stdout || e.stderr || e.message || "Failed to get logs";
  }
}
