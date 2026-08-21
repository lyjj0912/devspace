import { setTimeout as delay } from "node:timers/promises";

const PROFILE = "PERSONAL_DIRECT_OWNER";

export async function waitForHealthyPersonalRuntime(url, runtimeRevision, options = {}) {
  const timeoutMs = positiveInteger(options.timeoutMs ?? 30_000, "timeoutMs");
  const requestTimeoutMs = positiveInteger(options.requestTimeoutMs ?? 2_000, "requestTimeoutMs");
  const intervalMs = positiveInteger(options.intervalMs ?? 250, "intervalMs");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  do {
    try {
      const remainingMs = Math.max(1, deadline - Date.now());
      const response = await fetch(url, {
        signal: AbortSignal.timeout(Math.min(requestTimeoutMs, remainingMs)),
      });
      if (!response.ok) throw new Error(`Runtime health returned HTTP ${response.status}: ${url}`);
      const value = await response.json();
      const productProfile = value.productProfile ?? value.identity?.productProfile;
      if (productProfile !== PROFILE) throw new Error("Runtime health profile mismatch.");
      if (value.runtimeRevision !== runtimeRevision && value.identity?.runtimeRevision !== runtimeRevision) {
        throw new Error("Runtime health revision mismatch.");
      }
      return value;
    } catch (error) {
      lastError = error;
    }
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    await delay(Math.min(intervalMs, remainingMs));
  } while (Date.now() < deadline);
  throw new Error(`Runtime health did not converge within ${timeoutMs}ms: ${url}`, { cause: lastError });
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be a positive integer.`);
  return value;
}
