/**
 * Source verification must not inherit a running DevSpace deployment's configuration. Tests
 * provide their own explicit fixtures; inherited DEVSPACE_* values can silently change profile,
 * connector, state-directory, or production-mode behavior.
 */
export function sourceGateEnvironment(environment = process.env) {
  return Object.freeze(Object.fromEntries(
    Object.entries(environment).filter(([key]) => !key.startsWith("DEVSPACE_")),
  ));
}
