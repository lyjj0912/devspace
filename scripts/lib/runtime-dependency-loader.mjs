import { builtinModules, createRequire, registerHooks } from "node:module";
import { realpathSync } from "node:fs";
import { isAbsolute, join, relative, resolve as resolvePath, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const configuredPackageRoot = requiredAbsolute(
  process.env.DEVSPACE_RUNTIME_PACKAGE_ROOT,
  "DEVSPACE_RUNTIME_PACKAGE_ROOT",
);
const dependencyRoot = requiredAbsolute(
  process.env.DEVSPACE_RUNTIME_DEPENDENCY_ROOT,
  "DEVSPACE_RUNTIME_DEPENDENCY_ROOT",
);
const dependencyAnchor = pathToFileURL(join(dependencyRoot, "package.json")).href;
const dependencyRequire = createRequire(dependencyAnchor);
const builtins = new Set(builtinModules.map((name) => name.replace(/^node:/u, "")));

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (!isBareSpecifier(specifier) || !isPackageParent(context.parentURL)) {
      return nextResolve(specifier, context);
    }
    if (context.conditions?.includes("require")) {
      return {
        shortCircuit: true,
        url: pathToFileURL(dependencyRequire.resolve(specifier)).href,
      };
    }
    return nextResolve(specifier, { ...context, parentURL: dependencyAnchor });
  },
});

function isPackageParent(parentURL) {
  if (typeof parentURL !== "string" || !parentURL.startsWith("file:")) return false;
  const parentPath = realpathSync(resolvePath(fileURLToPath(parentURL)));
  const path = relative(configuredPackageRoot, parentPath);
  return path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

function isBareSpecifier(value) {
  return typeof value === "string"
    && value.length > 0
    && !builtins.has(value)
    && !value.startsWith("#")
    && !value.startsWith(".")
    && !value.startsWith("/")
    && !value.includes(":");
}

function requiredAbsolute(value, name) {
  if (typeof value !== "string" || !isAbsolute(value) || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be an absolute path.`);
  }
  return realpathSync(resolvePath(value));
}
