#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
env_file="${DEVSPACE_NEXT_ENV_FILE:-$HOME/.devspace/universal-broker-v2.env}"
expected_script_fallback="${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT-}"

if [[ ! -f "$env_file" ]]; then
  echo "Universal Broker v2 environment file is missing: $env_file" >&2
  exit 1
fi
mode="$(stat -f '%Lp' "$env_file" 2>/dev/null || stat -c '%a' "$env_file")"
if [[ "$mode" != "600" ]]; then
  echo "Universal Broker v2 environment file must be mode 0600: $env_file ($mode)" >&2
  exit 1
fi

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  # shellcheck source=/dev/null
  source "$HOME/.nvm/nvm.sh"
  nvm use 22 >/dev/null
fi

# The owner-only environment file is the only runtime authority for DevSpace
# settings. PM2 and the serving broker may otherwise leak removed or stale
# DEVSPACE_* values into a candidate, upgrade, rollback, or ordinary restart.
while IFS= read -r variable; do
  unset "$variable"
done < <(compgen -A variable DEVSPACE_)

set -a
# shellcheck source=/dev/null
source "$env_file"
set +a

# The production wrapper supplies the exact script path as a fallback for older
# owner files. A value explicitly recorded in the environment file wins.
if [[ -z "${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT-}" && -n "$expected_script_fallback" ]]; then
  export DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT="$expected_script_fallback"
fi

unset DEVSPACE_OAUTH_OWNER_TOKEN
if [[ "${DEVSPACE_V2_DEPLOYMENT_MODE-}" == production ]]; then
  runtime_package_root="${DEVSPACE_RUNTIME_PACKAGE_ROOT:?Production runtime package root is required}"
  runtime_dependency_root="${DEVSPACE_RUNTIME_DEPENDENCY_ROOT:?Production runtime dependency root is required}"
  runtime_dependency_evidence="${DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE:?Production runtime dependency evidence is required}"
  runtime_dependency_evidence_sha256="${DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256:?Production runtime dependency evidence digest is required}"
  runtime_manifest="${DEVSPACE_RELEASE_MANIFEST:?Production release manifest is required}"
  runtime_manifest_sha256="${DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256:?Production release manifest digest is required}"
  [[ "$(cd "$runtime_package_root" && pwd -P)" == "$repo" ]] || {
    echo "Production runtime package root does not match the executing package: $runtime_package_root" >&2
    exit 1
  }
  [[ "$(cd "$(dirname "$runtime_manifest")" && pwd -P)/$(basename "$runtime_manifest")" == "$repo/BUILD-MANIFEST.json" ]] || {
    echo "Production release manifest does not belong to the executing package: $runtime_manifest" >&2
    exit 1
  }
  node "$repo/scripts/personal-direct-owner-runtime.mjs" verify \
    --package "$repo" \
    --entrypoint "${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT:?Production PM2 entrypoint is required}" \
    --manifest "$runtime_manifest" \
    --manifest-sha256 "$runtime_manifest_sha256" \
    --source-revision "${DEVSPACE_SOURCE_REVISION:?Production source revision is required}" \
    --runtime-revision "${DEVSPACE_RUNTIME_REVISION:?Production runtime revision is required}" \
    --dependency-root "$runtime_dependency_root" \
    --dependency-evidence "$runtime_dependency_evidence" \
    --dependency-evidence-sha256 "$runtime_dependency_evidence_sha256" >/dev/null
  exec node --import "$repo/scripts/lib/runtime-dependency-loader.mjs" "$repo/dist/cli.js" serve-next
fi
if [[ -n "${DEVSPACE_RUNTIME_DEPENDENCY_ROOT-}" ]]; then
  runtime_package_root="${DEVSPACE_RUNTIME_PACKAGE_ROOT:?Parallel runtime package root is required}"
  [[ "$(cd "$runtime_package_root" && pwd -P)" == "$repo" ]] || {
    echo "Parallel runtime package root does not match the executing package: $runtime_package_root" >&2
    exit 1
  }
  exec node --import "$repo/scripts/lib/runtime-dependency-loader.mjs" "$repo/dist/cli.js" serve-next
fi
exec node "$repo/dist/cli.js" serve-next
