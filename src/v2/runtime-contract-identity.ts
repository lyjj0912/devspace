/**
 * Dependency-free contract identities consumed by both runtime health and the
 * standalone immutable-package verifier. contracts.test.ts recomputes these
 * values from the live schemas and authority classifiers to prevent drift.
 */
export const RUNTIME_SCHEMA_GENERATION =
  "sha256:5d7a22e47302136a6d7f84108d27fba8264b5d64a3a5db40983e6f9e39de100c";

export const RUNTIME_AUTHORITY_CONTRACT_GENERATION =
  "sha256:58b792783dd59c429489688f55117469181de50facff8ebbff1179324babcddd";
