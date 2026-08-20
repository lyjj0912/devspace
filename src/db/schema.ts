import { sql } from "drizzle-orm";
import { index, integer, primaryKey, sqliteTable, text, unique, uniqueIndex } from "drizzle-orm/sqlite-core";

export const devspaceSchemaMigrations = sqliteTable(
  "devspace_schema_migrations",
  {
    storeId: text("store_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    checksum: text("checksum").notNull(),
    module: text("module").notNull(),
    appliedAt: text("applied_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.storeId, table.version] }),
    unique().on(table.storeId, table.name),
    index("devspace_schema_migrations_module_idx").on(table.module, table.storeId, table.version),
  ],
);

export const workspaceSessions = sqliteTable(
  "workspace_sessions",
  {
    id: text("id").primaryKey(),
    root: text("root").notNull(),
    status: text("status").notNull().default("active"),
    mode: text("mode").notNull().default("checkout"),
    sourceRoot: text("source_root"),
    baseRef: text("base_ref"),
    baseSha: text("base_sha"),
    managed: text("managed").notNull().default("false"),
    createdAt: text("created_at").notNull(),
    lastUsedAt: text("last_used_at").notNull(),
  },
  (table) => [
    index("workspace_sessions_root_idx").on(table.root, table.lastUsedAt),
    index("workspace_sessions_status_idx").on(table.status, table.lastUsedAt),
  ],
);

export const loadedAgentFiles = sqliteTable(
  "loaded_agent_files",
  {
    workspaceSessionId: text("workspace_session_id")
      .notNull()
      .references(() => workspaceSessions.id, { onDelete: "cascade" }),
    path: text("path").notNull(),
    contentHash: text("content_hash").notNull(),
    content: text("content").notNull(),
    loadedAt: text("loaded_at").notNull(),
    lastSeenAt: text("last_seen_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.workspaceSessionId, table.path] }),
    index("loaded_agent_files_path_idx").on(table.path),
  ],
);

export const workspaceConversationBindings = sqliteTable(
  "workspace_conversation_bindings",
  {
    conversationScopeId: text("conversation_scope_id").notNull(),
    targetKey: text("target_key").notNull(),
    workspaceSessionId: text("workspace_session_id")
      .notNull()
      .references(() => workspaceSessions.id, { onDelete: "cascade" }),
    createdAt: text("created_at").notNull(),
    lastUsedAt: text("last_used_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.conversationScopeId, table.targetKey] }),
    index("workspace_conversation_bindings_workspace_idx").on(table.workspaceSessionId),
  ],
);

export const oauthClients = sqliteTable(
  "oauth_clients",
  {
    clientId: text("client_id").primaryKey(),
    clientJson: text("client_json").notNull(),
    issuedAt: integer("issued_at").notNull(),
  },
  (table) => [
    index("oauth_clients_issued_at_idx").on(sql`${table.issuedAt} desc`),
  ],
);

export const oauthAccessTokens = sqliteTable(
  "oauth_access_tokens",
  {
    tokenHash: text("token_hash").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.clientId, { onDelete: "cascade" }),
    scopesJson: text("scopes_json").notNull(),
    expiresAt: integer("expires_at").notNull(),
    resource: text("resource"),
    familyId: text("family_id"),
    connectorBindingId: text("connector_binding_id"),
    connectorDrainEpoch: integer("connector_drain_epoch"),
    installationEpoch: integer("installation_epoch"),
    rotationSequence: integer("rotation_sequence").notNull().default(0),
  },
  (table) => [
    index("oauth_access_tokens_client_id_idx").on(table.clientId),
    index("oauth_access_tokens_expires_at_idx").on(table.expiresAt),
    index("oauth_access_tokens_family_idx").on(table.familyId),
  ],
);

export const oauthRefreshTokens = sqliteTable(
  "oauth_refresh_tokens",
  {
    tokenHash: text("token_hash").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.clientId, { onDelete: "cascade" }),
    scopesJson: text("scopes_json").notNull(),
    expiresAt: integer("expires_at").notNull(),
    resource: text("resource"),
    familyId: text("family_id"),
    connectorBindingId: text("connector_binding_id"),
    connectorDrainEpoch: integer("connector_drain_epoch"),
    installationEpoch: integer("installation_epoch"),
    rotationSequence: integer("rotation_sequence").notNull().default(0),
  },
  (table) => [
    index("oauth_refresh_tokens_client_id_idx").on(table.clientId),
    index("oauth_refresh_tokens_expires_at_idx").on(table.expiresAt),
    index("oauth_refresh_tokens_family_idx").on(table.familyId),
  ],
);

export const oauthConnectorBindings = sqliteTable(
  "oauth_connector_bindings",
  {
    bindingId: text("binding_id").primaryKey(),
    canonicalName: text("canonical_name").notNull(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.clientId, { onDelete: "cascade" }),
    installationEpoch: integer("installation_epoch").notNull(),
    schemaGeneration: text("schema_generation").notNull(),
    authorityContractGeneration: text("authority_contract_generation"),
    redirectUrisDigest: text("redirect_uris_digest"),
    buildDigest: text("build_digest"),
    drainEpoch: integer("drain_epoch").notNull().default(0),
    drainDeadlineAt: text("drain_deadline_at"),
    refreshAllowedDuringDrain: integer("refresh_allowed_during_drain").notNull().default(0),
    state: text("state").notNull(),
    stateReason: text("state_reason"),
    refCount: integer("ref_count").notNull().default(0),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    unique().on(table.canonicalName, table.installationEpoch),
    uniqueIndex("oauth_connector_bindings_one_active_name_idx")
      .on(table.canonicalName)
      .where(sql`${table.state} = 'ACTIVE'`),
    index("oauth_connector_bindings_client_idx").on(table.clientId, table.state),
  ],
);

export const oauthTokenFamilies = sqliteTable(
  "oauth_token_families",
  {
    familyId: text("family_id").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.clientId, { onDelete: "cascade" }),
    connectorBindingId: text("connector_binding_id")
      .references(() => oauthConnectorBindings.bindingId, { onDelete: "restrict" }),
    installationEpoch: integer("installation_epoch"),
    drainEpoch: integer("drain_epoch"),
    status: text("status").notNull(),
    rotationSequence: integer("rotation_sequence").notNull().default(0),
    createdAt: text("created_at").notNull(),
    rotatedAt: text("rotated_at"),
    revokedAt: text("revoked_at"),
  },
  (table) => [
    index("oauth_token_families_client_idx").on(table.clientId, table.status),
    index("oauth_token_families_binding_idx").on(table.connectorBindingId, table.status),
  ],
);

export const oauthConnectorActivationReceipts = sqliteTable(
  "oauth_connector_activation_receipts",
  {
    receiptId: text("receipt_id").primaryKey(),
    canonicalName: text("canonical_name").notNull(),
    candidateBindingId: text("candidate_binding_id")
      .notNull()
      .references(() => oauthConnectorBindings.bindingId, { onDelete: "restrict" }),
    clientId: text("client_id").notNull(),
    installationEpoch: integer("installation_epoch").notNull(),
    schemaGeneration: text("schema_generation").notNull(),
    authorityContractGeneration: text("authority_contract_generation").notNull(),
    redirectUrisDigest: text("redirect_uris_digest").notNull(),
    buildDigest: text("build_digest").notNull(),
    tupleDigest: text("tuple_digest").notNull(),
    preimageJson: text("preimage_json").notNull(),
    preimageDigest: text("preimage_digest").notNull(),
    previousActiveBindingId: text("previous_active_binding_id")
      .references(() => oauthConnectorBindings.bindingId, { onDelete: "restrict" }),
    ownerAuthorityId: text("owner_authority_id"),
    drainDeadlineAt: text("drain_deadline_at").notNull(),
    refreshAllowedDuringDrain: integer("refresh_allowed_during_drain").notNull(),
    status: text("status").notNull(),
    failureCode: text("failure_code"),
    preparedAt: text("prepared_at").notNull(),
    activatedAt: text("activated_at"),
    failedAt: text("failed_at"),
  },
  (table) => [
    uniqueIndex("oauth_connector_activation_receipts_one_prepared_idx")
      .on(table.canonicalName)
      .where(sql`${table.status} = 'PREPARED'`),
    index("oauth_connector_activation_receipts_candidate_idx").on(table.candidateBindingId, table.status),
  ],
);

export const oauthConnectorActivationAuthorities = sqliteTable(
  "oauth_connector_activation_authorities",
  {
    actionClaimId: text("action_claim_id").primaryKey(),
    receiptId: text("receipt_id")
      .notNull()
      .references(() => oauthConnectorActivationReceipts.receiptId, { onDelete: "restrict" }),
    authorityId: text("authority_id").notNull(),
    principalKeyFingerprint: text("principal_key_fingerprint").notNull(),
    actionFingerprint: text("action_fingerprint").notNull(),
    resourceKeySha256: text("resource_key_sha256").notNull(),
    fencingToken: integer("fencing_token").notNull(),
    risk: text("risk").notNull(),
    claimState: text("claim_state").notNull(),
    approvalAssurance: text("approval_assurance").notNull(),
    canonicalName: text("canonical_name").notNull(),
    tupleDigest: text("tuple_digest").notNull(),
    activePreimageDigest: text("active_preimage_digest").notNull(),
    finalizationPlanDigest: text("finalization_plan_digest").notNull(),
    evidenceDigest: text("evidence_digest").notNull(),
    claimedAtMs: integer("claimed_at_ms").notNull(),
    dispatchedAtMs: integer("dispatched_at_ms").notNull(),
    proofDigest: text("proof_digest").notNull(),
    consumedAt: text("consumed_at").notNull(),
  },
  (table) => [
    unique().on(table.receiptId),
    unique().on(table.resourceKeySha256, table.fencingToken),
    unique().on(table.proofDigest),
    index("oauth_connector_activation_authorities_canonical_idx").on(table.canonicalName, table.consumedAt),
    index("oauth_connector_activation_authorities_authority_idx").on(table.authorityId, table.actionClaimId),
  ],
);

export const oauthConnectorRetirementReceipts = sqliteTable(
  "oauth_connector_retirement_receipts",
  {
    receiptId: text("receipt_id").primaryKey(),
    bindingId: text("binding_id")
      .notNull()
      .unique()
      .references(() => oauthConnectorBindings.bindingId, { onDelete: "restrict" }),
    canonicalName: text("canonical_name").notNull(),
    drainEpoch: integer("drain_epoch").notNull(),
    reason: text("reason").notNull(),
    revokedFamilyCount: integer("revoked_family_count").notNull(),
    retiredAt: text("retired_at").notNull(),
  },
  (table) => [
    index("oauth_connector_retirement_receipts_binding_idx").on(table.bindingId, table.retiredAt),
  ],
);

export const localAgentSessions = sqliteTable(
  "local_agent_sessions",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id"),
    workspaceRoot: text("workspace_root").notNull(),
    profileName: text("profile_name").notNull(),
    provider: text("provider").notNull(),
    model: text("model"),
    thinking: text("thinking"),
    providerSessionId: text("provider_session_id"),
    status: text("status").notNull(),
    latestResponse: text("latest_response"),
    error: text("error"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    index("local_agent_sessions_workspace_id_idx").on(table.workspaceId, table.updatedAt),
    index("local_agent_sessions_workspace_root_idx").on(table.workspaceRoot, table.updatedAt),
    index("local_agent_sessions_provider_session_id_idx").on(table.providerSessionId),
  ],
);

export type WorkspaceSessionRow = typeof workspaceSessions.$inferSelect;
export type NewWorkspaceSessionRow = typeof workspaceSessions.$inferInsert;
export type DevspaceSchemaMigrationRow = typeof devspaceSchemaMigrations.$inferSelect;
export type NewDevspaceSchemaMigrationRow = typeof devspaceSchemaMigrations.$inferInsert;
export type LoadedAgentFileRow = typeof loadedAgentFiles.$inferSelect;
export type NewLoadedAgentFileRow = typeof loadedAgentFiles.$inferInsert;
export type WorkspaceConversationBindingRow = typeof workspaceConversationBindings.$inferSelect;
export type NewWorkspaceConversationBindingRow = typeof workspaceConversationBindings.$inferInsert;
export type LocalAgentSessionRow = typeof localAgentSessions.$inferSelect;
export type NewLocalAgentSessionRow = typeof localAgentSessions.$inferInsert;
export type OAuthConnectorActivationReceiptRow = typeof oauthConnectorActivationReceipts.$inferSelect;
export type NewOAuthConnectorActivationReceiptRow = typeof oauthConnectorActivationReceipts.$inferInsert;
export type OAuthConnectorRetirementReceiptRow = typeof oauthConnectorRetirementReceipts.$inferSelect;
export type NewOAuthConnectorRetirementReceiptRow = typeof oauthConnectorRetirementReceipts.$inferInsert;
