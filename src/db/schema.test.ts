import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { getTableConfig } from "drizzle-orm/sqlite-core/utils";
import { openDatabase } from "./client.js";
import {
  devspaceSchemaMigrations,
  oauthAccessTokens,
  oauthClients,
  oauthConnectorActivationAuthorities,
  oauthConnectorActivationReceipts,
  oauthConnectorBindings,
  oauthConnectorRetirementReceipts,
  oauthRefreshTokens,
  oauthTokenFamilies,
} from "./schema.js";

type SchemaTable = Parameters<typeof getTableConfig>[0];

interface TableExpectation {
  readonly name: string;
  readonly table: SchemaTable;
  readonly indexes: readonly string[];
}

const targetTables: readonly TableExpectation[] = [
  {
    name: "devspace_schema_migrations",
    table: devspaceSchemaMigrations,
    indexes: ["devspace_schema_migrations_module_idx"],
  },
  {
    name: "oauth_clients",
    table: oauthClients,
    indexes: ["oauth_clients_issued_at_idx"],
  },
  {
    name: "oauth_access_tokens",
    table: oauthAccessTokens,
    indexes: [
      "oauth_access_tokens_client_id_idx",
      "oauth_access_tokens_expires_at_idx",
      "oauth_access_tokens_family_idx",
    ],
  },
  {
    name: "oauth_refresh_tokens",
    table: oauthRefreshTokens,
    indexes: [
      "oauth_refresh_tokens_client_id_idx",
      "oauth_refresh_tokens_expires_at_idx",
      "oauth_refresh_tokens_family_idx",
    ],
  },
  {
    name: "oauth_connector_bindings",
    table: oauthConnectorBindings,
    indexes: [
      "oauth_connector_bindings_client_idx",
      "oauth_connector_bindings_one_active_name_idx",
    ],
  },
  {
    name: "oauth_token_families",
    table: oauthTokenFamilies,
    indexes: [
      "oauth_token_families_binding_idx",
      "oauth_token_families_client_idx",
    ],
  },
  {
    name: "oauth_connector_activation_receipts",
    table: oauthConnectorActivationReceipts,
    indexes: [
      "oauth_connector_activation_receipts_candidate_idx",
      "oauth_connector_activation_receipts_one_prepared_idx",
    ],
  },
  {
    name: "oauth_connector_activation_authorities",
    table: oauthConnectorActivationAuthorities,
    indexes: [
      "oauth_connector_activation_authorities_authority_idx",
      "oauth_connector_activation_authorities_canonical_idx",
    ],
  },
  {
    name: "oauth_connector_retirement_receipts",
    table: oauthConnectorRetirementReceipts,
    indexes: ["oauth_connector_retirement_receipts_binding_idx"],
  },
];

const root = await mkdtemp(join(tmpdir(), "devspace-schema-test-"));
try {
  const database = openDatabase(root);
  try {
    for (const expectation of targetTables) {
      assert.deepEqual(
        drizzleColumnNames(expectation.table),
        sqliteColumnNames(database.sqlite, expectation.name),
        `${expectation.name} Drizzle columns must match the raw migration DDL`,
      );
      assert.deepEqual(
        drizzleIndexNames(expectation.table),
        sqliteIndexNames(database.sqlite, expectation.name, expectation.indexes),
        `${expectation.name} Drizzle indexes must match the raw migration DDL`,
      );
    }
  } finally {
    database.close();
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("Drizzle schema metadata parity: PASS");

function drizzleColumnNames(table: SchemaTable): string[] {
  return getTableConfig(table).columns.map((column) => column.name);
}

function sqliteColumnNames(sqlite: Database.Database, tableName: string): string[] {
  return sqlite.prepare(`pragma table_info(${tableName})`).all()
    .map((column) => (column as { name: string }).name);
}

function drizzleIndexNames(table: SchemaTable): string[] {
  return getTableConfig(table).indexes.map((entry) => entry.config.name).sort();
}

function sqliteIndexNames(
  sqlite: Database.Database,
  tableName: string,
  expectedIndexes: readonly string[],
): string[] {
  const expected = new Set(expectedIndexes);
  return sqlite.prepare("select name from sqlite_master where type = 'index' and tbl_name = ? order by name")
    .all(tableName)
    .map((row) => (row as { name: string }).name)
    .filter((name) => expected.has(name))
    .sort();
}
