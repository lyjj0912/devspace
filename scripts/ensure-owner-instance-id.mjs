#!/usr/bin/env node
import { ensureOwnerInstanceId } from "./lib/owner-instance-id.mjs";

const [directory, ...extra] = process.argv.slice(2);
if (!directory || extra.length > 0) {
  console.error("Usage: ensure-owner-instance-id.mjs <identity-directory>");
  process.exit(2);
}

try {
  process.stdout.write(`${ensureOwnerInstanceId(directory)}\n`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
