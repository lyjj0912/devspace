import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createFixtureMcpServer } from "./mcp-fixture-core.js";

const server = createFixtureMcpServer();
const transport = new StdioServerTransport();
await server.connect(transport);

const shutdown = async () => {
  await Promise.allSettled([server.close(), transport.close()]);
  process.exit(0);
};
process.once("SIGINT", () => void shutdown());
process.once("SIGTERM", () => void shutdown());
