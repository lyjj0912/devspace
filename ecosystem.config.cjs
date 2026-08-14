const { homedir } = require("node:os");
const { join } = require("node:path");

module.exports = {
  apps: [
    {
      name: "devspace",
      cwd: __dirname,
      script: join(homedir(), ".devspace", "start.sh"),
      interpreter: "/bin/bash",
      autorestart: true,
      restart_delay: 1_000,
      kill_timeout: 15_000,
    },
  ],
};
