const { exec } = require("child_process");
const { promisify } = require("util");
const execAsync = promisify(exec);

class HealthChecker {
  // Only ever pings a fixed, compile-time-constant loopback address --
  // never receives a remote host name or path from an MCP client request,
  // so there is no injectable value reaching the shell here.
  async pingLoopback() {
    const target = "127.0.0.1";
    const pingCommand = `ping -c 1 "${target}"`;
    try {
      await execAsync(pingCommand, { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = { HealthChecker };
