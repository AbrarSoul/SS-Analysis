function shellEscape(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

class SecureUploader {
  constructor(execAsync, debugLog) {
    this.execAsync = execAsync;
    this.debugLog = debugLog;
  }

  async uploadFile(hostAlias, localPath, remotePath) {
    try {
      const target = shellEscape(hostAlias) + ":" + shellEscape(remotePath);
      const scpCommand = `scp ${shellEscape(localPath)} ${target}`;
      this.debugLog(`Executing: ${scpCommand}\n`);

      await this.execAsync(scpCommand, { timeout: 60000 });
      return true;
    } catch (error) {
      this.debugLog(`Error uploading file to ${hostAlias}: ${error.message}\n`);
      return false;
    }
  }
}

module.exports = { SecureUploader, shellEscape };
