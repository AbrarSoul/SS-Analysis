import * as vscode from 'vscode';

/**
 * Same `config.update(key, value, ConfigurationTarget.Global)` call as the
 * save-defaults command, but the values are the server HOST and PORT, which
 * are not secrets; the password is never written to settings.json here.
 */
export async function saveHostAndPort(host: string, port: number): Promise<void> {
  const config = vscode.workspace.getConfiguration('minecraftRcon');
  await config.update('defaultHost', host, vscode.ConfigurationTarget.Global);
  await config.update('defaultPort', port, vscode.ConfigurationTarget.Global);
}
