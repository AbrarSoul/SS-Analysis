"""
Section 9 ground-truth test bundle: CASE-0177
(jaketcooper/Minecraft-rcon, src/extension.ts activate, CVE-2025-61680,
CWE-256 plaintext storage of a password).

Located target: `export function activate(context: vscode.ExtensionContext) {`.

Core vulnerable mechanism: the `minecraftRcon.saveDefaults` command saves the
server's RCON password with
`config.update('defaultPassword', currentConnection.password, ConfigurationTarget.Global)`,
i.e. in the user's settings.json in clear text, and the extension later reads
it back with `config.get('defaultPassword')`. Anyone or anything that can read
or sync settings.json (dotfile repos, Settings Sync, screen shares) gets the
server password. The upstream fix stores it in `context.secrets` (VS Code
SecretStorage), reads it from there in the two other places, and adds a
migration that moves an existing plaintext value into secret storage and clears
it from settings.

Sibling sites: the password is read in `createRconTerminalProfile` and in
`connectToRcon` (`hasDefaults`), so the safe variant changes all three sites
plus the migration; the vulnerable variants leave them all.

Every variant is the FULL real file. `activate` is the extension entry point
(called by name by VS Code), so the renamed variant keeps its name and the
`{ profile, controller, pty, connectionInfo }` destructuring keys, and renames
the other locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0177"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

s = original.index("export function activate(context: vscode.ExtensionContext) {\n")
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
SAVE = "      await config.update('defaultPassword', currentConnection.password, vscode.ConfigurationTarget.Global);\n"
READ1 = "  const defaultPassword = config.get<string>('defaultPassword');\n"
READ2 = "      const hasDefaults = config.get('defaultHost') && config.get('defaultPort') && config.get('defaultPassword');\n"
ACT_START = '''  let currentConnection: { host: string; port: number; password: string } | null = null;

'''
for x in (SAVE, READ1, READ2):
    assert original.count(x) == 1
assert BLOCK.count(SAVE) == 1 and BLOCK.count(ACT_START) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r"('(?:[^'\\]|\\.)*')", BLOCK)
pairs = (("output", "channel"), ("activeTerminals", "openTerminals"), ("ptyToController", "controllerByPty"),
         ("currentConnection", "liveConnection"), ("openListener", "onOpenListener"),
         ("connectNewCommand", "connectFreshCommand"), ("saveDefaultsCommand", "persistDefaultsCommand"),
         ("closeListener", "onCloseListener"), ("config", "settings"), ("terminal", "term"), ("err", "failure"))
for i in range(0, len(parts), 2):
    for old, new in pairs:
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert "const { profile, controller, pty, connectionInfo } = await createRconTerminalProfile(channel, context);" in b
assert "liveConnection = connectionInfo;" in b and "Terminal opened: ${term.name}" in b
assert "await settings.update('defaultPassword', liveConnection.password, vscode.ConfigurationTarget.Global);" in b
assert "vscode.window.createOutputChannel('Minecraft RCON')" in b and "(terminal.creationOptions" not in b
(CASE_DIR / "variant_vulnerable_01.ts").write_text(original[:s] + b + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, SAVE, "      await saveConnectionDefaults(currentConnection, config);\n")
v2 = swap(v2, "      await config.update('defaultHost', currentConnection.host, vscode.ConfigurationTarget.Global);\n", "")
v2 = swap(v2, "      await config.update('defaultPort', currentConnection.port, vscode.ConfigurationTarget.Global);\n", "")
v2 = swap(v2, "async function createRconTerminalProfile(", '''async function saveConnectionDefaults(
  connection: { host: string; port: number; password: string },
  config: vscode.WorkspaceConfiguration
): Promise<void> {
  await config.update('defaultHost', connection.host, vscode.ConfigurationTarget.Global);
  await config.update('defaultPort', connection.port, vscode.ConfigurationTarget.Global);
  await config.update('defaultPassword', connection.password, vscode.ConfigurationTarget.Global);
}

async function createRconTerminalProfile(''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The password lives only in SecretStorage, through two small helpers used at
# all three former settings.json sites, and any legacy plaintext value is moved
# out of settings when the extension activates.
v3 = swap(original, ACT_START, ACT_START + '''  moveLegacyPassword(context).catch(error => {
    output.appendLine(`Password migration warning: ${error}`);
  });

''')
v3 = swap(v3, SAVE, "      await saveDefaultPassword(context, currentConnection.password);\n")
v3 = swap(v3, READ1, "  const defaultPassword = await readDefaultPassword(context);\n")
v3 = swap(v3, READ2, '''      const savedPassword = await readDefaultPassword(context);
      const hasDefaults = config.get('defaultHost') && config.get('defaultPort') && savedPassword;
''')
v3 = swap(v3, "async function createRconTerminalProfile(", '''const PASSWORD_SECRET_KEY = 'minecraftRcon.defaultPassword';

async function saveDefaultPassword(context: vscode.ExtensionContext, password: string): Promise<void> {
  await context.secrets.store(PASSWORD_SECRET_KEY, password);
}

async function readDefaultPassword(context: vscode.ExtensionContext): Promise<string | undefined> {
  return context.secrets.get(PASSWORD_SECRET_KEY);
}

async function moveLegacyPassword(context: vscode.ExtensionContext): Promise<void> {
  const config = vscode.workspace.getConfiguration('minecraftRcon');
  const legacy = config.get<string>('defaultPassword');
  if (legacy) {
    await saveDefaultPassword(context, legacy);
    await config.update('defaultPassword', undefined, vscode.ConfigurationTarget.Global);
  }
}

async function createRconTerminalProfile(''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import * as vscode from 'vscode';

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
'''
assert "never written to settings.json" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0177.")
