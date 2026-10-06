// src/extension.ts
import * as vscode from 'vscode';
import { RconController } from './rconClient';
import { RconTerminal } from './rconTerminal';
import * as path from 'path';

export function activate(context: vscode.ExtensionContext) {
  const channel = vscode.window.createOutputChannel('Minecraft RCON');
  let openTerminals = new Map<vscode.Terminal, RconController>();
  let controllerByPty = new Map<RconTerminal, RconController>();
  let liveConnection: { host: string; port: number; password: string } | null = null;

  // Register the term profile provider
  context.subscriptions.push(
    vscode.window.registerTerminalProfileProvider('minecraftRcon.terminal', {
      provideTerminalProfile: async (token: vscode.CancellationToken) => {
        const { profile, controller, pty, connectionInfo } = await createRconTerminalProfile(channel, context);
        
        // Store current connection info
        liveConnection = connectionInfo;
        
        // Add icon to the profile
        profile.options.iconPath = {
          light: vscode.Uri.file(path.join(context.extensionPath, 'images', 'light.png')),
          dark: vscode.Uri.file(path.join(context.extensionPath, 'images', 'dark.png'))
        };
        
        // Store the controller with the pty so we can track it later
        controllerByPty.set(pty, controller);
        
        return profile;
      }
    })
  );

  // Track when terminals open
  const onOpenListener = vscode.window.onDidOpenTerminal((term) => {
    // Check if this term has one of our pty instances
    for (const [pty, controller] of controllerByPty.entries()) {
      if ((term.creationOptions as any).pty === pty) {
        openTerminals.set(term, controller);
        controllerByPty.delete(pty);
        channel.appendLine(`Terminal opened: ${term.name}`);
        break;
      }
    }
  });

  // Keep the original connect command
  const connectCommand = vscode.commands.registerCommand('minecraftRcon.connect', async () => {
    await connectToRcon(channel, openTerminals, context, liveConnection);
  });

  // Add command to connect with new credentials (always prompts)
  const connectFreshCommand = vscode.commands.registerCommand('minecraftRcon.connectNew', async () => {
    await connectToRcon(channel, openTerminals, context, liveConnection, false);
  });

  // Add command to save current connection as default
  const persistDefaultsCommand = vscode.commands.registerCommand('minecraftRcon.saveDefaults', async () => {
    if (!liveConnection) {
      vscode.window.showWarningMessage('No active connection to save');
      return;
    }

    const settings = vscode.workspace.getConfiguration('minecraftRcon');
    
    try {
      await settings.update('defaultHost', liveConnection.host, vscode.ConfigurationTarget.Global);
      await settings.update('defaultPort', liveConnection.port, vscode.ConfigurationTarget.Global);
      await settings.update('defaultPassword', liveConnection.password, vscode.ConfigurationTarget.Global);
      
      vscode.window.showInformationMessage(
        `Saved connection settings for ${liveConnection.host}:${liveConnection.port} as defaults`
      );
    } catch (failure) {
      vscode.window.showErrorMessage(`Failed to save defaults: ${failure}`);
    }
  });

  // Handle term close events
  const onCloseListener = vscode.window.onDidCloseTerminal(async (term) => {
    const controller = openTerminals.get(term);
    if (controller) {
      await controller.disconnect();
      openTerminals.delete(term);
      channel.appendLine(`Terminal closed: ${term.name}`);
    }
  });

  context.subscriptions.push(
    connectCommand, 
    connectFreshCommand, 
    persistDefaultsCommand, 
    onOpenListener, 
    onCloseListener, 
    channel
  );
}

async function createRconTerminalProfile(
  output: vscode.OutputChannel,
  context: vscode.ExtensionContext,
  useDefaults: boolean = true
): Promise<{ 
  profile: vscode.TerminalProfile, 
  controller: RconController, 
  pty: RconTerminal,
  connectionInfo: { host: string; port: number; password: string }
}> {
  // Gather settings
  const config = vscode.workspace.getConfiguration('minecraftRcon');
  
  const defaultHost = config.get<string>('defaultHost');
  const defaultPort = config.get<number>('defaultPort');
  const defaultPassword = config.get<string>('defaultPassword');
  
  let host: string | undefined;
  let port: number;
  let password: string;
  
  // Check if we have all defaults and should use them
  if (useDefaults && defaultHost && defaultPort && defaultPassword) {
    // Use defaults without prompting
    host = defaultHost;
    port = defaultPort;
    password = defaultPassword;
    output.appendLine(`Using saved connection settings for ${host}:${port}`);
  } else {
    // Prompt for missing values
    host = await vscode.window.showInputBox({
      prompt: 'RCON Host',
      value: defaultHost ?? '127.0.0.1',
      placeHolder: 'e.g., 127.0.0.1 or mc.example.com'
    });
    if (!host) {
      throw new Error('Host is required');
    }

    const portInput = await vscode.window.showInputBox({
      prompt: 'RCON Port',
      value: String(defaultPort ?? 25575),
      placeHolder: 'e.g., 25575'
    });
    if (!portInput) {
      throw new Error('Port is required');
    }
    port = parseInt(portInput, 10);

    password = await vscode.window.showInputBox({ 
      prompt: 'RCON Password', 
      password: true,
      value: defaultPassword ?? '',
      placeHolder: 'Enter your server RCON password'
    }) ?? '';
    if (password === undefined) {
      throw new Error('Password is required');
    }
  }

  // Create controller and connect
  const controller = new RconController(host, port, password, output);

  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: `Connecting to ${host}:${port}...`,
      cancellable: false
    }, async () => {
      await controller.connect();
    });
  } catch (err: any) {
    // If using defaults failed, offer to re-enter credentials
    if (useDefaults && defaultHost && defaultPort && defaultPassword) {
      const retry = await vscode.window.showErrorMessage(
        `Failed to connect with saved settings: ${err.message}`,
        'Enter New Credentials',
        'Cancel'
      );
      
      if (retry === 'Enter New Credentials') {
        // Retry with prompts
        return createRconTerminalProfile(output, context, false);
      }
    }
    throw err;
  }

  // Create terminal with RCON integration - Pass all required parameters including context
  const pty = new RconTerminal(controller, host, port, password, output, context);
  
  const profile = new vscode.TerminalProfile({
    name: `RCON: ${host}:${port}`,
    pty
  });

  return { 
    profile, 
    controller, 
    pty,
    connectionInfo: { host, port, password }
  };
}

async function connectToRcon(
  output: vscode.OutputChannel,
  activeTerminals: Map<vscode.Terminal, RconController>,
  context: vscode.ExtensionContext,
  currentConnection: { host: string; port: number; password: string } | null,
  useDefaults: boolean = true
): Promise<void> {
  try {
    const { profile, controller, connectionInfo } = await createRconTerminalProfile(output, context, useDefaults);
    const terminal = vscode.window.createTerminal({
      ...profile.options,
      iconPath: {
        light: vscode.Uri.file(path.join(context.extensionPath, 'images', 'light.png')),
        dark: vscode.Uri.file(path.join(context.extensionPath, 'images', 'dark.png'))
      }
    });
    
    // Store the controller reference
    activeTerminals.set(terminal, controller);
    
    // Update current connection info
    if (currentConnection) {
      currentConnection.host = connectionInfo.host;
      currentConnection.port = connectionInfo.port;
      currentConnection.password = connectionInfo.password;
    }
    
    terminal.show();
    
    // Show different messages based on whether defaults were used
    if (useDefaults) {
      const config = vscode.workspace.getConfiguration('minecraftRcon');
      const hasDefaults = config.get('defaultHost') && config.get('defaultPort') && config.get('defaultPassword');
      if (hasDefaults) {
        vscode.window.showInformationMessage(`Connected to Minecraft server using saved settings`);
      } else {
        vscode.window.showInformationMessage(`Connected to Minecraft server`);
      }
    } else {
      vscode.window.showInformationMessage(`Connected to Minecraft server`);
    }
  } catch (err: any) {
    if (err.message && !err.message.includes('required')) {
      output.appendLine('Connection failed: ' + String(err.message ?? err));
      vscode.window.showErrorMessage('RCON connection failed: ' + String(err.message ?? err));
    }
  }
}

export function deactivate() {
  // Cleanup will happen automatically
}