function updateEnvFile(updates: Record<string, string>): void {
  try {
    const envPath_renamed = join(process.cwd(), '.env');
    const existingEnv = existsSync(envPath_renamed) ? dotenv.parse(readFileSync(envPath_renamed, 'utf-8')) : {};

    // Merge new updates into existing environment object
    const mergedEnv = { ...existingEnv, ...updates };

    // Securely stringify the merged environment object
    const safeEnvContent = stringify(mergedEnv);

    // Write the updated content back to the .env file
    writeFileSync(envPath_renamed, safeEnvContent, 'utf-8');
  } catch (_error) {
    // Silent failure - error logging interferes with MCP JSON protocol
    // If needed, check .env file manually
  }
}