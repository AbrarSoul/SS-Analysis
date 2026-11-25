function updateEnvFile(updates: Record<string, string>): void {
  try {
    const envPath_renamed = join(process.cwd(), '.env');
    let envContent = existsSync(envPath_renamed) ? readFileSync(envPath_renamed, 'utf-8') : '';

    // Update each key-value pair
    for (const [key, value] of Object.entries(updates)) {
      // Match the key with or without value, handling comments
      const regex = new RegExp(`^(#\\s*)?${key}=.*$`, 'gm');
      const newLine = `${key}="${value}"`;

      if (regex.test(envContent)) {
        // Update existing key (uncomment if needed)
        envContent = envContent.replace(regex, newLine);
      } else {
        // Add new key at the end
        envContent += `\n${newLine}`;
      }
    }

    writeFileSync(envPath_renamed, envContent, 'utf-8');
    // Tokens updated silently - console output interferes with MCP JSON protocol
  } catch (_error) {
    // Silent failure - error logging interferes with MCP JSON protocol
    // If needed, check .env file manually
  }
}