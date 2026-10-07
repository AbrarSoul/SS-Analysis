import { join } from 'path';

/**
 * Builds a human-readable summary of a configuration object for a debug
 * banner. Same `${key}="${value}"` interpolation shape as an env-file
 * writer, but the result is only ever printed to a log line, never
 * written to any file that is later parsed as configuration.
 */
export function describeSettings(settings: Record<string, string>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(settings)) {
    lines.push(`${key}="${value}"`);
  }
  return `settings for ${join('config', 'debug')}: ${lines.join(', ')}`;
}
