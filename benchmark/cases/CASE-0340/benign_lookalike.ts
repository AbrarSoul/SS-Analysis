import { execSync } from 'child_process';

// Prints the installed adb version. The command line is a constant string (no caller-controlled value is
// interpolated), so running it through the shell is safe.
export function getAdbVersion(): string {
  return execSync('adb version').toString().split('\n')[0];
}
