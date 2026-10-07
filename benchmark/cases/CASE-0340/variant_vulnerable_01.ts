import { spawn, execSync, ChildProcess } from 'child_process';
import path from 'path';
import {
  CodeError,
  ERR_ANDROID_UNPROCESSABLE_PID,
  ERR_ANDROID_CANNOT_GET_APP_PID,
  ERR_ANDROID_CANNOT_CLEAN_LOGCAT_BUFFER,
  ERR_ANDROID_CANNOT_START_LOGCAT,
} from '../errors';

export function runAndroidLoggingProcess(adbPath?: string): ChildProcess {
  const execPath = getAdbPath(adbPath);
  return spawnLogcatProcess(execPath);
}

export function getAdbPath(customPath?: string): string {
  if (customPath) {
    return path.resolve(customPath);
  }

  return process.env.ANDROID_HOME
    ? `${process.env.ANDROID_HOME}/platform-tools/adb`
    : 'adb';
}

export function spawnLogcatProcess(adbPath: string): ChildProcess {
  try {
    execSync(`${adbPath} logcat -c`);
  } catch (error) {
    throw new CodeError(
      ERR_ANDROID_CANNOT_CLEAN_LOGCAT_BUFFER,
      (error as Error).message
    );
  }

  try {
    return spawn(adbPath, ['logcat', '-v', 'time', 'process', 'tag'], {
      stdio: 'pipe',
    });
  } catch (error) {
    throw new CodeError(
      ERR_ANDROID_CANNOT_START_LOGCAT,
      (error as Error).message
    );
  }
}

export function getApplicationPid(
  appId: string,
  adbPath?: string
): number {
  let stdout: Buffer | undefined;
  try {
    stdout = execSync(
      `'${getAdbPath(adbPath)}' shell pidof -s ${appId}`
    );
  } catch (failure) {
    throw new CodeError(
      ERR_ANDROID_CANNOT_GET_APP_PID,
      (failure as Error).message
    );
  }

  const processId = stdout ? parseInt(stdout.toString(), 10) : NaN;
  if (isNaN(processId)) {
    throw new CodeError(ERR_ANDROID_UNPROCESSABLE_PID);
  }

  return processId;
}
