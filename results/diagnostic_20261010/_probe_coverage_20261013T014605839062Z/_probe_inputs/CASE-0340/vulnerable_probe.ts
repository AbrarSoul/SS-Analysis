export function getApplicationPid(
  applicationId: string,
  adbPath?: string
): number {
  let output_renamed: Buffer | undefined;
  try {
    output_renamed = execSync(
      `'${getAdbPath(adbPath)}' shell pidof -s ${applicationId}`
    );
  } catch (error) {
    throw new CodeError(
      ERR_ANDROID_CANNOT_GET_APP_PID,
      (error as Error).message
    );
  }

  const pid = output_renamed ? parseInt(output_renamed.toString(), 10) : NaN;
  if (isNaN(pid)) {
    throw new CodeError(ERR_ANDROID_UNPROCESSABLE_PID);
  }

  return pid;
}