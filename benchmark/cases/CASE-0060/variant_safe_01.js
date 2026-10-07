const fs = require("fs/promises");
const path = require("path");

async function copyRecursive(source, destination) {
  const lstat = await fs.lstat(source);

  if (lstat.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(source);
    for (const entry of entries) {
      await copyRecursive(
        path.join(source, entry),
        path.join(destination, entry)
      );
    }
    return;
  }

  if (!lstat.isFile()) {
    throw new Error(
      `Refusing to copy non-regular entry (symlink, socket, or device): ${source}`
    );
  }

  await fs.copyFile(source, destination);
}

module.exports = { copyRecursive };
