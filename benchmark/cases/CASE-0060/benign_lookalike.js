const fs = require("fs/promises");
const os = require("os");
const path = require("path");

async function snapshotOwnScratchDir() {
  // sourceDir is always a directory THIS function just created via
  // mkdtemp() a moment earlier -- never derived from any external input,
  // so it can never contain an attacker-planted symlink.
  const sourceDir = await fs.mkdtemp(path.join(os.tmpdir(), "scratch-"));
  await fs.writeFile(path.join(sourceDir, "marker.txt"), "ok");

  const destination = path.join(os.tmpdir(), "scratch-snapshot");
  const stats = await fs.stat(sourceDir);
  if (stats.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(sourceDir);
    for (const entry of entries) {
      await fs.copyFile(
        path.join(sourceDir, entry),
        path.join(destination, entry)
      );
    }
  }
  return destination;
}

module.exports = { snapshotOwnScratchDir };
