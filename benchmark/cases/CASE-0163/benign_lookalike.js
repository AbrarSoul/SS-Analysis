const crossSpawn = require('cross-spawn')

/**
 * Same crossSpawn('git', args, ...) call as the clone helper, but every
 * argument is a developer-written constant and the repository is chosen only
 * through `cwd`, so no caller-supplied string can be parsed as a git option.
 */
function recentCommits (repoDir, cb) {
  const child = crossSpawn('git', ['log', '--oneline', '-n', '5'], { cwd: repoDir, stdio: 'ignore' })
  child.on('error', cb)
  child.on('close', function (code) {
    cb(code === 0 ? null : new Error('Non-zero exit code: ' + code))
  })
}

module.exports = recentCommits
