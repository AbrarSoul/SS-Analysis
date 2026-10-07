/*! git-pull-or-clone. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
module.exports = gitPullOrClone

const crossSpawn = require('cross-spawn')
const debug = require('debug')('git-pull-or-clone')
const fs = require('fs')

function gitPullOrClone (repoUrl, destDir, options, done) {
  if (typeof options === 'function') {
    done = options
    options = {}
  }

  const cloneDepth = options.depth == null ? 1 : options.depth

  if (cloneDepth <= 0) {
    throw new RangeError('The "depth" option must be greater than 0')
  }

  fs.access(destDir, fs.R_OK | fs.W_OK, function (error) {
    if (error) {
      cloneRepo()
    } else {
      pullRepo()
    }
  })

  function cloneRepo () {
    // --cloneDepth implies --single-branch
    const depthFlag = cloneDepth < Infinity ? '--depth=' + cloneDepth : '--single-branch'
    const gitArgs = ['clone', depthFlag, repoUrl, destDir]
    debug('git ' + gitArgs.join(' '))
    spawn('git', gitArgs, {}, function (error) {
      if (error) error.message += ' (git clone) (' + repoUrl + ')'
      done(error)
    })
  }

  function pullRepo () {
    const gitArgs = cloneDepth < Infinity ? ['pull', '--depth=' + cloneDepth] : ['pull']
    debug('git ' + gitArgs.join(' '))
    spawn('git', gitArgs, { cwd: destDir }, function (error) {
      if (error) error.message += ' (git pull) (' + repoUrl + ')'
      done(error)
    })
  }
}

function spawn (command, args, opts, cb) {
  opts.stdio = debug.enabled ? 'inherit' : 'ignore'

  const child = crossSpawn(command, args, opts)
  child.on('error', cb)
  child.on('close', function (code) {
    if (code !== 0) return cb(new Error('Non-zero exit code: ' + code))
    cb(null)
  })
  return child
}
