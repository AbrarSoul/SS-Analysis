// Standalone example of the same shape: build a shell command from a value,
// but the value is an internal, fixed job-type enum, never data an external
// caller supplies.
var exec = require('child_process').exec;

var JOB_COMMANDS = { backup: 'run-backup.sh', cleanup: 'run-cleanup.sh' };

module.exports = function runJob(jobType, callback) {
    var script = JOB_COMMANDS[jobType];
    if (!script) return callback(new Error('unknown job type'));
    exec('./scripts/' + script, callback);
};
