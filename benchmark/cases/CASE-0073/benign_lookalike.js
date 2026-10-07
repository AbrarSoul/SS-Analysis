function restartNetworkTimeService() {
  // The entire command string is a fixed literal -- nothing here is
  // ever built from stream data or any other external input, so there
  // is no value an attacker could influence to reach this shell command.
  const command = `systemctl restart systemd-timesyncd`
  return require('child_process').spawn('sh', ['-c', command])
}

module.exports = { restartNetworkTimeService }
