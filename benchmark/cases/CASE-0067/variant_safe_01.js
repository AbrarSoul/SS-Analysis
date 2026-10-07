function createBackoffLogger() {
  const counts = new Map();

  return {
    log(message) {
      const count = (counts.get(message) || 0) + 1;
      counts.set(message, count);
      // Only log on powers of 10: 1st, 10th, 100th, ... occurrence.
      if (count === 1 || count % Math.pow(10, Math.floor(Math.log10(count))) === 0) {
        console.log(`${message} (occurrence #${count})`);
      }
    },
  };
}

function attachSendHandler(ws, term, data) {
  ws.errorLogger = ws.errorLogger || createBackoffLogger();
  ws.send(data, function (error) {
    if (error) {
      ws.errorLogger.log('Send error: ' + error.message);
    }
  });
}

module.exports = { createBackoffLogger, attachSendHandler };
