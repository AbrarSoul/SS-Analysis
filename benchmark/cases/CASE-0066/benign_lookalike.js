const CONNECTION_STATE = Object.freeze({ CONNECTED: 1, DISCONNECTED: 0 });

function describeConnectionState(state) {
  // state is always CONNECTION_STATE.CONNECTED or .DISCONNECTED, both
  // fixed numeric constants defined above -- never a value taken from
  // an incoming socket message, so String() here can never invoke an
  // attacker-supplied toString().
  return `connection state: ${String(state)}`;
}

module.exports = { CONNECTION_STATE, describeConnectionState };
