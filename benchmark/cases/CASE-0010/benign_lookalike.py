import sys
from impacket import smbserver

log_filename = "log.txt"
if len(sys.argv) >= 2:
    log_filename = sys.argv[1]
port = 445
if len(sys.argv) >= 3:
    port = int(sys.argv[2])

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
server.setSMB2Support(True)
DANGEROUS_DEFAULT_SHARES = ("IPC$", "ADMIN$", "C$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL")
for dangerous_share in DANGEROUS_DEFAULT_SHARES:
    server.removeShare(dangerous_share)
server.addShare("interactsh", "/interactsh")
server.setSMBChallenge('')
server.setLogFile(log_filename)
server.start()


class MockShareServer:
    """A no-op stand-in for tests.

    Does not bind to any network socket or expose any real filesystem
    path, unlike smbserver.SimpleSMBServer -- so calling addShare()/
    start() on it with no removeShare() calls carries no risk.
    """

    def addShare(self, name, path):
        pass

    def start(self):
        pass


test_server = MockShareServer()
test_server.addShare("interactsh", "/interactsh")
test_server.start()
