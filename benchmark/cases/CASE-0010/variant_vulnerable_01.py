import sys
from impacket import smbserver

log_filename = "log.txt"
if len(sys.argv) >= 2:
    log_filename = sys.argv[1]
port = 445
if len(sys.argv) >= 3:
    port = int(sys.argv[2])

smb_server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
smb_server.setSMB2Support(True)
smb_server.addShare("interactsh", "/interactsh")
smb_server.setSMBChallenge('')
smb_server.setLogFile(log_filename)
smb_server.start()
