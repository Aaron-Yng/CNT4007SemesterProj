import socket
import threading
from threading import Thread
import pathlib
from pathlib import Path
import sys


class Peer:
    #constructor
    def __init__(self, id: int):
        self.id = id

        #create path objects for files
        common: Path = Path("Common.cfg")
        peer_info: Path = Path("PeerInfo.cfg")

        #populate common attributes
        with common.open() as f:
            for line in f:
                # FIX: robust split; keep reading all keys (no break)
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # split into key and value once
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                attr, val = parts[0], parts[1]
                match attr:
                    case "NumberOfPreferredNeighbors":
                        # FIX: cast to int; do not break so we can parse the rest
                        try:
                            self.preferred_neighbors = int(val)
                        except:
                            pass
                    case "UnchokingInterval":
                        try:
                            self.unchoking_interval = int(val)
                        except:
                            pass
                    case "OptimisticUnchokingInterval":
                        try:
                            self.optimistic_interval = int(val)
                        except:
                            pass
                    case "FileName":
                        self.file_name = val
                    case "FileSize":
                        try:
                            self.file_size = int(val)
                        except:
                            pass
                    case "PieceSize":
                        try:
                            self.piece_size = int(val)
                        except:
                            pass
              
        #populate peer info, dict to hold id/info pairs
#populate peer info, dict to hold id/info pairs
        self.peers = {}
        with peer_info.open() as f:
            for line in f:
                # FIX: parse by fields, not by single characters
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    pid = int(parts[0])
                    host = parts[1]
                    port = int(parts[2])
                    has = int(parts[3])
                    self.peers[pid] = (host, port, has)
                except: 
                    pass


    #server side functionality
    #listens for connections
    #can get self peer vals from peer_info dict
    #when calling this, use a thread with daemon set to true
    #Thread(target= self.begin_listening, daemon= True)
    #this will cause it to run in background and terminate once program naturally ends
    def begin_listening(self):
        # FIX: use self.id (not builtin id), and fetch tuple (host, port, has)
        if self.id not in self.peers:
            print(f"[peer {self.id}] not in PeerInfo.cfg; cannot listen.")
            return
        host, port, has = self.peers[self.id]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind((host, int(port)))

        sock.listen(int(self.preferred_neighbors))
        print(f"[peer {self.id}] listening on {host}:{port} (backlog={self.preferred_neighbors})")

        while True:
            try:
                connection, addr = sock.accept()
                print(f"[peer {self.id}] accepted from {addr}")
                Thread(target=self.connect_peer, args=(connection,), daemon=True).start()
            except Exception as e:
                print(f"[peer {self.id}] accept error: {e}")
                break

    # connect out to another peer using (host, port) from PeerInfo.cfg
    def dial_peer(self, host: str, port: int):
        try:
            s = socket.create_connection((host, int(port)), timeout=3)
            # reuse your per-connection handler exactly as-is
            self.connect_peer(s)
        except Exception as e:
            print(f"[peer {self.id}] dial to {host}:{port} failed: {e}")    

    #connect to peer
    #still in progress
    def connect_peer(self, connection: socket):
        #main func of peer class, main equivalent, does handshake then handles msgs
        # minimal placeholder so we can see activity now (replace with real handshake later)
        try:
            connection.sendall(b"hello from peer\n")
        except Exception as e:
            print(f"[peer {self.id}] handler error: {e}")
        finally:
            try:
                connection.close()
            except:
                pass
        return
    

if __name__ == "__main__":
    id: int = int(sys.argv[1])
    peer = Peer(id)
   
    # when calling this, use a thread with daemon set to true
    # Thread(target= self.begin_listening, daemon= True)
    t = Thread(target= peer.begin_listening, daemon= True)
    t.start()
    
    # autoconnector 
    for pid, info in peer.peers.items():
        if pid < peer.id:
            host, port, has = info
            Thread(target= peer.dial_peer, args=(host, port), daemon=True).start()

    
    try:
        while True:
            pass   # keep running; Ctrl+C to stop
    except KeyboardInterrupt:
        print(f"[peer {id}] exiting")
