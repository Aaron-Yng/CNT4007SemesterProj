import socket
import threading
from threading import Thread
import pathlib
from pathlib import Path
import sys
import struct

# Protocal Constants
HANDSHAKE_HEADER = b"P2PFILESHARINGPROJ"  # 18 bytes
HANDSHAKE_PAD = b"\x00" * 10              # 10 bytes

# message type IDs
MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_NOT_INTERESTED = 3
MSG_HAVE = 4
MSG_BITFIELD = 5
MSG_REQUEST = 6
MSG_PIECE = 7


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    # Receive exactly n bytes from a blocking socket.
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed while receiving")
        data += chunk
    return data


def _u32(i: int) -> bytes:
    #big-endian unsigned 32-bit
    return struct.pack(">I", int(i))


def _from_u32(b: bytes) -> int:
    """parse big-endian unsigned 32-bit"""
    return struct.unpack(">I", b)[0]


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

        # ---- message framing helpers (length-prefixed per spec) ----
    
    def send_msg(self, sock: socket.socket, msg_id: int, payload: bytes = b"") -> None:
        try:
            length = 1 + (len(payload) if payload else 0)
            sock.sendall(_u32(length) + struct.pack("B", msg_id) + (payload or b""))
        except Exception as e:
            # For midpoint we just print; later we might log/raise
            print(f"[peer {self.id}] send_msg error: {e}")

    def recv_msg(self, sock: socket.socket) -> tuple[int, bytes]:
        hdr = _recv_exact(sock, 4)
        (length,) = struct.unpack(">I", hdr)
        if length < 1:
            raise ValueError("invalid message length")
        body = _recv_exact(sock, length)
        msg_id = body[0]
        payload = body[1:]
        return msg_id, payload

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
    def dial_peer(self, host: str, port: int, remote_id: int):
        try:
            s = socket.create_connection((host, int(port)), timeout=3)
            # log: we (self.id) make a connection to remote_id
            self.log_makes_connection(remote_id)
            # send our peer id (4 bytes) so the server can log "connected from"
            s.sendall(_u32(self.id))
            # reuse handler (it will still send your 'hello' and close)
            self.connect_peer(s)
        except Exception as e:
            print(f"[peer {self.id}] dial to {host}:{port} failed: {e}") 

    #connect to peer
    #still in progress
    def connect_peer(self, connection: socket.socket):
        # main func of peer class, main equivalent, does handshake then handles msgs
        try:
            # read 4 bytes peer id if the dialer sent it; if not present, ignore gracefully
            try:
                connection.settimeout(1.0)
                raw = _recv_exact(connection, 4)
                other_id = _from_u32(raw)
                self.log_connected_from(other_id)
            except Exception:
                pass
            finally:
                try:
                    connection.settimeout(None)
                except:
                    pass

            # minimal placeholder so we can see activity now (replace with real handshake later)
            connection.sendall(b"hello from peer\n")

        except Exception as e:
            print(f"[peer {self.id}] handler error: {e}")
        finally:
            try:
                connection.close()
            except:
                pass
        return

# log helpers for TCP connection events (simplified versions)
    def _log_path(self) -> Path:
        return Path(f"log_peer_{self.id}.log")

    def _timestamp(self) -> str:
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _log(self, line: str) -> None:
        try:
            with self._log_path().open("a", encoding="utf-8") as f:
                f.write(f"[{self._timestamp()}]: {line}\n")
        except Exception as e:
            print(f"[peer {self.id}] log error: {e}")

    def log_makes_connection(self, other_id: int) -> None:
        self._log(f"Peer [{self.id}] makes a connection to Peer [{other_id}].")

    def log_connected_from(self, other_id: int) -> None:
        self._log(f"Peer [{self.id}] is connected from Peer [{other_id}].")


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
            Thread(target=peer.dial_peer, args=(host, port, pid), daemon=True).start()

    
    try:
        while True:
            pass   # keep running; Ctrl+C to stop
    except KeyboardInterrupt:
        print(f"[peer {id}] exiting")
