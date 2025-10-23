import socket
import threading
from threading import Thread
import pathlib
from pathlib import Path
import sys
import struct
import math
import random
import time

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

def build_handshake(peer_id: int) -> bytes:
    return HANDSHAKE_HEADER + HANDSHAKE_PAD + _u32(peer_id)

def parse_handshake(data: bytes) -> int | None:
    if len(data) != 32 or not data.startswith(HANDSHAKE_HEADER):
        print(f"Bad handshake len={len(data)} data={data}")
        return None
    return _from_u32(data[-4:])
    

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

        #create dict of other connections
        self.connections = {}

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

        #created dict to store bitfields of other peers 
        self.peer_bitfields: dict[int, Bitfield] = {}

        #populate own bitfield based on has
        self.bitfield = Bitfield(math.ceil(self.file_size/self.piece_size), 0) if self.peers[self.id][2] == 0 else Bitfield(math.ceil(self.file_size/self.piece_size), 1)

        #dict to track states of peers
        #initial state is unchoked and not interested
        self.peer_states = {}
        for pid in self.peers.keys():
            self.peer_states[pid] = {
                "choked": True,
                "interested": False,
                "is_choked": True, #self is choked by other
                "is_interested": False
            }

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
            #s.sendall(_u32(self.id))
            # reuse handler (it will still send your 'hello' and close)
            self.connect_peer(s)
        except Exception as e:
            print(f"[peer {self.id}] dial to {host}:{port} failed: {e}") 

    #connect to peer
    #still in progress
    '''def connect_peer(self, connection: socket.socket):
        # main func of peer class, main equivalent, does handshake then handles msgs
        try:
            my_handshake = build_handshake(self.id)
            connection.sendall(my_handshake)
            # read 4 bytes peer id if the dialer sent it; if not present, ignore gracefully
            try:
                their_handshake = _recv_exact(connection, 32)
                other_id = parse_handshake(their_handshake)
                if other_id is None:
                    print(f"[peer {self.id}] invalid handshake received")
                    return
                self.log_connected_from(other_id)
                print(f"[peer {self.id}] handshake successfully with peer {other_id}")
            except Exception as e:
                print(f"[peer {self.id}] failed receiving handshake: {e}")
                return
            

                #connection.settimeout(1.0)
                #raw = _recv_exact(connection, 4)
                #other_id = _from_u32(raw)
                #self.log_connected_from(other_id)
        except Exception:
            pass
        finally:
            try:
                connection.settimeout(None)
            except:
                pass

            # minimal placeholder so we can see activity now (replace with real handshake later)
            #connection.sendall(b"hello from peer\n")

        except Exception as e:
        print(f"[peer {self.id}] handler error: {e}")
        finally:
            try:
                connection.close()
            except:
                pass
        return'''
    def connect_peer(self, connection: socket.socket):

        try:
            my_handshake = build_handshake(self.id)
            connection.sendall(my_handshake)

            try:
                their_handshake = _recv_exact(connection, 32)
                other_id = parse_handshake(their_handshake)
                if other_id is None:
                    print(f"[peer {self.id}] invalid handshake received")
                    return
                self.log_connected_from(other_id)
                print(f"[peer {self.id}] handshake successful with peer {other_id}")
                #add to connections
                self.connections[other_id] = connection

            except Exception as e:
                print(f"[peer {self.id}] failed receiving handshake: {e}")
                return

            total_pieces = (self.file_size + self.piece_size - 1) // self.piece_size
            self.total_pieces = total_pieces
            has_file = self.peers[self.id][2] == 1
            bitfield = Bitfield(total_pieces, has_file)
            self.send_msg(connection, MSG_BITFIELD, bitfield.to_bytes())
            self._log(f"Peer [{self.id}] sent BITFIELD to Peer [{other_id}].")

            while True:
                try:
                    msg_id, payload = self.recv_msg(connection)
                    self.handle_message(msg_id, payload, connection, other_id)
                except ConnectionError:
                    print(f"[peer {self.id}] connection closed by peer {other_id}")
                    break
                except Exception as e:
                    print(f"[peer {self.id}] error in message loop: {e}")
                    break

        except Exception as e:
            print(f"[peer {self.id}] handler error: {e}")

        finally:
            try:
                connection.close()
            except:
                pass
            print(f"[peer {self.id}] closed connection.")


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

    def handle_message(self, msg_id: int, payload: bytes, conn: socket.socket, other_id: int):
        if msg_id == MSG_CHOKE:
            self.peer_states[self.id]["choked"] = True
            self._log(f"Peer [{self.id}] received CHOKE.")
        elif msg_id == MSG_UNCHOKE:
            self.peer_states[self.id]["choked"] = False
            self._log(f"Peer [{self.id}] received UNCHOKE.")
        elif msg_id == MSG_INTERESTED:
            self.peer_states[self.id]["interested"] = True
            self._log(f"Peer [{self.id}] received INTERESTED.")
        elif msg_id == MSG_NOT_INTERESTED:
            self.peer_states[self.id]["interested"] = False
            self._log(f"Peer [{self.id}] received NOT INTERESTED.")
        elif msg_id == MSG_HAVE:
            #calls after request
            #set piece in other bitfield
            piece_index = _from_u32(payload)
            self.peer_bitfields[other_id].set_piece(piece_index)

            #check if interested
            if self.bitfield.has_piece(piece_index):
                #already has the piece
                self.send_not_interested(conn)
            else:
                #doesn't have piece, is interested
                self.send_interested(conn)
        elif msg_id == MSG_BITFIELD:
            self.peer_bitfields[other_id] = Bitfield.from_bytes(payload, self.total_pieces)
            print(f"[peer {self.id}] received bitfield {self.peer_bitfields[other_id][:8]}...")
            self._log(f"Peer [{self.id}] received BITFIELD.")

            if hasattr(self, "bitfield"):
                interested = any(
                    my_bit == 0 and their_bit == 1
                    for my_bit, their_bit in zip(self.bitfield.bits, self.peer_bitfields[other_id].bits)
                )
                if interested:
                    self.send_interested(conn)
                else:
                    self.send_not_interested(conn)
        elif msg_id == MSG_REQUEST:
            #requests transfer of certain piece after being unchoked
            #prevent request if currently choked else execute
            if not self.peer_states[self.id]["choked"]:
                self.send_request(conn, other_id)
            self._log()
        elif msg_id == MSG_PIECE:
            #sends payload of 4 byte piece
            #temporary log to prevent error msg
            self._log()

    def choke_peer(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_CHOKE)
        self.peer_states[other_id]["choked"] = True
        self._log(f"Peer [{self.id}] choked its connection.")

    def unchoke_peer(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_UNCHOKE)
        self.peer_states[other_id]["choked"] = False
        self._log(f"Peer [{self.id}] unchoked its connection.")

    def send_interested(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_INTERESTED)
        self.peer_states[other_id]["interested"] = True
        self._log(f"Peer [{self.id}] sent 'interested'.")
        print(f"[peer {self.id}] sent INTERESTED.")

    def send_not_interested(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_NOT_INTERESTED)
        self.peer_states[other_id]["interested"] = False
        self._log(f"Peer [{self.id}] sent 'not interested'.")
        print(f"[peer {self.id}] sent NOT INTERESTED.")

    def send_request(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_REQUEST)
        self._log(f"Peer [{self.id}] has downloaded the piece TBD from [{other_id}]")

    def choke_unchoke(self):
        #stop time for unchoking interval
        time.sleep(self.unchoking_interval)

        #get list of interested peers using list comprehension
        interested_peers = [pid for pid, vec in self.peer_states.items() if vec["interested"]]

        #get 'num = preferred neighbors' random set of interested peers, all interested peers if num interested is < num preferred
        preferred_peers = random.sample(interested_peers, min(self.preferred_neighbors, len(interested_peers)))

        for pid in self.peer_states:
            if pid in preferred_peers:
                self.peer_states[pid]["choked"] = False

                #check if connection exists and if it does then send msg to unchoke
                if self.connections[pid]:
                    self.unchoke_peer(self.connections[pid], pid)
            else:
                #must choke if not in preferred so num of peers currently unchoked doesn't exceed the preferred neighbors
                self.peer_states[pid]["choked"] = True

                #chokes if connection exists
                if self.connections[pid]:
                    self.choke_peer(self.connections[pid], pid)

        

    
class Bitfield:
    def __init__(self, total_pieces: int, has_all: bool):
        self.bits = [1 if has_all else 0] * total_pieces

    def has_piece(self, index: int) -> bool:
        return bool(self.bits[index])

    def set_piece(self, index: int):
        self.bits[index] = 1

    def to_bytes(self) -> bytes:
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            byte = 0
            for bit in self.bits[i:i+8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes, total_pieces: int):
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        b = cls(total_pieces, False)
        b.bits = bits[:total_pieces]
        return b

def handle_message(self, msg_id: int, payload: bytes, conn: socket.socket):
    if msg_id == MSG_CHOKE:
        self.choked = True
        self._log(f"Peer [{self.id}] received CHOKE.")
    elif msg_id == MSG_UNCHOKE:
        self.choked = False
        self._log(f"Peer [{self.id}] received UNCHOKE.")
    elif msg_id == MSG_INTERESTED:
        self.interested = True
        self._log(f"Peer [{self.id}] received INTERESTED.")
    elif msg_id == MSG_NOT_INTERESTED:
        self.interested = False
        self._log(f"Peer [{self.id}] received NOT INTERESTED.")
    elif msg_id == MSG_BITFIELD:
        other_bf = Bitfield.from_bytes(payload, self.total_pieces)
        print(f"[peer {self.id}] received bitfield {other_bf.bits[:8]}...")
        self._log(f"Peer [{self.id}] received BITFIELD.")




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
