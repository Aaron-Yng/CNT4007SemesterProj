import socket
import threading
from threading import Thread
from pathlib import Path
import sys
import struct
import math
import random
import time

# Protocol Constants
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
MSG_COMPLETE = 8  # new: completion notification

# debug print bool
debug: bool = False


def build_handshake(peer_id: int) -> bytes:
    return HANDSHAKE_HEADER + HANDSHAKE_PAD + _u32(peer_id)


def parse_handshake(data: bytes) -> int | None:
    if len(data) != 32 or not data.startswith(HANDSHAKE_HEADER):
        if debug:
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
    # big-endian unsigned 32-bit
    return struct.pack(">I", int(i))


def _from_u32(b: bytes) -> int:
    """parse big-endian unsigned 32-bit"""
    return struct.unpack(">I", b)[0]


##########################################################################################
# File Manager Class
class FileManager:
    # constructor
    # assuming project only handles 1 file, so will store file specs including name in file manager itself
    def __init__(self, pid: int, file_name: str, file_size: int, piece_size: int, total_pieces: int, has_file: bool):
        self.pid = pid
        self.file_name = file_name
        self.file_size = file_size
        self.piece_size = piece_size
        self.total_pieces = total_pieces
        self.has_file = has_file

        self.directory = Path(str(pid))
        self.directory.mkdir(exist_ok=True)  # create dir if not exist
        self.pieces = [False] * total_pieces  # init local bitmap to all false
        self.data_array = [b""] * total_pieces
        self.lock = threading.Lock()  # lock to ensure threading safety

        self.load_file()  # get pieces and update the local bitmap (piece)

    # loads
    def load_file(self):
        if self.has_file:
            path = Path(self.directory, self.file_name)  # separate entire file into pieces
            data = path.read_bytes()  # get data from file in prep for portioning into pieces
            for i in range(self.total_pieces):
                piece_data = data[self.piece_size * i: self.piece_size * (i + 1)]
                self.data_array[i] = piece_data  # store piece data
                self.pieces[i] = True  # mark present
        else:
            # load current pieces in dir
            for i in range(self.total_pieces):
                path = Path(self.directory, f"piece_{i}")
                if path.exists():
                    piece_data = path.read_bytes()  # just read the piece file, no need for slicing
                    self.data_array[i] = piece_data
                    self.pieces[i] = True

    # getter setters
    def get_piece(self, pnum):
        return self.data_array[pnum]

    def set_piece(self, pnum, val):
        self.data_array[pnum] = val
        self.pieces[pnum] = True

        # write to dir
        path = Path(self.directory, f"piece_{pnum}")
        path.write_bytes(val)

    # file assembly
    def assemble_file(self):
        fpath = Path(self.directory, self.file_name)

        # DEBUG
        if debug:
            print(f"[FileManager] Assembling file to {fpath}")
            print(f"[FileManager] total_pieces={self.total_pieces}")
            print(f"[FileManager] data_array lengths: {[len(d) for d in self.data_array[:5]]}...")  # first 5

        total_bytes = 0
        with fpath.open("wb") as f:
            for i in range(self.total_pieces):
                chunk = self.data_array[i]
                total_bytes += len(chunk)
                f.write(chunk)

        if debug:
            print(f"[FileManager] Wrote {total_bytes} bytes total")

        # delete pieces
        for i in range(self.total_pieces):
            piece = Path(self.directory, f"piece_{i}")
            if piece.exists():
                piece.unlink()

        self.has_file = True


##########################################################################################
# Peer Class
class Peer:
    # constructor
    def __init__(self, id: int):
        self.id = id

        self.log_lock = threading.Lock()

        # create path objects for files
        common: Path = Path("Common.cfg")
        peer_info: Path = Path("PeerInfo.cfg")

        # create dict of other connections
        self.connections = {}

        # populate common attributes
        with common.open() as f:
            for line in f:
                # robust split; keep reading all keys
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                attr, val = parts[0], parts[1]
                match attr:
                    case "NumberOfPreferredNeighbors":
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

        # populate peer info, dict to hold id/info pairs
        self.peers = {}
        with peer_info.open() as f:
            for line in f:
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

        # calc total_pieces and store as property
        total_pieces = (self.file_size + self.piece_size - 1) // self.piece_size
        self.total_pieces = total_pieces
        if debug:
            print(f"[peer {self.id}] DEBUG: total_pieces = {total_pieces}")

        # dict to track states of peers
        # initial state is choked and not interested
        self.peer_states = {}
        for pid in self.peers.keys():
            self.peer_states[pid] = {
                "choked": True,
                "interested": False,   # they are interested in us
                "is_choked": True,     # self is choked by other
                "is_interested": False # we are interested in them
            }

        # Download tracking - bytes received from each peer in current interval
        self.download_counts = {}
        self.download_lock = threading.Lock()

        # Optimistic unchoke tracking
        self.optimistic_unchoked_peer = None

        # Track last preferred neighbors to reduce log spam
        self.last_preferred_peers: set[int] = set()

        # init a local file manager for this peer, accessing own has status
        self.file_manager = FileManager(
            self.id,
            self.file_name,
            self.file_size,
            self.piece_size,
            self.total_pieces,
            self.peers[self.id][2],
        )

        # created dict to store bitfields of other peers
        self.peer_bitfields: dict[int, Bitfield] = {}

        # populate own bitfield based on has
        has_file = self.peers[self.id][2] == 1
        self.bitfield = Bitfield(self.total_pieces, has_file)

        # completion tracking
        self.completed = {pid: False for pid in self.peers}
        self.terminated = False
        if self._has_complete_file():
            self.completed[self.id] = True

        # global and per-peer request tracking
        self.global_requests = set()
        self.pending_requests = {}

        # log startup configuration for demo/video
        self._log_startup_config()

    # ---------------------------------------------------------------------
    # Startup config logging (for video presentation + debugging)
    # ---------------------------------------------------------------------
    def _log_startup_config(self):
        """
        Log the key configuration and initial state when a peer starts.
        This is great to show in the demo/video.
        """
        self._log(
            f"STARTUP: Peer [{self.id}] loaded Common.cfg with "
            f"NumberOfPreferredNeighbors={getattr(self, 'preferred_neighbors', 'NA')}, "
            f"UnchokingInterval={getattr(self, 'unchoking_interval', 'NA')}s, "
            f"OptimisticUnchokingInterval={getattr(self, 'optimistic_interval', 'NA')}s, "
            f"FileName='{getattr(self, 'file_name', '')}', "
            f"FileSize={getattr(self, 'file_size', 0)} bytes, "
            f"PieceSize={getattr(self, 'piece_size', 0)} bytes, "
            f"TotalPieces={self.total_pieces}."
        )

        # Print PeerInfo summary
        for pid, (host, port, has) in self.peers.items():
            self._log(
                f"CONFIG: PeerInfo entry -> Peer [{pid}] at {host}:{port}, hasFile={has}."
            )

        # Initial bitfield preview
        preview_len = min(32, self.total_pieces)
        bit_preview = "".join(str(b) for b in self.bitfield.bits[:preview_len])
        self._log(
            f"INITIAL BITFIELD: Peer [{self.id}] first {preview_len} pieces = {bit_preview}"
        )

        has_file_flag = self.peers[self.id][2]
        self._log(
            f"INITIAL STATE: Peer [{self.id}] has_file={bool(has_file_flag)}, "
            f"completed[{self.id}]={self.completed[self.id]}."
        )

    # ---------------------------------------------------------------------
    # Messaging + networking
    # ---------------------------------------------------------------------
    def send_msg(self, sock: socket.socket, msg_id: int, payload: bytes = b"") -> None:
        try:
            length = 1 + (len(payload) if payload else 0)
            sock.sendall(_u32(length) + struct.pack("B", msg_id) + (payload or b""))
        except Exception as e:
            if debug:
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

    # server-side functionality
    def begin_listening(self):
        # use self.id and PeerInfo.cfg
        if self.id not in self.peers:
            self._log(f"ERROR: Peer [{self.id}] not in PeerInfo.cfg; cannot listen.")
            return
        host, port, has = self.peers[self.id]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind((host, int(port)))
        sock.listen(int(self.preferred_neighbors))

        self._log(
            f"LISTEN: Peer [{self.id}] listening on {host}:{port} "
            f"(backlog={self.preferred_neighbors})."
        )

        while True:
            try:
                connection, addr = sock.accept()
                self._log(
                    f"ACCEPT: Peer [{self.id}] accepted inbound TCP connection from {addr}."
                )
                Thread(target=self.connect_peer, args=(connection,), daemon=True).start()
            except Exception as e:
                self._log(f"ACCEPT ERROR: {e}")
                break

    # connect out to another peer using (host, port) from PeerInfo.cfg
    def dial_peer(self, host: str, port: int, remote_id: int):
        if remote_id in self.connections:
            return

        try:
            self.log_makes_connection(remote_id)
            s = socket.create_connection((host, int(port)), timeout=3)
            self._log(
                f"TCP CONNECTION BUILT: Peer [{self.id}] connected to Peer [{remote_id}] "
                f"at {host}:{port}."
            )
            # reuse handler
            self.connect_peer(s)
        except Exception as e:
            self._log(
                f"DIAL ERROR: Peer [{self.id}] failed to connect to Peer [{remote_id}] "
                f"at {host}:{port}. Error={e}"
            )

    def connect_peer(self, connection: socket.socket):
        if other_id in self.connections:
            try:
                connection.close()
            except:
                pass
            return

        try:
            my_handshake = build_handshake(self.id)
            connection.sendall(my_handshake)

            try:
                their_handshake = _recv_exact(connection, 32)
                other_id = parse_handshake(their_handshake)
                if other_id is None:
                    if debug:
                        print(f"[peer {self.id}] invalid handshake received")
                    return
                self.log_connected_from(other_id)
                if debug:
                    print(f"[peer {self.id}] handshake successful with peer {other_id}")
                # add to connections
                self.connections[other_id] = connection

            except Exception as e:
                if debug:
                    print(f"[peer {self.id}] failed receiving handshake: {e}")
                return

            # send BITFIELD only if we have at least one piece
            if any(self.bitfield.bits):
                self.send_msg(connection, MSG_BITFIELD, self.bitfield.to_bytes())
                self._log(f"Peer [{self.id}] sent BITFIELD to Peer [{other_id}].")

            while True:
                try:
                    msg_id, payload = self.recv_msg(connection)
                    self.handle_message(msg_id, payload, connection, other_id)
                except ConnectionError:
                    if debug:
                        print(f"[peer {self.id}] connection closed by peer {other_id}")
                    break
                except Exception as e:
                    if debug:
                        print(f"[peer {self.id}] error in message loop: {e}")
                    break

        except Exception as e:
            if debug:
                print(f"[peer {self.id}] handler error: {e}")

        finally:
            try:
                connection.close()
            except:
                pass
            if debug:
                print(f"[peer {self.id}] closed connection.")

    # log helpers
    def _log_path(self) -> Path:
        return Path(f"log_peer_{self.id}.log")

    def _timestamp(self) -> str:
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _log(self, line: str) -> None:
        """
        Write log line to file AND print it nicely to the terminal.
        """
        ts = self._timestamp()
        formatted = f"[{ts}] {line}"

        # write to log file
        with self.log_lock:
            try:
                with self._log_path().open("a", encoding="utf-8") as f:
                    f.write(formatted + "\n")
            except Exception as e:
                if debug:
                    print(f"[peer {self.id}] log error: {e}")

        # mirror to console
        print(f"[peer {self.id}] {formatted}")

    def log_makes_connection(self, other_id: int) -> None:
        self._log(f"PLAN: Peer [{self.id}] will make a connection to Peer [{other_id}].")

    def log_connected_from(self, other_id: int) -> None:
        self._log(f"Peer [{self.id}] is connected from Peer [{other_id}].")

    # ---------------------------------------------------------------------
    # Message handling
    # ---------------------------------------------------------------------
    def handle_message(self, msg_id: int, payload: bytes, conn: socket.socket, other_id: int):
        if msg_id == MSG_CHOKE:
            self.peer_states[other_id]["is_choked"] = True
            self._log(f"Peer [{self.id}] is choked by [{other_id}].")
            if debug:
                print(f"[peer {self.id}] choked by peer {other_id}")

            # cancel pending request, if any
            if other_id in self.pending_requests:
                piece_lost = self.pending_requests.pop(other_id)
                if piece_lost in self.global_requests:
                    self.global_requests.remove(piece_lost)
                self._log(
                    f"Peer [{self.id}] pending request {piece_lost} cancelled due to choke by [{other_id}]."
                )

        elif msg_id == MSG_UNCHOKE:
            self.peer_states[other_id]["is_choked"] = False
            self._log(f"Peer [{self.id}] is unchoked by [{other_id}].")
            if debug:
                print(f"[peer {self.id}] unchoked by peer {other_id}")
            self.request_piece(conn, other_id)

        elif msg_id == MSG_INTERESTED:
            self.peer_states[other_id]["interested"] = True
            self._log(f"Peer [{self.id}] received the 'interested' message from [{other_id}].")
            if debug:
                print(f"[peer {self.id}] received INTERESTED from peer {other_id}")

        elif msg_id == MSG_NOT_INTERESTED:
            self.peer_states[other_id]["interested"] = False
            self._log(f"Peer [{self.id}] received the 'not interested' message from [{other_id}].")
            if debug:
                print(f"[peer {self.id}] received NOT INTERESTED from peer {other_id}")

        elif msg_id == MSG_HAVE:
            piece_index = _from_u32(payload)
            # ensure bitfield exists for this peer
            if other_id not in self.peer_bitfields:
                self.peer_bitfields[other_id] = Bitfield(self.total_pieces, False)
            self.peer_bitfields[other_id].set_piece(piece_index)
            self._log(
                f"Peer [{self.id}] received the 'have' message from [{other_id}] for the piece {piece_index}."
            )
            if debug:
                print(f"[peer {self.id}] received HAVE for piece {piece_index} from peer {other_id}")

            # Decide if we are (still) interested in this neighbor
            if self._has_interesting_pieces(other_id):
                self.send_interested(conn, other_id)
            else:
                self.send_not_interested(conn, other_id)

        elif msg_id == MSG_BITFIELD:
            self.peer_bitfields[other_id] = Bitfield.from_bytes(payload, self.total_pieces)
            if debug:
                print(
                    f"[peer {self.id}] DEBUG: received bitfield with "
                    f"{sum(self.peer_bitfields[other_id].bits)} pieces set out of {self.total_pieces}"
                )
                print(f"[peer {self.id}] received bitfield {self.peer_bitfields[other_id].bits[:8]}...")
            self._log(f"Peer [{self.id}] received BITFIELD from [{other_id}].")

            if self._has_interesting_pieces(other_id):
                self.send_interested(conn, other_id)
            else:
                self.send_not_interested(conn, other_id)

        elif msg_id == MSG_REQUEST:
            piece_index = _from_u32(payload)
            if debug:
                print(f"[peer {self.id}] received REQUEST for piece {piece_index} from peer {other_id}")

            if not self.peer_states[other_id]["choked"] and self.bitfield.has_piece(piece_index):
                piece_data = self.file_manager.get_piece(piece_index)
                piece_payload = _u32(piece_index) + piece_data
                self.send_msg(conn, MSG_PIECE, piece_payload)
                if debug:
                    print(f"[peer {self.id}] sent PIECE {piece_index} to peer {other_id}")
            else:
                if debug:
                    print(f"[peer {self.id}] denied REQUEST for piece {piece_index} (choked or don't have)")

        elif msg_id == MSG_PIECE:
            piece_index = _from_u32(payload[:4])
            piece_data = payload[4:]

            # clear global/pending request tracking
            if other_id in self.pending_requests and self.pending_requests[other_id] == piece_index:
                del self.pending_requests[other_id]
            if piece_index in self.global_requests:
                self.global_requests.remove(piece_index)

            self.record_download(other_id, len(piece_data))

            with self.file_manager.lock:
                self.file_manager.set_piece(piece_index, piece_data)
                self.bitfield.set_piece(piece_index)

            num_pieces = sum(self.bitfield.bits)

            self._log(
                f"Peer [{self.id}] has downloaded the piece {piece_index} from [{other_id}]. "
                f"Now the number of pieces it has is {num_pieces}."
            )
            if debug:
                print(
                    f"[peer {self.id}] received PIECE {piece_index} from peer {other_id}. "
                    f"Total pieces: {num_pieces}"
                )

            self.broadcast_have(piece_index)

            if num_pieces == self.total_pieces:
                self.file_manager.assemble_file()
                self._log(f"Peer [{self.id}] has downloaded the COMPLETE file.")
                if debug:
                    print(f"[peer {self.id}] COMPLETE FILE DOWNLOADED!")
                self.completed[self.id] = True
                self.broadcast_complete()
                self.check_for_shutdown()
            else:
                if not self.peer_states[other_id]["is_choked"]:
                    self.request_piece(conn, other_id)

        elif msg_id == MSG_COMPLETE:
            self.completed[other_id] = True
            self._log(f"Peer [{self.id}] received COMPLETE from [{other_id}].")
            if debug:
                print(f"[peer {self.id}] peer {other_id} reported completion.")
            self.check_for_shutdown()

    def _has_interesting_pieces(self, other_id: int) -> bool:
        if other_id not in self.peer_bitfields:
            return False
        other_bits = self.peer_bitfields[other_id].bits
        my_bits = self.bitfield.bits
        return any(my == 0 and their == 1 for my, their in zip(my_bits, other_bits))

    def _has_complete_file(self) -> bool:
        return all(self.bitfield.bits)

    def request_piece(self, conn: socket.socket, other_id: int):
        # only one outstanding request per peer
        if other_id in self.pending_requests:
            return

        if other_id not in self.peer_bitfields:
            return

        available_pieces = []
        for i in range(self.total_pieces):
            if (
                self.peer_bitfields[other_id].has_piece(i)
                and not self.bitfield.has_piece(i)
                and i not in self.global_requests
            ):
                available_pieces.append(i)

        if not available_pieces:
            if debug:
                print(f"[peer {self.id}] no pieces to request from peer {other_id}")
            return

        piece_index = random.choice(available_pieces)

        # track globally + per-peer
        self.global_requests.add(piece_index)
        self.pending_requests[other_id] = piece_index

        self.send_msg(conn, MSG_REQUEST, _u32(piece_index))
        self._log(f"Peer [{self.id}] requested piece {piece_index} from [{other_id}].")
        if debug:
            print(f"[peer {self.id}] sent REQUEST for piece {piece_index} to peer {other_id}")

    def broadcast_have(self, piece_index: int):
        for pid, conn in self.connections.items():
            try:
                self.send_msg(conn, MSG_HAVE, _u32(piece_index))
                if debug:
                    print(f"[peer {self.id}] sent HAVE for piece {piece_index} to peer {pid}")
            except Exception as e:
                if debug:
                    print(f"[peer {self.id}] failed to send HAVE to peer {pid}: {e}")

    def broadcast_complete(self):
        for pid, conn in self.connections.items():
            try:
                self.send_msg(conn, MSG_COMPLETE)
                if debug:
                    print(f"[peer {self.id}] sent COMPLETE to peer {pid}")
            except Exception:
                pass

    def check_for_shutdown(self):
        if self.terminated:
            return

        if all(self.completed.values()):
            self.terminated = True
            self._log(f"Peer [{self.id}] terminating: All peers have completed the file.")
            if debug:
                print(f"[peer {self.id}] ALL PEERS COMPLETE — shutting down.")

            for conn in list(self.connections.values()):
                try:
                    conn.close()
                except:
                    pass

            sys.exit(0)

    def record_download(self, from_peer: int, num_bytes: int):
        with self.download_lock:
            if from_peer not in self.download_counts:
                self.download_counts[from_peer] = 0
            self.download_counts[from_peer] += num_bytes

    def choke_peer(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_CHOKE)
        self.peer_states[other_id]["choked"] = True
        self._log(f"Peer [{self.id}] choked its connection.")

    def unchoke_peer(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_UNCHOKE)
        self.peer_states[other_id]["choked"] = False
        self._log(f"Peer [{self.id}] unchoked its connection.")

    def send_interested(self, conn: socket.socket, other_id: int):
        """
        Send INTERESTED only if we are transitioning from
        not-interested -> interested for this peer.
        """
        if self.peer_states[other_id]["is_interested"]:
            if debug:
                print(f"[peer {self.id}] already INTERESTED in {other_id}, not resending")
            return

        self.send_msg(conn, MSG_INTERESTED)
        self.peer_states[other_id]["is_interested"] = True
        self._log(f"Peer [{self.id}] sent 'interested' to [{other_id}].")
        if debug:
            print(f"[peer {self.id}] sent INTERESTED to peer {other_id}")

    def send_not_interested(self, conn: socket.socket, other_id: int):
        """
        Send NOT_INTERESTED only if we are transitioning from
        interested -> not-interested for this peer.
        """
        if not self.peer_states[other_id]["is_interested"]:
            if debug:
                print(f"[peer {self.id}] already NOT INTERESTED in {other_id}, not resending")
            return

        self.send_msg(conn, MSG_NOT_INTERESTED)
        self.peer_states[other_id]["is_interested"] = False
        self._log(f"Peer [{self.id}] sent 'not interested' to [{other_id}].")
        if debug:
            print(f"[peer {self.id}] sent NOT INTERESTED to peer {other_id}")

    def send_request(self, conn: socket.socket, other_id):
        self.send_msg(conn, MSG_REQUEST)
        self._log(f"Peer [{self.id}] has downloaded the piece TBD from [{other_id}]")

    def start_choke_unchoke_loop(self):
        """Periodically select preferred neighbors."""
        while True:
            time.sleep(self.unchoking_interval)
            self.select_preferred_neighbors()

    def select_preferred_neighbors(self):
        """Select and unchoke preferred neighbors based on download rate."""

        # Get interested peers that we have connections to
        interested_peers = [
            pid
            for pid, state in self.peer_states.items()
            if state["interested"] and pid in self.connections
        ]

        if not interested_peers:
            if debug:
                print(f"[peer {self.id}] no interested peers to unchoke")
            return

        # Determine preferred peers
        if self._has_complete_file():
            # Random selection if we have complete file
            num_to_select = min(self.preferred_neighbors, len(interested_peers))
            preferred_peers = random.sample(interested_peers, num_to_select)
        else:
            # Select by download rate
            with self.download_lock:
                # Sort by download rate (descending)
                rates = [(pid, self.download_counts.get(pid, 0)) for pid in interested_peers]
                rates.sort(key=lambda x: x[1], reverse=True)

                # Handle ties randomly - group by rate, shuffle within groups
                grouped = {}
                for pid, rate in rates:
                    if rate not in grouped:
                        grouped[rate] = []
                    grouped[rate].append(pid)

                sorted_peers = []
                for rate in sorted(grouped.keys(), reverse=True):
                    peers_at_rate = grouped[rate]
                    random.shuffle(peers_at_rate)
                    sorted_peers.extend(peers_at_rate)

                preferred_peers = sorted_peers[: self.preferred_neighbors]

                # Reset download counts for next interval
                self.download_counts.clear()

        # Log preferred neighbors only if the set changed
        new_set = set(preferred_peers)
        if new_set != self.last_preferred_peers:
            self.last_preferred_peers = new_set
            self._log(
                f"Peer [{self.id}] has the preferred neighbors {','.join(map(str, preferred_peers))}."
            )
        if debug:
            print(f"[peer {self.id}] preferred neighbors: {preferred_peers}")

        # Unchoke preferred, choke others (but not optimistic unchoke)
        for pid in list(self.connections.keys()):
            if pid in preferred_peers:
                if self.peer_states[pid]["choked"]:
                    self.unchoke_peer(self.connections[pid], pid)
            else:
                # Don't choke the optimistically unchoked peer
                if pid != self.optimistic_unchoked_peer:
                    if not self.peer_states[pid]["choked"]:
                        self.choke_peer(self.connections[pid], pid)

    def start_optimistic_unchoke_loop(self):
        """Periodically select optimistically unchoked neighbor."""
        while True:
            time.sleep(self.optimistic_interval)
            self.select_optimistic_unchoke()

    def select_optimistic_unchoke(self):
        """Randomly select one choked but interested peer to unchoke."""

        # Find choked but interested peers
        candidates = [
            pid
            for pid, state in self.peer_states.items()
            if state["choked"] and state["interested"] and pid in self.connections
        ]

        if not candidates:
            if debug:
                print(f"[peer {self.id}] no candidates for optimistic unchoke")
            return

        # Randomly select one
        selected = random.choice(candidates)
        self.optimistic_unchoked_peer = selected

        # Unchoke them
        self.unchoke_peer(self.connections[selected], selected)

        self._log(f"Peer [{self.id}] has the optimistically unchoked neighbor {selected}.")
        if debug:
            print(f"[peer {self.id}] optimistically unchoked: {selected}")


##########################################################################################
# Bitfield Class
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
            chunk = self.bits[i:i + 8]
            for bit in chunk:
                byte = (byte << 1) | bit
            # Pad with zeros if last chunk is less than 8 bits
            byte <<= (8 - len(chunk))
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


##########################################################################################
# Main Function
if __name__ == "__main__":
    id: int = int(sys.argv[1])
    peer = Peer(id)

    # Nice extra log for the beginning of the demo
    peer._log(f"PROCESS START: Peer [{id}] is up and running.")

    # listener
    t = Thread(target=peer.begin_listening, daemon=True)
    t.start()

    # periodic choke/unchoke
    unchoke_thread = Thread(target=peer.start_choke_unchoke_loop, daemon=True)
    unchoke_thread.start()

    # optimistic unchoke loop
    optimistic_thread = Thread(target=peer.start_optimistic_unchoke_loop, daemon=True)
    optimistic_thread.start()

    # autoconnector
    for pid, info in peer.peers.items():
        if pid < peer.id:
            host, port, has = info
            Thread(target=peer.dial_peer, args=(host, port, pid), daemon=True).start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        peer._log(f"MANUAL EXIT: Peer [{id}] received KeyboardInterrupt and is exiting.")
