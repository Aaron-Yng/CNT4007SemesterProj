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
                attr, val = line.split(" ")
                match attr:
                    case "NumberOfPreferredNeighbors":
                        self.preferred_neighbors = val
                        break
                    case "UnchokingInterval":
                        self.unchoking_interval = val
                        break
                    case "OptimisticUnchokingInterval":
                        self.optimistic_interval = val
                        break
                    case "FileName":
                        self.file_name = val
                        break
                    case "FileSize":
                        self.file_size = val
                        break
                    case "PieceSize":
                        self.piece_size = val
                        break
        
        #populate peer info, dict to hold id/info pairs
        self.peers = {}
        with peer_info.open() as f:
            for line in f:
                self.peers[line[0]] = [line[1], line[2], line[3]]



    #server side functionality
    #listens for connections
    #can get self peer vals from peer_info dict
    #when calling this, use a thread with daemon set to true
    #Thread(target= self.begin_listening, daemon= True)
    #this will cause it to run in background and terminate once program naturally ends
    def begin_listening(self):
        host, port, has = self.peers[id]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(host,port)
        sock.listen(self.preferred_neighbors)
        while True:
            connection = sock.accept()
            Thread(target= self.connect_peer, args= connection)
        

    #connect to peer
    #still in progress
    def connect_peer(self, connection: socket):
        #main func of peer class, main equivalent, does handshake then handles msgs
        return
        

if __name__ == "__main__":
    id: int = int(sys.argv[1])
    peer = Peer(id)

