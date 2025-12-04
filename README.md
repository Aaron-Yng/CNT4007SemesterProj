# CNT4007SemesterProj

## Group Members:
Aaron Young, Asrith Yerramesetty, Nicholas Tayag


## We met all requirements! Including hosting on multiple devices (demonstration in video)

## Nicholas Contribution

My main contributions to this project focused on improving the peer-to-peer communication visibility and making the system fully demo-ready. 

I implemented the logging for peer-to-peer connection events, including:
- `log_makes_connection()`  
- `log_connected_from()`  
- Handshake logging inside `connect_peer()`  
- Directional logs: **HANDSHAKE OUT** and **HANDSHAKE IN**
  
I added or expanded logging inside several message-related functions:

- `send_interested()`  
- `send_not_interested()`  
- `choke_peer()`  
- `unchoke_peer()`  
- `broadcast_have()`  
- `broadcast_complete()`

Earlier in the project, I contributed to building several core helper functions that support the message pipeline:

- `_recv_exact()` — safe, blocking read of exact byte counts  
- `_u32()` / `_from_u32()` — message length and ID encoding helpers  
- `build_handshake()` — creates the 32-byte handshake message  
- `parse_handshake()` — validates handshake format and extracts peer I


