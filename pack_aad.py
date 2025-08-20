# pack_aad.py - add sem_type/sem_ver (uint16 each) at the end
import struct

def pack_aad(*, ver: int, suite: int, session_id: int,
             msg_id: int, part_id: int, total_parts: int,
             n: int, k: int, interleave: int, dup: int,
             chunk_len: int,
             sem_type: int = 0, sem_ver: int = 0) -> bytes:
    """
    AAD layout (big-endian):
    ver(1) | suite(1) | session_id(4) | msg_id(4) | part_id(2) | total_parts(2) |
    n(2) | k(2) | interleave(2) | dup(2) | chunk_len(4) | sem_type(2) | sem_ver(2)
    """
    return struct.pack(
        ">BBIIHHHHHHIHH",
        ver & 0xFF, suite & 0xFF,
        session_id & 0xFFFFFFFF,
        msg_id & 0xFFFFFFFF,
        part_id & 0xFFFF,
        total_parts & 0xFFFF,
        n & 0xFFFF, k & 0xFFFF,
        interleave & 0xFFFF, dup & 0xFFFF,
        chunk_len & 0xFFFFFFFF,
        sem_type & 0xFFFF, sem_ver & 0xFFFF
    )

