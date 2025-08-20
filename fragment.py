# fragment.py
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass(frozen=True)
class Part:
    msg_id: int
    part_id: int
    total_parts: int
    payload: bytes  # this is the cleartext segment that will be encrypted

MAX_PART = 512  # bytes before encryption (tunable; profile-specific)

def fragment(msg_id: int, data: bytes, max_part: int = MAX_PART) -> List[Part]:
    assert max_part > 0
    parts = []
    total = (len(data) + max_part - 1) // max_part or 1
    for i in range(total):
        seg = data[i*max_part:(i+1)*max_part]
        parts.append(Part(msg_id=msg_id, part_id=i, total_parts=total, payload=seg))
    return parts

class Reassembler:
    """Loss/dup/out-of-order tolerant reassembler."""
    def __init__(self, cap_msgs: int = 1024):
        self._msgs: Dict[int, Dict[int, bytes]] = {}
        self._totals: Dict[int, int] = {}
        self._cap = cap_msgs

    def offer(self, msg_id: int, part_id: int, total_parts: int, payload: bytes) -> Optional[bytes]:
        if msg_id not in self._msgs:
            if len(self._msgs) >= self._cap:
                # simple eviction: drop oldest
                self._msgs.pop(next(iter(self._msgs)))
                self._totals.pop(next(iter(self._totals)))
            self._msgs[msg_id] = {}
            self._totals[msg_id] = total_parts
        # ignore mismatched totals to avoid poisoning
        if self._totals.get(msg_id) != total_parts:
            return None
        # dedupe
        if part_id in self._msgs[msg_id]:
            return None
        self._msgs[msg_id][part_id] = payload
        # complete?
        if len(self._msgs[msg_id]) == total_parts:
            parts = [self._msgs[msg_id][i] for i in range(total_parts)]
            data = b"".join(parts)
            del self._msgs[msg_id]; del self._totals[msg_id]
            return data
        return None


