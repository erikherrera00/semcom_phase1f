from typing import Tuple, Dict, Any
from semantic_pb2 import Envelope, SemType, Command, Status, Alert, Ack

# Bump if the Envelope wrapper schema changes
SEM_VER = 1

# Map CLI names -> (enum code, protobuf class)
SEM_MAP = {
    "command": (SemType.SEM_COMMAND, Command),
    "status":  (SemType.SEM_STATUS,  Status),
    "alert":   (SemType.SEM_ALERT,   Alert),
    "ack":     (SemType.SEM_ACK,     Ack),
}

def _is_map_field(field) -> bool:
    # In python protobuf, a map is a repeated message with map_entry=True
    if field.label != field.LABEL_REPEATED:
        return False
    if field.type != field.TYPE_MESSAGE or field.message_type is None:
        return False
    return bool(field.message_type.GetOptions().map_entry)

def encode_from_json(sem_type_str: str, json_obj: Dict[str, Any]) -> Tuple[bytes, int, int]:
    """
    Build inner message from JSON, wrap in Envelope, return (wire_bytes, sem_type_code, sem_version).
    Handles map fields via .update().
    """
    sem_type_str = sem_type_str.lower()
    if sem_type_str not in SEM_MAP:
        raise ValueError(f"unknown semantic type: {sem_type_str}")
    sem_code, msg_cls = SEM_MAP[sem_type_str]

    msg = msg_cls()
    fd_by_name = msg.DESCRIPTOR.fields_by_name

    for k, v in json_obj.items():
        field = fd_by_name.get(k)
        if field is None:
            # Ignore unknown keys for forward-compat
            continue

        if _is_map_field(field):
            mp = getattr(msg, k)
            if isinstance(v, dict):
                # For map<string,string>, ensure str keys/values
                mp.update({str(kk): str(vv) for kk, vv in v.items()})
            else:
                raise TypeError(f"Field '{k}' is a map; expected object/dict, got {type(v).__name__}")
        else:
            try:
                setattr(msg, k, v)
            except Exception as e:
                raise TypeError(f"Invalid value for field '{k}': {v!r} ({e})") from e

    inner = msg.SerializeToString()
    env = Envelope(version=SEM_VER, type=sem_code, payload=inner)
    return env.SerializeToString(), int(sem_code), SEM_VER

def decode_to_dict(wire: bytes) -> Dict[str, Any]:
    """
    Parse Envelope -> dict form for pretty printing and app logic.
    Returns {"version":..., "type":..., "type_str":..., "body":{...}}.
    """
    env = Envelope()
    env.ParseFromString(wire)
    out: Dict[str, Any] = {"version": env.version, "type": int(env.type), "body": {}}

    if env.type == SemType.SEM_COMMAND:
        m = Command(); m.ParseFromString(env.payload)
        out.update(type_str="command", body={
            "name": m.name,
            "params": dict(m.params),
            "deadline_ms": int(m.deadline_ms),
        })
    elif env.type == SemType.SEM_STATUS:
        m = Status(); m.ParseFromString(env.payload)
        out.update(type_str="status", body={
            "system": m.system,
            "health": int(m.health),
            "metrics": dict(m.metrics),
        })
    elif env.type == SemType.SEM_ALERT:
        m = Alert(); m.ParseFromString(env.payload)
        out.update(type_str="alert", body={
            "level": m.level,
            "source": m.source,
            "detail": m.detail,
        })
    elif env.type == SemType.SEM_ACK:
        m = Ack(); m.ParseFromString(env.payload)
        out.update(type_str="ack", body={
            "ref_msg_id": int(m.ref_msg_id),
            "note": m.note,
        })
    else:
        out.update(type_str="unknown", body_raw_hex=env.payload.hex())

    return out
