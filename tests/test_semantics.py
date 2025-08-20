from semcodec import encode_from_json, decode_to_dict

def test_status_roundtrip():
    payload = {"system":"uav-12","health":92,"metrics":{"cpu":"43","temp":"59C"}}
    wire, code, ver = encode_from_json("status", payload)
    info = decode_to_dict(wire)
    assert info["type_str"] == "status"
    assert info["body"]["system"] == "uav-12"
    assert info["body"]["metrics"]["cpu"] == "43"
