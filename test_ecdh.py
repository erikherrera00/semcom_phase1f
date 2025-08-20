# test_ecdh.py
from ecdh_session import (
    start_handshake_initiator, respond_handshake_responder,
    finish_handshake_initiator, finish_handshake_responder
)
from pack_aad import pack_aad

hello, a_priv = start_handshake_initiator(session_id=42)
ack, a_pub, b_priv, sid = respond_handshake_responder(hello)
sess_a = finish_handshake_initiator(ack, a_priv, hello)
sess_b = finish_handshake_responder(b_priv, a_pub, ack)

aad = pack_aad(ver=1, suite=1, session_id=sid, msg_id=111, part_id=0, total_parts=1,
               n=26, k=20, interleave=6, dup=1, chunk_len=5)
nonce, ct = sess_a.encrypt(aad, b"hello")
assert sess_b.decrypt(aad, nonce, ct) == b"hello"
print("ECDH session test: OK")

