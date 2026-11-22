"""Decode ATT writes/notifications in an Apple PacketLogger (.pklg) capture and decrypt CSRmesh packets.
Usage: python3 -I pklg_decode.py capture.pklg PIN
Prints every ATT write/notify with handle and bytes, reassembles CSRmesh MTL packets, and decrypts them.
"""
import sys, struct, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers.modes import OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import OFB

def key_from(pin):
    d = bytearray(hashlib.sha256(pin.encode() + b"\x00MCP").digest()); d.reverse(); return bytes(d)[:16]

def try_decrypt(k, p):
    for body in (p[:-1], p):
        if len(body) < 13: continue
        seq, src, ct, mac = body[:3], body[3:5], body[5:-8], body[-8:]
        h = bytearray(hmac.new(k, b"\0"*8 + seq + src + ct, hashlib.sha256).digest()); h.reverse()
        if bytes(h)[:8] == mac:
            d = Cipher(algorithms.AES(k), OFB(seq + b"\0" + src + b"\0"*10)).decryptor()
            return int.from_bytes(src, "little"), (d.update(ct) + d.finalize())
    return None

def records(data):
    i = 0
    while i + 13 <= len(data):
        ln = struct.unpack(">I", data[i:i+4])[0]
        ts_s, ts_us = struct.unpack(">II", data[i+4:i+12])
        typ = data[i+12]; payload = data[i+13:i+4+ln]
        yield ts_s + ts_us/1e6, typ, payload
        i += 4 + ln

def main():
    data = open(sys.argv[1], "rb").read(); k = key_from(sys.argv[2])
    pend = {}
    for ts, typ, p in records(data):
        if typ not in (2, 3) or len(p) < 9: continue  # 2=ACL sent, 3=ACL recv
        conn = struct.unpack("<H", p[0:2])[0] & 0x0fff
        l2len, cid = struct.unpack("<HH", p[4:8])
        if cid != 4: continue
        att = p[8:]; op = att[0]
        if op in (0x12, 0x52, 0x1b, 0x1d) and len(att) >= 3:
            h = struct.unpack("<H", att[1:3])[0]; val = att[3:]
            dirn = "->" if typ == 2 else "<-"
            print(f"{ts:.3f} conn{conn} {dirn} op{op:02x} h{h:04x} {val.hex(' ')}")
            buf = pend.setdefault((conn, dirn), b"") + val
            r = try_decrypt(k, buf)
            if r:
                print(f"      MESH src {r[0]:04x}: {r[1].hex(' ')}"); pend[(conn, dirn)] = b""
            elif len(buf) > 60: pend[(conn, dirn)] = b""
            else: pend[(conn, dirn)] = buf
main()
