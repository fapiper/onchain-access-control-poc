import argparse
import hashlib
import struct
import sys

from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli

def hash_attr(key, value):
    digest = hashlib.sha256(b"".join([key[-32:], value[-32:]])).digest()
    digest += digest
    return digest

def out_u32(msg):
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    return b0, b1

def zok_attr(key, value):
    zok_key = " ".join([str(i) for i in struct.unpack(">16I", key)][-8:])
    zok_value = " ".join([str(i) for i in struct.unpack(">16I", value)][-8:])
    return zok_key, zok_value

def zok_hash_attr(key, value):
    return zok_out_u32(hash_attr(key, value))

def zok_hash(lhs, rhs):
    msg = int.to_bytes(lhs, 32, "big") + int.to_bytes(rhs, 32, "big")
    return hashlib.sha256(msg).digest()

def zok_out_u32(msg):
    b0, b1 = out_u32(msg)
    return " ".join(b0 + b1)

def write_signature_for_zokrates_cli(pk, sig, msg):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = " ".join(map(str, args))
    args = args + " " + zok_out_u32(msg)
    return args

def read_amount_from_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--amount', type=int, required=False,default=1)
    args = parser.parse_args()
    return args.amount

def write_witness_for_cli(nonce: str, msg: bytes, out, n = 1):
    sk = PrivateKey.from_rand()
    sig_R, sig_S = sk.sign(msg)
    pk = PublicKey.from_private(sk)
    out = out + [" ".join([str(sig_R.x), str(sig_R.y)]), sig_S, " ".join([str(pk.p.x.n), str(pk.p.y.n)]), zok_out_u32(msg)]
    out_n = [str(item) for item in out for i in range(n)]
    out_n.append(write_nonce_signature_for_cli(nonce))
    sys.stdout.write(" ".join(out_n))

def write_cp_witness_for_cli(nonce: str, out, n = 1):
    out_n = [item for item in out for i in range(n)]
    out_n.append(write_nonce_signature_for_cli(nonce))
    sys.stdout.write(" ".join(out_n))

def write_nonce_signature_for_cli(nonce: str):
    sk = PrivateKey.from_rand()
    msg = hashlib.sha512(nonce.encode("utf-8")).digest()
    sig = sk.sign(msg)
    vk = PublicKey.from_private(sk)
    return write_signature_for_zokrates_cli(vk, sig, msg)

def write_treecred_witness_for_cli(msg: bytes, out_single, out, n = 1):
    sk = PrivateKey.from_rand()

    digest = hashlib.sha256(msg).digest()
    digest += digest

    sig = sk.sign(digest)
    vk = PublicKey.from_private(sk)

    out_n = [item for item in out for i in range(n)]

    out_n += out_single
    out_n.append(write_signature_for_zokrates_cli(vk, sig, digest))

    sys.stdout.write(" ".join(out_n))