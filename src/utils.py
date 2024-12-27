import argparse
import hashlib
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli
import sys

def zok_hash(lhs, rhs):
    preimage = int.to_bytes(lhs, 32, "big") + int.to_bytes(rhs, 32, "big")
    return hashlib.sha256(preimage).digest()

def zok_out_u32(msg):
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
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

def write_witness_for_cli(msg: bytes, out, n = 1):
    sk = PrivateKey.from_rand()

    digest = hashlib.sha256(msg).digest()
    digest += digest

    sig = sk.sign(digest)
    vk = PublicKey.from_private(sk)

    out.append(write_signature_for_zokrates_cli(vk, sig, digest))
    out_n = out * n

    sys.stdout.write(" ".join(out_n))