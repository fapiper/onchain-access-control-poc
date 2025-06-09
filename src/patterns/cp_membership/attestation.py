import hashlib

from src.utils import write_cp_witness_for_cli, read_amount_from_cli, zok_out_u32, zok_hash_attr, zok_attr, zok_hash

def main():
    n_times = read_amount_from_cli()

    nonce = "3983795221"
    leaves = [1337, 7, 1989, 51966, 1234, 9999, 0, 6]

    attr_key_bn = int.to_bytes(9, 64, "big")
    attr_value_bn = int.to_bytes(leaves[1], 64, "big")
    commitment = zok_hash_attr(attr_key_bn, attr_value_bn)

    h0 = zok_hash(leaves[0], leaves[1])
    h1 = zok_hash(leaves[2], leaves[3])
    h2 = zok_hash(leaves[4], leaves[5])
    h3 = zok_hash(leaves[6], leaves[7])
    h00 = hashlib.sha256(h0 + h1).digest()
    h01 = hashlib.sha256(h2 + h3).digest()

    membership_path = ["0", "0", "0", "0", "0", "0", "0", str(leaves[0])] + [zok_out_u32(h1), zok_out_u32(h01)]
    membership_root = zok_out_u32(hashlib.sha256(h00 + h01).digest())
    membership_dir = ["1", "0", "0"]

    attr_key, attr_value = zok_attr(attr_key_bn, attr_value_bn)

    out = [membership_root] + membership_dir + membership_path  + [commitment, attr_key, attr_value]

    write_cp_witness_for_cli(nonce, out, n_times)

if __name__ == "__main__":
    main()