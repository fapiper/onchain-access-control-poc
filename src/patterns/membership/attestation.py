import hashlib

from src.utils import zok_out_u32, write_witness_for_cli, zok_hash, read_amount_from_cli


def main():
    amount = read_amount_from_cli()

    leaves = [1337, 7, 1989, 51966, 1234, 9999, 0, 6]
    h0 = zok_hash(leaves[0], leaves[1])
    h1 = zok_hash(leaves[2], leaves[3])
    h2 = zok_hash(leaves[4], leaves[5])
    h3 = zok_hash(leaves[6], leaves[7])

    h00 = hashlib.sha256(h0 + h1).digest()
    h01 = hashlib.sha256(h2 + h3).digest()

    root = hashlib.sha256(h00 + h01).digest()

    msg = hashlib.sha256(int.to_bytes(leaves[1], 64, "big")).digest()
    msg += msg

    base = ["0", "0", "0", "0", "0", "0", "0"]
    l0 = base + [str(leaves[0])]
    l1 = base + [str(leaves[1])]

    # sys.stdout.write(" ".join([str(i) for i in l1]) + " " + zok_out_u32(root) + " " + dir + " " + " ".join(path) + " ")
    # sys.stdout.write(" ".join(l1 + zok_out_u32(root) + dir + path))

    direction = ["1", "0", "0"]
    path = l0 + [zok_out_u32(h1), zok_out_u32(h01)]
    params = l1 + [zok_out_u32(root)] + direction + path

    write_witness_for_cli(msg, params, amount)

if __name__ == "__main__":
    main()