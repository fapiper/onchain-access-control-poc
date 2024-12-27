import hashlib

from src.utils import zok_out_u32, write_witness_for_cli, zok_hash, read_amount_from_cli


def main():
    amount = read_amount_from_cli()
    min = "1337"
    max = "51966"

    out = [min, max]

    attribute = 9
    value = 45054

    leaves = [attribute, value, 1989, 51966, 1234, 9999, 0, 6]
    h0 = zok_hash(leaves[0], leaves[1])
    h1 = zok_hash(leaves[2], leaves[3])
    h2 = zok_hash(leaves[4], leaves[5])
    h3 = zok_hash(leaves[6], leaves[7])

    h00 = hashlib.sha256(h0 + h1).digest()
    h01 = hashlib.sha256(h2 + h3).digest()

    root = hashlib.sha256(h00 + h01).digest()

    msg = root
    msg += msg

    base = ["0", "0", "0", "0", "0", "0", "0"]
    l0 = base + [str(leaves[0])]
    l1 = base + [str(leaves[1])]

    direction = ["1", "0", "0"]
    path = l0 + [zok_out_u32(h1), zok_out_u32(h01)]
    params = l1 + [zok_out_u32(root)] + direction + path

    write_witness_for_cli(msg, out + params, amount)

if __name__ == "__main__":
    main()