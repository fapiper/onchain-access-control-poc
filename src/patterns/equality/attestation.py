import struct
from src.utils import write_witness_for_cli, read_amount_from_cli


def main():
    amount = read_amount_from_cli()

    attribute = int.to_bytes(24, 64, "big")
    value = int.to_bytes(19890519, 64, "big")

    msg = b"".join([p[-32:] for p in [attribute, value]])

    params = [" ".join([str(i) for i in struct.unpack(">16I", attribute)][-8:]) for p in [attribute, value]]

    write_witness_for_cli(msg, params, amount)

if __name__ == "__main__":
    main()