from src.utils import write_cp_witness_for_cli, read_amount_from_cli, zok_out_u32, zok_hash_attr, zok_attr

def main():
    n_times = read_amount_from_cli()

    nonce = "3983795221"
    range_min = "1337"
    range_max = "51966"
    attr_key_bn = int.to_bytes(9, 64, "big")
    attr_value_bn = int.to_bytes(45054, 64, "big")

    commitment = zok_hash_attr(attr_key_bn, attr_value_bn)
    attr_key, attr_value = zok_attr(attr_key_bn, attr_value_bn)

    out = [range_min, range_max, commitment, attr_key, attr_value]

    write_cp_witness_for_cli(nonce, out, n_times)

if __name__ == "__main__":
    main()