from poseidon_py.poseidon_hash import (
    poseidon_perm,
    poseidon_hash_func,
    poseidon_hash as lib_poseidon_hash,
    poseidon_hash_single,
    poseidon_hash_many,
)
from poseidon_py.utils import to_bytes

def poseidon_hash(x, y):
    return lib_poseidon_hash(x, y)
