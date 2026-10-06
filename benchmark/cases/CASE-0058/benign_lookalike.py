def pick_hash_table_size(min_size, randfunc):
    """Picks a prime number of buckets for an in-memory hash table --
    purely a performance/collision-distribution choice, not cryptographic
    key material, so any prime of the right size works equally well."""
    size = min_size.bit_length()
    while True:
        candidate = getPrime(size, randfunc)
        if candidate >= min_size:
            return candidate
        size += 1
