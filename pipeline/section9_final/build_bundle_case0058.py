"""
Section 9 ground-truth test bundle: CASE-0058
(Legrandin/pycrypto, CVE-2012-2417, CWE-310 cryptographic weakness in
ElGamal key generation).

Core vulnerable mechanism: `generate()` picks the modulus `p` as ANY
random prime, and the generator `g` as an arbitrary prime smaller than
`p` -- neither is verified to have the algebraic properties ElGamal
actually needs. `p` should be a SAFE PRIME (`p = 2q+1` with `q` also
prime) so the multiplicative group has a large prime-order subgroup, and
`g` must be checked to avoid small-order elements and known attacks
(Bleichenbacher's forgery attack for `g` with `g^2 = 1`, and generators
whose value or inverse divides `p-1`). Without these checks, a
maliciously-crafted or unlucky key can make forged ElGamal signatures
computable. The fix builds `p` as `2q+1` with both checked prime, and
rejects any candidate `g` that fails the known-attack checks.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0058"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    obj.p=bignum(getPrime(bits, randfunc))
    # Generate random number g
    if progress_func:
        progress_func('g\\n')
    size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
    if size<1:
        size=bits-1
    while (1):
        obj.g=bignum(getPrime(size, randfunc))
        if obj.g < obj.p:
            break
        size=(size+1) % bits
        if size==0:
            size=4'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename generate -> create_keypair, obj -> key. Same exact non-safe-prime
# p and unchecked generator g.
renamed_source = original.replace(
    "def generate(bits, randfunc, progress_func=None):",
    "def create_keypair(bits, randfunc, progress_func=None):",
)
renamed_source = renamed_source.replace("obj=ElGamalobj()", "key=ElGamalobj()")
renamed_source = renamed_source.replace(VULNERABLE_BLOCK, '''    key.p=bignum(getPrime(bits, randfunc))
    # Generate random number g
    if progress_func:
        progress_func('g\\n')
    size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
    if size<1:
        size=bits-1
    while (1):
        key.g=bignum(getPrime(size, randfunc))
        if key.g < key.p:
            break
        size=(size+1) % bits
        if size==0:
            size=4''')
# Remaining obj.-> key. occurrences in the rest of the (still-vulnerable)
# function body -- x/y generation is unrelated to this specific fix but
# needs the same rename applied consistently so the function still parses.
renamed_source = renamed_source.replace("obj.x", "key.x").replace("obj.y", "key.y").replace("return obj", "return key")
assert "def create_keypair(bits, randfunc, progress_func=None):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact non-safe-prime p and unchecked generator g, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    prime_candidate = getPrime(bits, randfunc)
    obj.p = bignum(prime_candidate)
    # Generate random number g
    if progress_func:
        progress_func('g\\n')
    size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
    if size<1:
        size=bits-1
    g_found = False
    while not g_found:
        obj.g=bignum(getPrime(size, randfunc))
        g_found = obj.g < obj.p
        if not g_found:
            size=(size+1) % bits
            if size==0:
                size=4''',
)
assert structural_source != original
assert "prime_candidate = getPrime(bits, randfunc)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (a safe prime p=2q+1, and a generator g
# checked against known attacks) but a materially different code shape:
# extracts the safety checks into a standalone is_safe_generator() helper
# function called from the main loop, instead of the real patch's single
# inline while-loop with a `safe` flag threaded through several
# conditions -- genuinely implements the same safe-prime + attack-
# resistant-generator algorithm, different structure.
SAFE_SOURCE = '''def is_safe_generator(g, p, q):
    if pow(g, 2, p) == 1:
        return False
    if pow(g, q, p) == 1:
        return False
    if divmod(p - 1, g)[1] == 0:
        return False
    ginv = number.inverse(g, p)
    if divmod(p - 1, ginv)[1] == 0:
        return False
    return True


def generate(bits, randfunc, progress_func=None):
    obj = ElGamalobj()
    if progress_func:
        progress_func('p\\n')
    while True:
        q = bignum(getPrime(bits - 1, randfunc))
        obj.p = 2 * q + 1
        if number.isPrime(obj.p, randfunc=randfunc):
            break

    if progress_func:
        progress_func('g\\n')
    while True:
        candidate_g = number.getRandomRange(3, obj.p, randfunc)
        if is_safe_generator(candidate_g, obj.p, q):
            obj.g = candidate_g
            break

    if progress_func:
        progress_func('x\\n')
    obj.x = number.getRandomRange(2, obj.p - 1, randfunc)
    if progress_func:
        progress_func('y\\n')
    obj.y = pow(obj.g, obj.x, obj.p)
    return obj
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "is_safe_generator" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a loop calling getPrime() repeatedly to find a
# prime satisfying a size constraint) but this sibling picks a prime
# ONLY to use as a hash-table bucket count for a non-cryptographic
# in-memory cache -- any prime works equally well for that purpose, so
# skipping the safe-prime/generator-security checks here has no security
# consequence at all, unlike generate()'s cryptographic key material.
BENIGN_SOURCE = '''def pick_hash_table_size(min_size, randfunc):
    """Picks a prime number of buckets for an in-memory hash table --
    purely a performance/collision-distribution choice, not cryptographic
    key material, so any prime of the right size works equally well."""
    size = min_size.bit_length()
    while True:
        candidate = getPrime(size, randfunc)
        if candidate >= min_size:
            return candidate
        size += 1
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "ElGamalobj" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0058.")
