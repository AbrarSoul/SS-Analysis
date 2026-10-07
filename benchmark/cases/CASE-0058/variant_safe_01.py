def is_safe_generator(g, p, q):
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
        progress_func('p\n')
    while True:
        q = bignum(getPrime(bits - 1, randfunc))
        obj.p = 2 * q + 1
        if number.isPrime(obj.p, randfunc=randfunc):
            break

    if progress_func:
        progress_func('g\n')
    while True:
        candidate_g = number.getRandomRange(3, obj.p, randfunc)
        if is_safe_generator(candidate_g, obj.p, q):
            obj.g = candidate_g
            break

    if progress_func:
        progress_func('x\n')
    obj.x = number.getRandomRange(2, obj.p - 1, randfunc)
    if progress_func:
        progress_func('y\n')
    obj.y = pow(obj.g, obj.x, obj.p)
    return obj
