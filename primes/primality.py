import random
import secrets

from modular import operations
from . import FOUND_PRIMES

def fermat_pseudoprime(candidate_prime):
    """Uses Fermat's theorem to test compositeness.

    It returns 'True' if the number is a pseudoprime.

    It runs in O(B^3), the same as modular exponentiation.
    It errors on Carmichael numbers and other pseudoprimes,
    but the error rate decreases to 0 as we go to infinity.

    Based on the implementation from CLSR pg. 967.
    """
    return False if operations.modular_exp(2, candidate_prime - 1, candidate_prime) != 1 \
                 else True


def clsr_miller_rabin(candidate_prime, iterations=32):
    """Uses the Miller-Rabin randomized primality test to
    test compositeness.

    Returns 'True' if the number is probably a prime.
    
    It runs in O(sB) arithmetic-operations and O(sB^3) bit-arithmetic,
    where s represents the number of iterations.

    The error rate no longer depends on the candidate_prime,
    and the error rate is 2^(-s) for incorrectly
    testing compositeness (i.e. returns 'True' for a composite).

    Based on the implementation from CLSR pg. 969 and 970.
    """
    def witness(a, candidate_prime):
        """Returns True when a witness is found."""
        if not candidate_prime & 1:  # avoids hanging on evens
            if candidate_prime == 2:
                return False
            return True

        # first, construct t and u such thmilat
        # candidate_prime - 1 = 2^t * u
        # where u must be odd
        t = 1
        u = (candidate_prime - 1) // (1 << t)
        while candidate_prime - 1 != (1 << t) * u or not u & 1:
            t += 1
            u = (candidate_prime - 1) // (1 << t)
        
        x = [0] * (t+1)
        x[0] = operations.modular_exp(a, u, candidate_prime)
        for i in range(1, t + 1):
            x[i] = operations.modular_exp(x[i-1], 2, candidate_prime)
            if x[i] == 1 and x[i-1] != 1 and x[i-1] != candidate_prime - 1:
                return True

        if x[t] != 1:
            return True
        return False

    for _ in range(iterations):
        a = random.randint(1, candidate_prime - 1)
        if witness(a, candidate_prime):
            return False
    return True


def nist_miller_rabin(candidate_prime, iterations=38):
    """Uses the Miller-Rabin compositeness test on a candidate prime.

    Returns True if the number is probably prime.

    Uses the NIST implementation from
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    on pg. 71 to 72 in Appendix C.3.1
    """
    # special case
    if candidate_prime == 2:
        return True
    elif not candidate_prime & 1:
        return False

    # let a be the largest such integer that divides
    # the candidate - 1
    # i.e. 2^(a) * s = candidate - 1
    a, s = 0, candidate_prime - 1
    while not s & 1:
        a += 1
        s = s >> 1  # s = (candidate - 1)/2^a

    for _ in range(iterations):
        b = random.randint(2, candidate_prime - 2)

        z = operations.modular_exp(b, s, candidate_prime)
        if z == 1 or z == candidate_prime - 1:
            continue
        
        for __ in range(1, a):
            z = operations.modular_exp(z, 2, candidate_prime)

            if z == 1:
                return False  # it's not prime
            elif z == candidate_prime - 1:
                break  # leave this inner loop and continue the outer loop

        if z != candidate_prime - 1:
            return False

    return True


def trial_division(candidate_prime, B=None):
    """Checks if a number is divisible by some multiple of primes
    until some value B.
    
    Returns True if it's divisible, and False if it isn't.
    """
    return any(candidate_prime % prime == 0 for prime in FOUND_PRIMES[:B])