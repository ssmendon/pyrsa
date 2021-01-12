import secrets

import itertools

import math
from decimal import Decimal

from . import primality
from modular import operations


def applied_random_search(plen=1024, iterations=32):
    """Uses a random search algorithm to pick a prime
    of length nlen. Iterations is a security parameter for a
    Miller-Rabin test.

    It uses the implementation provided at
    http://cacr.uwaterloo.ca/hac/about/chap4.pdf
    on pg. 146 with some modifications.
    """
    isPrime = False

    while not isPrime:
        candidate_prime = secrets.randbits(plen) | 1 | (1 << (plen - 1))  # not even & at least 1024

        # must be right size
        # and a prime
        isPrime = candidate_prime.bit_length() == plen and \
            (not primality.trial_division(candidate_prime)) and \
                primality.clsr_miller_rabin(candidate_prime, iterations)

    return candidate_prime


def nist_probable_primes(nlen=2048, pub_exp=65537):
    """Guided by the NIST's probable prime generation 
    algorithm to create a prime with a given length and given exponent.

    The length of the prime must be 2048 or 3072.
    The exponent must also be within a certain range of values
    for security and speed.

    It uses the implementation from
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    pg. 55, Appendix B.3.3
    """
    if nlen != 2048 and nlen != 3072:
        return False, (0, 0)
    else:
        iterations = 32 if nlen == 2048 else 27

    # exponent must be odd
    # e must be between 2^16 and 2^256 exclusive
    if not pub_exp & 1 or pub_exp <= (1 << 16) or pub_exp >= (1 << 256):
        return False, (0, 0)

    # gen p
    for i in itertools.count():
        candidateValid = False

        while not candidateValid:
            p = secrets.randbits((nlen >> 1)) | 1  # make sure it's odd

            # make sure it's exactly nlen/2 bits
            # and large (i.e. not exactly 2^(nlen/2))
            if nlen == 2048:
                candidateValid = p >= math.sqrt(2) * (1 << ((nlen >> 1) - 1))
            else: 
                candidateValid = p >= Decimal(math.sqrt(2)) * Decimal(1 << ((nlen >> 1) - 1))

        if operations.gcd(p-1, pub_exp) == 1:
            if not primality.trial_division(p) and \
                   primality.nist_miller_rabin(p, iterations):
                   break

        if i >= 5 * (nlen >> 1):  # if > 5*nlen/2 times
            return False, (0, 0)

    # gen q
    for i in itertools.count():
        candidateValid = False

        while not candidateValid:
            q = secrets.randbits((nlen >> 1)) | 1  # make sure it's odd

            # make sure it's close to p
            # p - q is within 2^(nlen/2 - 100)
            candidateValid = abs(p - q) >= (1 << ((nlen >> 1) - 100)) 
            if candidateValid and nlen == 2048:
                candidateValid = q >= math.sqrt(2) * (1 << ((nlen >> 1) - 1))
            elif candidateValid:
                candidateValid = q >= Decimal(math.sqrt(2)) * Decimal(1 << ((nlen >> 1) - 1))
            
        if operations.gcd(q-1, pub_exp) == 1:
            if not primality.trial_division(q) and \
                   primality.nist_miller_rabin(q, iterations):
                   return True, (p, q)

        if i >= 5 * (nlen >> 1):
            return False, (0, 0)
    