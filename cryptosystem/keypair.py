from collections import namedtuple
import random

from primes import generator
from primes import primality
from modular import operations

"""Inspiration for the keypair class structure is from
http://code.activestate.com/recipes/578838-rsa-a-simple-and-easy-to-read-implementation/
"""

class PrivateKey(namedtuple('PrivateKey', 'exponent modulus')):
    """Represents a PrivateKey with an exponent and modulus.
    
    Has some wrapper functions for encryption, decryption, and signing.
    """

    def sign(self, message):
        return encrypt(self, message)

    def decrypt(self, ciphertext):
        return decrypt(self, ciphertext)


class PublicKey(namedtuple('PublicKey', 'exponent modulus')):
    """Represents a Publickey with an exponent and modulus.

    Has some wrapper functions for encryption, decryption, and signing.
    """
    def verify(self, message):
        return decrypt(self, message)

    def encrypt(self, plaintext):
        return encrypt(self, plaintext)


def encrypt(key, plaintext):
    """Takes an ASCII plaintext and encrypts it.
    
    plaintext ^ key exponent mod modulus
    """
    plaintext = int.from_bytes(bytes(plaintext, 'ascii'), byteorder='little')
    return operations.wiki_modular_exp(plaintext, key.exponent, key.modulus)


def decrypt(key, ciphertext):
    """Takes an encrypted ciphertext and decrypts it.
    
    ciphertext ^ key exponent mod modulus
    """
    plaintext = operations.wiki_modular_exp(ciphertext, key.exponent, key.modulus) 
    plaintext = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='little')
    return plaintext.decode('ascii')


def clsr_make_keypair(p, q):
    """Creates a keypair using any two given
    primes.

    Returns two dictionaries, a public and
    private key, with exponent and modulus
    fields.

    According to the CLSR description on
    pg. 962.
    """
    if p == q:
        return None, None

    if primality.trial_division(p) or not primality.nist_miller_rabin(p):
        return None, None
    
    if primality.trial_division(q) or not primality.nist_miller_rabin(q):
        return None, None

    n = p*q
    euler_totient = (p-1)*(q-1) 
    
    invalid_e = True
    while invalid_e:  # coprime to totient and odd
        e = random.randint(2, euler_totient - 2) | 1  
        invalid_e = not operations.gcd(e, euler_totient) == 1

    # private exponent
    d = operations.modular_multiplicative_inverse(e, euler_totient)

    pub = PublicKey(exponent=e, modulus=n)
    priv = PrivateKey(exponent=d, modulus=n)

    return pub, priv


def clsr_manual_keypair(p, q, e, d):
    """Fully manually specified version of the CLSR
    description of the RSA cryptosystem.

    Returns None, None if an invalidity was detected.
    """    
    if p == q:
        return None, None

    n = p*q
    euler_totient = (p-1)*(q-1)

    # not odd and not coprime with totient
    if not e & 1 or operations.gcd(e, euler_totient) != 1:
        return None, None

    # not inverse
    if d*e % euler_totient != 1:
        return None, None

    pub = PublicKey(exponent=e, modulus=n)
    priv = PrivateKey(exponent=d, modulus=n)

    return pub, priv


def make_nist_keypair(nlen=2048, e=65537):
    """Makes a keypair using NIST's recommendations.
    
    Implemented according to the specifications at
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    Appendix B.3.1, pg. 50 to pg. 53
    """

    invalid_d = True
    while invalid_d:
        success, primes = generator.nist_probable_primes(nlen, e)
        if not success:
            return {'modulus': 0, 'product': 0}, {'modulus': 0, 'product': 0}
        p, q = primes

        product = p * q
        carmichael_totient = operations.lcm(p - 1, q - 1)

        d = operations.modular_multiplicative_inverse(e, carmichael_totient)

        if d:
            invalid_d = d <= (1 << nlen//2) or d >= carmichael_totient or \
                        ((e % carmichael_totient) * (d % carmichael_totient)) % carmichael_totient != 1

    pub = PublicKey(exponent=e, modulus=product)
    priv = PrivateKey(exponent=d, modulus=product)

    return pub, priv
