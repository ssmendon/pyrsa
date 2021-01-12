def modular_exp(base, exponent, modulus):
    """This quickly performs modular exponentiation.

    It runs in O(B^3) and is implemented according to
    CLSR pg. 957.
    """
    c, d, exp_length = 0, 1, exponent.bit_length() - 1
    for i in range(exp_length, -1, -1):
        c = c << 1  # c = 2c
        d = (d * d) % modulus
        if exponent & (1 << i):  # ith bit of b is 1
            c += 1
            d = (d*base) % modulus
    return d


def wiki_modular_exp(base, exponent, modulus):
    """Quickly performs modular exponentiation.

    It uses the implementation on
    https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
    """
    if modulus == 1:
        return 0

    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:  # even
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus

    return result


def recur_gcd(a, b):
    """Recursively computes the GCD with Euclid's algorithm.

    It makes O(lg b) recursive calls, does O(B) arithmetic
    operations, and O(B^2) bit operations.

    Uses the CLSR algorithm implemented on
    pg. 935.
    """
    if not b:
        return a
    return recur_gcd(b, a % b)


def gcd(a, b):
    """Computes the GCD with Euclid's algorithm.

    Uses the iterative version from
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Implementations
    """
    while b:
        b, a = a % b, b
    return a


def recur_extended_euclid(a, b):
    """Returns the GCD, and the two Bezout
    coefficients. 

    It has O(lg b) recursive calls, and the number of bit
    operations is the same as Euclid, O(B^2).

    Uses the CLSR implementation on
    pg. 938.
    """
    if not b:
        return a, 1, 0
    d_prime, x_prime, y_prime = recur_extended_euclid(b, a % b)
    return d_prime, y_prime, x_prime - a//b * y_prime
    

def modular_linear_equation_solver(a, b, n):
    """When b = 1, it finds the modular multiplicative
    inverses of a mod n.

    It returns whether there are any solutions,
    then a list of solutions.

    It performs O(lg n) arithmetic operations.

    Uses the CLSR implementation on
    pg. 949.
    """
    d, x_prime, _ = recur_extended_euclid(a, n)
    if not b % d:
        x = x_prime*(b//d) % n
        return True, [(x + i*(n//d)) % n for i in range(d)]
    return False, []


def modular_multiplicative_inverse(a, n):
    """Gets the modular multiplicative inverse
    of a mod n, if it exists.

    Returns None if it does not exist.

    Uses the implementation on
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
    """
    t, newt = 0, 1
    r, newr = n, a

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    
    if r > 1:
        return None  # not invertible

    if t < 0:
        t += n

    return t


def lcm(a, b):
    """Returns the LCM.

    Uses the implementation on
    https://en.wikipedia.org/wiki/Least_common_multiple#Using_the_greatest_common_divisor
    """
    return a//gcd(a, b) * b