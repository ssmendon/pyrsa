#!/usr/bin/env python3
"""
An academic implementation of RSA for ASU's
CSE 450 - Design and Analysis of Algorithms course.

2019 (c) Sohum Mendon
Do not redistribute without permission from the author.
"""

import sys
import os

import argparse
import importlib
import pickle

from cryptosystem import keypair
from primes import generator

KEY_NAME = 'rsa_key'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generates a public-private keypair and provides rudimentary encryption'
                    ' operations.'                               
    )

    group = parser.add_mutually_exclusive_group()

    # generate prime of the given length
    group.add_argument('--prime', '-p', metavar='BIT LENGTH', type=int)

    # generate keypair and store in local directory
    group.add_argument('--create', '-c', metavar='MODULUS LENGTH', type=int, choices=[2048, 3072])

    # encrypt message with saved keypair
    group.add_argument('--encrypt', '-e', metavar='MESSAGE', type=str)

    # decrypt with saved keypair
    group.add_argument('--decrypt', '-d', metavar='MESSAGE', type=int)

    # sign with saved keypair
    group.add_argument('--sign', '-s', metavar='MESSAGE', type=str)

    # verify with saved keypair
    group.add_argument('--verify', '-v', metavar='MESSAGE', type=int)

    # examine saved public key
    group.add_argument('--examine', '-x', action='store_true')

    # create manual keypair
    manual_command = group.add_argument_group('manual', 'Manually creates an RSA key when supplied with at least two primes.'
                             ' Optionally, a public exponent and private exponent may be provided (in that order).'
                             ' No guarantees if the values are not correct.')

    manual_command.add_argument('--manual', '-m', help='p, q, e, d', nargs='*')

    args = parser.parse_args()

    # --prime
    if args.prime:
        if args.prime < 100:
            print(f'Size of prime must be > 100 bits (given {args.prime}).', file=sys.stderr)
            sys.exit(-1)
        else:
            print(generator.applied_random_search(args.prime))
            sys.exit(0)

    # --create
    if args.create:
        pub, priv = keypair.make_nist_keypair(args.create)

        # write to file
        with open(f'{KEY_NAME}.pub', 'wb') as f:
            pickle.dump(pub, f)

        with open(f'{KEY_NAME}.priv', 'wb') as f:
            pickle.dump(priv, f)

        print(f'Wrote keys to files {KEY_NAME}.pub and {KEY_NAME}.priv in local directory.')
        sys.exit(0)

    # --examine
    if args.examine:
        # load pub key
        with open(f'{KEY_NAME}.pub', 'rb') as f:
            pub = pickle.load(f)

        # load priv key
        with open(f'{KEY_NAME}.priv', 'rb') as f:
            priv = pickle.load(f)

        print(f'Modulus: {pub.modulus}')
        print(f'Private exponent: {priv.exponent}')
        print(f'Public exponent: {pub.exponent}')

        sys.exit()


    # --encrypt or --verify
    if args.encrypt or args.verify:
        # load the public key
        with open(f'{KEY_NAME}.pub', 'rb') as f:
            pub = pickle.load(f)

        if args.encrypt:
            # ensure that message bit size is < modulus size
            if (len(args.encrypt) << 3) > pub.modulus.bit_length():
                print(f'Size of message ({len(args.encrypt) << 3}) must be smaller than'
                       f' size of key modulus ({pub.modulus.bit_length()}).', file=sys.stderr)
                sys.exit(-1)
            # message is of appropriate size
            print('Ciphertext:')
            print(pub.encrypt(args.encrypt))
        elif args.verify:
            print('Plaintext:')
            print(pub.verify(args.verify))

        sys.exit(0)

    # --decrypt or --sign
    if args.decrypt or args.sign:
        # load the private key
        with open(f'{KEY_NAME}.priv', 'rb') as f:
            priv = pickle.load(f)

        if args.decrypt:
            print('Plaintext:')
            print(priv.decrypt(args.decrypt))
        else:
            if (len(args.sign) << 3) > priv.modulus.bit_length():
                print(f'Size of message ({len(args.sign) << 3}) must be smaller than'
                      f' size of key modulus ({priv.modulus.bit_length()}).', file=sys.stderr)
                sys.exit(-1)
            # message is of appropriate size
            print('Ciphertext:')
            print(priv.sign(args.sign))

        sys.exit(0)

    # manual creation
    if args.manual:
        if len(args.manual) < 2:
            print('Must provide at least two primes for manual mode.', file=sys.stderr)
            sys.exit(-1)
        elif len(args.manual) < 4 and len(args.manual) != 2:
            print('Must provide both exponents for manual mode.', file=sys.stderr)
            sys.exit(-1)

        
        p, q = int(args.manual[0]), int(args.manual[1])
        if len(args.manual) == 2:

            # use the two primes
            pub, priv = keypair.clsr_make_keypair(p, q)

            if not pub or not priv:
                print('WARNING: Failed to generate the keys.', file=sys.stderr)
                print('Make sure the input is valid.', file=sys.stderr)
                sys.exit(-1)

            with open(f'{KEY_NAME}.pub', 'wb') as f:
                pickle.dump(pub, f)

            with open(f'{KEY_NAME}.priv', 'wb') as f:
                pickle.dump(priv, f)

            print(f'Wrote keys to files {KEY_NAME}.pub and {KEY_NAME}.priv in local directory.')
            sys.exit(0)
        # fully manual
        else:
            e, d = int(args.manual[2]), int(args.manual[3])

            pub, priv = keypair.clsr_manual_keypair(p, q, e, d)
            if not pub or not priv:
                print('WARNING: Failed to generate the keys.', file=sys.stderr)
                print('Make sure the input is valid.', file=sys.stderr)
                sys.exit(-1)

            with open(f'{KEY_NAME}.pub', 'wb') as f:
                pickle.dump(pub, f)

            with open(f'{KEY_NAME}.priv', 'wb') as f:
                pickle.dump(priv, f)

            sys.exit(0)

    # user didn't enter a command
    # print help
    parser.parse_args(['--h'])