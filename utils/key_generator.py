"""
This contains functions for creating cryptographic keys.

It UNSAFE to use this in production.
Do not use it anywhere except the HY458 Assignments.

Implemented by Nikolaos Boumakis, csdp1358
"""

import random
from math import gcd

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from gmpy2 import next_prime


def fermat_vulnerable() -> RSAPublicKey:
    """Creates a RSA public key that is vulnerable to Fermat's factorization algorithm"""
    e = 0x10001

    p = int(next_prime(random.randint(2**511, 2**512-1)))
    q = int(next_prime(p))

    for _ in range(random.randint(30, 50)):
        q = int(next_prime(q))

    assert all((gcd(e, (q-1)*(p-1)),
                (abs(p-q) < pow(p*q, 1/4)))), \
        "There was a problem during key creation. This is not your fault, try running again"

    return RSAPublicNumbers(e, p*q).public_key()


def create_pem_files(private_path: str, public_path: str):
    ''' Creates a key pair and saves them to disk '''
    with open(private_path, 'wb') as priv_f, open(public_path, 'wb') as pub_f:
        priv_key = generate_private_key(0x10001, 2048)

        priv_f.write(priv_key.
                     private_bytes(
                         serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()
                     ))
        pub_f.write(priv_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
