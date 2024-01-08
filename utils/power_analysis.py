"""
This contains classes for simulating a computer running the decryption procsess.

It UNSAFE to use this in production.
Do not use it anywhere except the HY458 Assignments.

Implemented by Nikolaos Boumakis, csdp1358
"""

import random
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256


class VictimComputer():
    """ The computer that runs the decryption and whose power is being tracked """

    def __init__(self) -> None:
        self.__private_key = generate_private_key(0x10001, 2048)
        self.__public_key = self.__private_key.public_key()

    def _square_multiply_power_trace(self):
        power_trace = [random.uniform(2, 5)
                       for _ in range(random.randint(20, 30))]
        power_trace.extend([random.uniform(0, 1)
                           for _ in range(random.randint(1, 5))])
        power_trace.extend([random.uniform(2, 5)
                           for _ in range(random.randint(20, 30))])

        return power_trace

    def _square_power_trace(self):
        return [random.uniform(2, 5) for _ in range(random.randint(20, 30))]

    def get_public_key(self) -> RSAPublicKey:
        """ Simulate getting the public key from the computer """
        return self.__public_key

    def decrypt(self, ciphertext: bytes) -> list[float]:
        """ Simulate decrypting the ciphertext and tracking the power required """
        _ = self.__private_key.decrypt(
            ciphertext, OAEP(MGF1(SHA256()), SHA256(), None))

        d = self.__private_key.private_numbers().d
        power_trace: list[float] = [random.uniform(0, 1)
                                    for _ in range(random.randint(6, 20))]
        for bit in bin(d)[3:]:
            bit = int(bit)
            # The single bit power trace
            if bit:
                power_trace.extend(self._square_multiply_power_trace())
            else:
                power_trace.extend(self._square_power_trace())

            # The idle time between operations
            power_trace.extend([random.uniform(0, 1)
                                for _ in range(random.randint(10, 20))])

        return power_trace
