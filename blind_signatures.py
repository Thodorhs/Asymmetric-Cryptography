from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from utils.converter import bytes_to_int, int_to_bytes
import random

def modInverse(A, M): 
    for X in range(1, M): 
        if (((A % M) * (X % M)) % M == 1): 
            return X 
    return -1

class signer:
    
    def __init__(self) -> None:
        self._private_key = generate_private_key(0x10001, 2048)
    
    def get_public_key(self) -> RSAPublicKey:
        return self._private_key.public_key()
    
    def sign(self, blinded_message: int):
        private_numbers=self._private_key.private_numbers()
        signature=pow(blinded_message, private_numbers.d, private_numbers.public_numbers.n)
        return signature

class user:

    def __init__(self, _signer: signer) -> None:
        self.signer = _signer

    def get_signed_message(self):
        message = b"Hello, world!" 
        
        digest = hashes.Hash(hashes.SHA256()) #a
        digest.update(message) #a
        hash=digest.finalize() #a

        m=bytes_to_int(hash) #b

        r = random.randint(1, self.signer.get_public_key().public_numbers().n - 1) #c

        blinded_message = pow(r, self.signer.get_public_key().public_numbers().e, self.signer.get_public_key().public_numbers().n) * (m % self.signer.get_public_key().public_numbers().n) #d
        
        blinded_signature = self.signer.sign(blinded_message) #e
        
        r_inv = pow(r, -1, self.signer.get_public_key().public_numbers().n) #f

        unblinded_signature = (blinded_signature * r_inv) % self.signer.get_public_key().public_numbers().n #f

        unblinded_signature_bytes = int_to_bytes(unblinded_signature) #g

        return unblinded_signature_bytes, message

class verifier:
    
    def __init__(self, _signer: signer) -> None:
        self.signer = _signer
    
    def verify(self, message: bytes, signature: bytes):

        digest = hashes.Hash(hashes.SHA256()) #a
        digest.update(message) #a
        hash=digest.finalize() #a

        s=bytes_to_int(signature) #b
        
        m=pow(s, self.signer.get_public_key().public_numbers().e, self.signer.get_public_key().public_numbers().n) #c

        m_bytes = int_to_bytes(m) #d

        return hash == m_bytes #e

def main():
    Signer = signer() #a
    User = user(Signer) #b
    Verifier = verifier(Signer) #b

    signature, message = User.get_signed_message() #c

    if Verifier.verify(message, signature): #d (a) message and signature as returned in step c
        print("Signature verified with the original message.")
    else:
        print("Signature verification failed with the original message.")

    if Verifier.verify(b"\x00" + message[1:], signature): #d (b) a damaged message and the signature as returned in step c
        print("Signature verified with a damaged message.")
    else:
        print("Signature verification failed with a damaged message.")
    
    if Verifier.verify(message, b"\x00" + signature[1:]): #d (c) message returned in step c. and a damaged signature
        print("Signature verified with a damaged signature.")
    else:
        print("Signature verification failed with a damaged signature.")

    if Verifier.verify(b"\x00" + message[1:], b"\x00" + signature[1:]): #d (d) a damaged message and a damaged signature
        print("Signature verified with a damaged message and a damaged signature.")
    else:
        print("Signature verification failed with a damaged message and a damaged signature.")

    return

if __name__ == "__main__":
    main()
