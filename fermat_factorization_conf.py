from utils.key_generator import fermat_vulnerable
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

#https://stackoverflow.com/questions/20464561/fermat-factorisation-with-python
def fermat(n, verbose=True):            
    a = isqrt(n) # int(ceil(n**0.5))
    b2 = a*a - n
    b = isqrt(n) # int(b2**0.5)
    count = 0
    while b*b != b2:
        if verbose:
            print('Trying: a=%s b2=%s b=%s' % (a, b2, b))
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2) # int(b2**0.5)
        count += 1
    p=a+b
    q=a-b
    assert n == p * q
    print('a=',a)
    print('b=',b)
    print('p=',p)
    print('q=',q)
    print('pq=',p*q)
    return p, q

def recover_key(public_key):
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n

    p, q = fermat(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=pow(d, 1, p - 1),
        dmq1=pow(d, 1, q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=public_key.public_numbers()
    )

    # Step 5: Create a private key
    private_key = private_numbers.private_key(default_backend())

    # Step 6: Return the private key
    return private_key

def main():
    parser = argparse.ArgumentParser(description='Digital Signature')
    parser.add_argument('-m', '--message', help='Message file', required=True)
    parser.add_argument('-prv', '--private', help='Signature file', required=True)
    args = parser.parse_args()
    
    message = bytes.fromhex(args.message)

    #create a vulnerable key and recover the private key
    vulnerable_key = fermat_vulnerable()
    private_key = recover_key(vulnerable_key)

    #encrypt with public key
    ciphertext = vulnerable_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    #Decrypt the ciphertext using the recovered private key
    decrypted_message = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    print(f"Decrypted Message (Hex): {decrypted_message.hex()}")

    #Save the private key
    with open(args.private, "wb") as private_key_file:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_bytes)

    
    return

if __name__ == "__main__":
    main()