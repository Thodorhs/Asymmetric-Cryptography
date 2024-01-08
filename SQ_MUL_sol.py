from utils.power_analysis import VictimComputer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import random
from enum import Enum

class States(Enum):
    IDLE = 1
    SQ = 2
    MUL = 3
    PAUSE = 4

def square_multiply_power_trace(power_trace: list[float]):
    #take out starting idle time
    start=0
    for power in power_trace:
        if power < 1:
            start=start+1
        else:
            break
    power_trace = power_trace[start:]
    
    private_exponent = 0
    bit_count = 2043
    op_count = 0
    state = States.SQ

    for power in power_trace:
        if state == States.IDLE:
            if power < 1:
                op_count += 1
            elif power >= 1:
                state = States.SQ
                op_count = 1

        elif state == States.SQ:
            if power >= 1:
                op_count += 1
            else:
                op_count = 1
                state = States.PAUSE

        elif state == States.PAUSE:
            if power >= 1:
                op_count = 1
                state = States.MUL
                private_exponent |= (1 << bit_count)
            elif power < 1 and op_count > 5:
                bit_count = bit_count - 1
                op_count += 1
                state = States.IDLE
            else:
                op_count += 1
                
        elif state == States.MUL:
            if power >= 1:
                op_count += 1
            elif power < 1:
                state = States.IDLE
                op_count = 1

    private_exponent |= (1 << 2044) #add last MS bit = 1
    return private_exponent
    
def recover_private_key(d: int, public_key: rsa.RSAPublicKey) -> rsa.RSAPrivateKey:

    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    p, q = rsa.rsa_recover_prime_factors(n, e, d)
    iqmp = pow(q, -1, p)  # Modular multiplicative inverse of q modulo p

    # Create the private key
    private_key = rsa.RSAPrivateKey(
        p=p,
        q=q,
        private_exponent=d,
        public_exponent=e,
        n=n,
        dmp1=(d % (p - 1)),
        dmq1=(d % (q - 1)),
        iqmp=iqmp,
        backend=default_backend()
    )

    return private_key

def main():
    victim = VictimComputer()
    pub = victim.get_public_key()

    with open('1000.txt', 'r', encoding='utf-8') as file:
        wordlist = file.read().splitlines()
    # Generate a random message by selecting random words from the wordlist
    random_message = ' '.join(random.choice(wordlist) for _ in range(random.randint(5, 10)))
    random_message = random_message.encode('utf-8')
    print("Random Message:", random_message)
    print("Encrypting message with public key...")
    ciphertext = pub.encrypt(random_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Observing power trace...")
    power_trace = victim.decrypt(ciphertext)
    print("Recovering private exponent from power trace...")
    private_exponent = square_multiply_power_trace(power_trace)
    print("Private Exponent:", bin(private_exponent)[2:])
    print("Recovering private key from private exponent and public key...")
    private_key = recover_private_key(private_exponent, pub)
    print("Decrypting ciphertext with private key...")
    plaintext = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Recovered Message:", plaintext)

if __name__=="__main__":
    main()