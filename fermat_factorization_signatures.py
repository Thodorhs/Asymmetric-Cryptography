from utils.key_generator import fermat_vulnerable
import argparse
from fermat_factorization_conf import recover_key
from digital_signature import calculate_signature, verify_signature

def create_signature(message, public_key):
    #change the first byte to “G”
    modmessage = b'G' + message[1:]
    #recover the private key
    private_key = recover_key(public_key)
    #calculate the signature
    signature = calculate_signature(modmessage, private_key)
    #return the modified message and the signature
    return modmessage, signature

def main():
    parser = argparse.ArgumentParser(description='Digital Signature')
    parser.add_argument('-m', '--message', help='Message', required=True)
    args = parser.parse_args()
    
    message = bytes.fromhex(args.message)
    vulnerable_key = fermat_vulnerable()
    modmessage, signature = create_signature(message, vulnerable_key)
    
    if verify_signature(modmessage, signature, vulnerable_key):
        print("Signature verified with the modified message.")
    else:
        print("Signature verification failed with the modified message.")
        
    return

if __name__ == "__main__":
    main()