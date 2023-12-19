import argparse
from cryptography.hazmat.primitives import serialization
from utils.converter import bytes_to_int, int_to_bytes
from cryptography.hazmat.primitives import hashes

def calculate_signature(message, private_key):
    #calculate hash of message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash=digest.finalize()

    #convert hash to int
    inthash=bytes_to_int(hash)

    #encrypt hash 
    private_numbers=private_key.private_numbers()
    encrypted=pow(inthash, private_numbers.d, private_numbers.public_numbers.n)

    #convert encrypted hash to bytes
    signature=int_to_bytes(encrypted)
    
    return signature

def verify_signature(message, signature, public_key):
    #calculate hash of message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash=digest.finalize()

    #convert signature to int
    signatureint=bytes_to_int(signature)

    #decrypt signature
    public_numbers=public_key.public_numbers()
    decrypted=pow(signatureint, public_numbers.e, public_numbers.n)

    #convert decrypted hash to bytes
    decrypted=int_to_bytes(decrypted)

    if hash == decrypted:
        return True
    else:
        return False
    
def test_signature(message, private_key):
    signature = calculate_signature(message, private_key)

    # Verify with the original message
    if verify_signature(message, signature, private_key.public_key()):
        print("Signature verified with the original message.")
    else:
        print("Signature verification failed with the original message.")

    # Change a single byte in the message
    modified_message = message[:len(message) // 2] + b"\x00" + message[len(message) // 2 + 1:]
    if verify_signature(modified_message, signature, private_key.public_key()):
        print("Signature verified with a modified message.")
    else:
        print("Signature verification failed with a modified message.")
    
def main():
    parser = argparse.ArgumentParser(description='Digital Signature')
    parser.add_argument('-m', '--message', help='Message file', required=True)
    parser.add_argument('-prv', '--private', help='Signature file', required=True)
    args = parser.parse_args()
    
    message = bytes.fromhex(args.message)
    private_path = args.private

    with open(private_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    
    test_signature(message, private_key)
    return

if __name__ == "__main__":
    main()