
from __future__ import annotations

from typing import Optional
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class Client:
    '''A class representing the client '''

    def __init__(self) -> None:
        self._channel: Optional[CommunicationChannel] = None
        self._public_key: Optional[RSAPublicKey] = None

    @property
    def channel(self):
        ''' Check if the communication channel has been set up, or complain '''
        if self._channel is None:
            raise BrokenPipeError("This client is not connected to a channel")

        return self._channel

    @property
    def public_key(self):
        ''' Check if the public key has been obtained, or complain '''
        if self._public_key is None:
            raise BrokenPipeError(
                "This client has not retrieved the server's public key")

        return self._public_key

    def channel_connect(self, channel: CommunicationChannel):
        ''' Connect to a communication channel '''
        self._channel = channel

    def get_server_key(self):
        ''' Obtain the server's public key throughthe communication channel '''
        self._public_key = self.channel.get_public_key()

    def send(self, message: bytes):
        ''' Send an encrypted message from the client to the server '''
        print(f"Sending {len(message)} bytes")

        ciphertext = self.public_key.encrypt(
            message,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        self.channel.transmit(ciphertext)


class Server:
    '''A class representing the server '''

    def __init__(self) -> None:
        self._private_key = generate_private_key(0x10001, 4096)

    def recv(self, message: bytes):
        ''' Receive some data from the channel.
            Call this from the communication channel to send data to the server '''
        plaintext = self._private_key.decrypt(
            message,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        print(f"Received {len(plaintext)} bytes")
        print("Received data (top secret):", plaintext)

    def get_public_key(self) -> RSAPublicKey:
        ''' Publish the public key of this server '''
        return self._private_key.public_key()


class CommunicationChannel:
    '''A class representing the communication channel where the MITM resides '''

    def __init__(self, server) -> None:
        self.server: Server = server

    def get_public_key(self) -> RSAPublicKey:
        '''
        WRITE YOUR CODE HERE!!

        Get the public key for the communication 
        from the server and pass it to the client.
        This is were the first part of the MITM
        attack will take place by substituting the
        original public key with one controlled by the attacker.
        '''
        mykey = generate_private_key(0x10001, 4096)
        self.mykey = mykey
        return mykey.public_key()
        pass

    def transmit(self, message: bytes):

        '''
        WRITE YOUR CODE HERE!!

        This function handles the transmission of data on the channel
        from the client to the server. Here, the attacker has the chance
        to recover the secret communication. Also, neither the client
        nor the server can realize what is happening.
        '''
        plaintext = self.mykey.decrypt(
            message,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        print("Attacker Decrypted data:", plaintext)
        #add some bytes to the message
        print("Adding bytes to the message")
        plaintext = plaintext + b' added bytes'
        #encrypt the message with the server's public key
        ciphertext = self.server.get_public_key().encrypt(
            plaintext,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        self.server.recv(ciphertext)
        pass


def main():
    server = Server()

    channel = CommunicationChannel(server)

    client = Client()
    client.channel_connect(channel)
    client.get_server_key()

    while (message := input("Message to be sent: ")):
        client.send(message.encode())


if __name__ == "__main__":
    main()
