"""
RSA cryptosystem in Python with decryption using the Chinese Remainder Theorem.
Author: Vadym Tunik.
"""
from sympy import randprime


def generate_keys(bits: int=512):
    """
    The key generation algorithm creates public and private keys.

    Args:
        bits: desired binary length of the secret modules.
    Return:
        (e, n), (d, p, q): public key, private key.
    """
    p = randprime(2**(bits-1), 2**bits)
    q = randprime(2**(bits-1), 2**bits)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # common choice for e
    d = pow(e, -1, phi)

    return (e, n), (d, p, q)


def encrypt(message: int, public_key) -> int:
    """ 
    The encryption algorithm for a message using a public key.

    Args:
        message: plaintext message.
        public_key: (e, n) public key pair.
    Return:
        c: ciphertext.
    """
    e, n = public_key
    ciphertext = pow(message, e, n)
    return ciphertext


def decrypt(ciphertext: int, private_key) -> int:
    """ 
    The decryption algorithm for a message using a private key.

    Args:
        ciphertext: ciphertext.
        private_key: (e, n) public key pair.
    Return:
        message: original message.
    """
    d, p, q = private_key
    n = p * q 

    d_p = d % (p-1)
    d_q = d % (q-1)

    m1 = pow(ciphertext, d_p, p)
    m2 = pow(ciphertext, d_q, q)

    q_inv = pow(q, -1, p)
    h = (q_inv * (m1 - m2)) % p
    message = m2 + h * q % n
    return message


def encoder(message: str) -> int:
    """
    The function encodes a text string into a large integer using base-256 encoding.
    """
    return sum(ord(char) << (8 * i) for i, char in enumerate(message))


def decoder(number: int) -> str:
    """
    The function decodes a large integer into a text string using base-256 encoding.
    """
    message = ""
    while number:
        message += chr(number & 0xff)
        number >>= 8
    return message


def test():
    public_key, private_key = generate_keys(512)
    message = "Glory to Ukraine!"
    print(f"{message=}")
    plaintext = encoder(message)
    print(f"{plaintext=}")
    ciphertext = encrypt(message=plaintext, public_key=public_key)
    print(f"{ciphertext=}")
    decrypted_message = decrypt(ciphertext=ciphertext, private_key=private_key)
    print(f"{decrypted_message=}")
    decoded_message = decoder(decrypted_message)
    print(f"{decoded_message=}")


if __name__ == "__main__":
    test()