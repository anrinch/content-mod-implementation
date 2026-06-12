from hashlib import sha256
from pickle import dumps
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def get_hash_digest(input):
    return sha256(dumps(input)).digest()


def get_rand_bytes(size):
    return get_random_bytes(size)

def bf_hash_func(obj):
    h = get_hash_digest(obj)
    return int.from_bytes(h[:16], "big", signed=True)

def encrypt_aes_eax(plaintext, key):
   
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def decrypt_aes_eax(nonce, ciphertext, tag, key):
   
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
