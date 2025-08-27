from hashlib import sha256
from pickle import dumps
import random
import math
import constants
import dhf
from Crypto.Cipher import AES

def hash_func(obj):
    h = sha256(dumps(obj)).hexdigest()
    return h

def hash_func_bytes(obj):
    h = sha256(dumps(obj)).digest()
    return h

def hash_func_int(obj):
    h = sha256(dumps(obj)).digest()
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


def get_bit(number, n):
    return (number >> n) & 1

def write_random_integers_to_file(filename, num_integers, min_val, max_val):

    with open(filename, 'w') as file:
        for i in range(num_integers):
            random_int = i #random.randint(min_val, max_val)
            file.write(str(random_int) + '\n')

def write_random_vectors_to_file(filename, num_vectors, vector_length):

    with open(filename, 'w+') as file:
        for i in range(num_vectors):
            input = hash_func(random.randint(0, int(math.pow(2,32))))
            str_input = bin(int(input, 16))[2:].zfill(vector_length)
            file.write(str_input + '\n')

def get_random_vector(vector_length):
    
    input = hash_func(random.randint(0, int(math.pow(2,32))))
    str_input = bin(int(input, 16))[2:].zfill(vector_length)

    return str_input

def xor_binary_strings(str1, str2):
    if len(str1) != len(str2):
        raise ValueError("Binary strings must be of equal length")

    result = ""
    for bit1, bit2 in zip(str1, str2):
        xor_result = str(int(bit1) ^ int(bit2))
        result += xor_result
    return result

def and_binary_strings(str1, str2):
    if len(str1) != len(str2):
        raise ValueError("Binary strings must be of equal length")

    result = ""
    for bit1, bit2 in zip(str1, str2):
        and_result = str(int(bit1) | int(bit2))
        result += and_result
    return result



def compute_projections(input, proj_fns):
    projections = []
    for proj in proj_fns:
        projections.append(str(and_binary_strings(input, proj)))
    return projections


def get_bin_substr(input, start_idx, end_idx):
    #print(input)
    return input[start_idx: end_idx]


### This function expects a binary string and outputs an object 
def conv_str_to_bin(input, vec_len):
    return bin(int(input))[2:].zfill(vec_len)



### This function expects a binary string as input and converts to int
def conv_bin_to_int(input):
    #print(input)
    return int(input, 2)

def conv_bytes_to_binary_string(bytes_data):
  
    return ''.join(bin(byte)[2:].zfill(8) for byte in bytes_data)

def conv_bin_to_bytes(input):
    integer_value = int(input,2)
    byte_length = (len(input) + 7) // 8

    # Convert integer to bytes, specifying big-endian byte order
    byte_string = integer_value.to_bytes(byte_length, byteorder='big')
    return byte_string

def conv_bytes_to_hex(bytes):
    return bytes.hex()

def conv_hex_to_bin(hex, length):
    return bin(int(hex, 16))[2:].zfill(length)

### Conversions data type between C++ NTL and python have been tricky, check the README.md 
### on how to install the dhf pybind11 with pip
### For now, it will generate a full matrix of (s+1 * s+t) and detect t vectors
### this is so that we can get an idea of the full run-time and call it from python
### TODO: fix bindings so that we can integrate the DHF with the full fuzzy protocol
def simulate_DHF(projections, threshold):
    return dhf.simDHF(projections, threshold)

