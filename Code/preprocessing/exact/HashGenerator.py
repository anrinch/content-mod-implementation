'''
2This is a utility script
'''
import hashlib
import random
import string
import sys

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

def generate_sha256_hashes(count, string_length=16):
    hashes = []
    for _ in range(count):
        rand_str = generate_random_string(string_length)
        hash_hex = hashlib.sha256(rand_str.encode('utf-8')).hexdigest()
        hashes.append(hash_hex)
    return hashes

def save_hashes_to_file(hashes, filename="hashes.txt"):
    with open(filename, "w") as f:
        for hash_hex in hashes:
            f.write(hash_hex + "\n")


def main(argv):


    how_many = int(argv[0])
    hashes = generate_sha256_hashes(how_many)
    save_hashes_to_file(hashes)
    


if __name__ == "__main__":
    
    main(sys.argv[1:])
    


