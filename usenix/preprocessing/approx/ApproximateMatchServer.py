
import time 
from CuckooHash import HashTab
from lightphe import LightPHE
import Utils
import constants
import random
import decimal
import pickle
import math
from Crypto.Protocol.SecretSharing import Shamir
import json

class ApproximateMatchServer:

    def __init__(self, params, keyFile, decryptFile, auxFile, inFile, CHTFile, projFile, INIT_KEY, INIT_CHT):
        self.blocklist_size = params['num_inputs']
        self.num_proj = params['num_projections']
        self.vec_len = params['vec_len']
        self.ss_threshold = params['ss_threshold']
        self.random_generators = {}
        self.random_generators_inv = {}
        self.projection_fns = []
        self.chunks_per_vec = int(self.vec_len/constants.DECRYPT_TABLE_SIZE)

      
        
        
        if(INIT_KEY):
       
            ### create keys
            self.phe = LightPHE(algorithm_name="ElGamal")
            self.phe.export_keys(keyFile,False)
            self.group_mod = self.phe.cs.keys['public_key']['p']

            ### Select a random generator       
            self.random_generator = (random.randint(2, int(decimal.Decimal(self.phe.cs.keys['public_key']['p']).sqrt())))
            self.random_generator_inv = pow(self.random_generator,-1, self.phe.cs.keys['public_key']['p'])
            aux_dict = {
            "generator" : self.random_generator,
            "generator_inverse" : self.random_generator_inv,
            }
            with open(auxFile, "w+") as file:
                json.dump(aux_dict, file)

            ### create decryption table 
            start_time = time.time()
            self.decryption_table = {}
            for i in range(int(math.pow(2,constants.DECRYPT_TABLE_SIZE))):
                message = Utils.conv_bin_to_int(bin(i))
                self.decryption_table[str(pow(self.random_generator, message, self.group_mod))] = bin(i)[2:].zfill(constants.DECRYPT_TABLE_SIZE)
            
            with open(decryptFile, "w+") as file:
                json.dump(self.decryption_table, file)
            end_time = time.time()
            if(constants.CONSOLE_OUTPUT): print("Server: decryption table time:", end_time - start_time, "sec")

        else:
            self.phe = LightPHE(algorithm_name="ElGamal", key_file=keyFile)
            self.group_mod = self.phe.cs.keys['public_key']['p']

            with open(auxFile, "r") as file:
            # read generators
                aux_dict = json.load(file)
            self.random_generator = aux_dict["generator"]
            self.random_generator_inv = aux_dict["generator_inverse"]
            with open(decryptFile, "r") as file:
                self.decryption_table = json.load(file)
       
        if(INIT_CHT):

            ### sample projections 
            for i in range(self.num_proj):
                self.projection_fns.append(Utils.get_random_vector(self.vec_len))
            with open(projFile, "wb") as file:
                pickle.dump( self.projection_fns, file)

            ### create blocklist 
            Utils.write_random_vectors_to_file(inFile, self.blocklist_size , self.vec_len)

            ### create CHT file 
            start_time = time.time()
            self.create_cuckoo_table(inFile, CHTFile)
            end_time = time.time()
            if(constants.CONSOLE_OUTPUT): print("Server: CHT time:", end_time - start_time, "sec")


        else:
            with open(projFile, "rb") as file:
                self.projection_fns = pickle.load(file)


    def get_public_key(self):
        return self.phe.cs.keys
   
    def get_proj_funcs(self):
        return self.projection_fns

    def get_generator(self):
        return self.random_generator

    def encrypt_vec(self, input):
        
        ciphertext = []
        for i in range(self.chunks_per_vec):
            _message = Utils.get_bin_substr(input, i*constants.DECRYPT_TABLE_SIZE, (i+1)*constants.DECRYPT_TABLE_SIZE) 
            message = Utils.conv_bin_to_int(_message)   
            plaintext = pow(self.random_generator, message, self.group_mod)
            ciphertext.append(self.phe.encrypt(plaintext))

        return ciphertext

    def encrypt_scalar(self, input):
        
        plaintext = pow(self.random_generator, input, self.group_mod)
        return self.phe.encrypt(plaintext)

    def decrypt_vec(self,ciphertext):
        plaintext = ''
        for i in range(self.chunks_per_vec):
            decrypted_val = self.phe.decrypt(ciphertext[i])
            if(constants.DEBUG): assert str(decrypted_val) in self.decryption_table
            plaintext = plaintext + str(self.decryption_table[str(decrypted_val)])
            
        return plaintext


    def create_cuckoo_table(self, in_file, cht_file):

       
        try:
            with open(in_file, "r") as file:
                inputs = file.read().splitlines()
        except FileNotFoundError:
            print("File not found.")

        CHT = HashTab(100)

        start_time = time.time()
        idx = 0
        inserted = 0
        for input in inputs:
            projections = Utils.compute_projections(input, self.projection_fns)
            for proj in projections:
                CHT_val = {}
                CHT_val['proj_ciphertext'] = self.encrypt_vec(proj)
                CHT_val['bkt_ciphertext'] = self.phe.encrypt(0)
                if CHT.insert(Utils.hash_func(proj), CHT_val):
                    inserted += 1
                    ret = CHT.find(Utils.hash_func(proj))
                    if(constants.DEBUG): assert str(self.phe.decrypt(ret['proj_ciphertext'][0])) in self.decryption_table
            idx += 1
        

        with open(cht_file, "wb") as file:
            pickle.dump(CHT, file)

        return CHT
    
    def query(self, ciphertexts,dhf, bkt_ciphetexts, key, ids):
      
        secret_shares = []

        for i in range(len(ciphertexts)):
            plaintext = Utils.conv_bin_to_bytes(self.decrypt_vec(ciphertexts
            [i]))
            ### DHF column key = plaintext[0:16]
            ### DHF column = try to decrypt with DHF key
            ### DHF matrix.append(DHF column)
            share = plaintext[16:32]
            secret_shares.append((ids[i],share))
            Utils.simulate_DHF(len(self.projection_fns), self.ss_threshold)

        ### DHF detect with DHF matrix 

        combined_key = Shamir.combine(secret_shares)
        assert key == combined_key
            