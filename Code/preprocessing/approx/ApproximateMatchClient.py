
from CuckooHash import HashTab
from lightphe import LightPHE
import Utils
import constants
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from binascii import hexlify

class ApproximateMatchClient:

    def __init__(self, params, key_file, proj_fns, pub_key, random_generator):

        self.vec_len = params['vec_len']
        self.num_projections = params['num_projections']
        self.ss_threshold = params['ss_threshold']
        self.projection_fns = proj_fns
        self.phe = LightPHE(algorithm_name="ElGamal", keys=pub_key)
        self.pub_key = pub_key
        self.random_generator = random_generator
        self.chunks_per_vec = int(self.vec_len/constants.DECRYPT_TABLE_SIZE)
        self.random_generator_inv = pow(self.random_generator,-1, self.pub_key['public_key']['p'])
        self.group_mod = self.phe.cs.keys['public_key']['p']
    

    def homomorphic_substract_vec(self, input1, input2):
        
        in_ciphertext = []
        ret_ciphertext = []
        for i in range(self.chunks_per_vec):
            _message = Utils.get_bin_substr(input1, i*constants.DECRYPT_TABLE_SIZE, (i+1)*constants.DECRYPT_TABLE_SIZE) 
            message = Utils.conv_bin_to_int(_message)   
            plaintext = pow(self.random_generator, message, self.group_mod)
            plaintext = pow(plaintext, -1, self.group_mod)
            ret_ciphertext.append(self.phe.encrypt(plaintext) * input2[i])

        return ret_ciphertext



    def homomorphic_add_vec(self, input1, input2):
        
        in_ciphertext = []
        ret_ciphertext = []
        for i in range(self.chunks_per_vec):
            _message = Utils.get_bin_substr(input1, i*constants.
            DECRYPT_TABLE_SIZE, (i+1)*constants.DECRYPT_TABLE_SIZE) 
            message = Utils.conv_bin_to_int(_message)   
            plaintext = pow(self.random_generator, message, self.group_mod)
            ret_ciphertext.append(self.phe.encrypt(plaintext) * input2[i])

        return ret_ciphertext

    def homomorphic_mul_vec(self, input1, input2):
        
        ret_ciphertext = []
        for i in range(self.chunks_per_vec):
            ret_ciphertext.append(input[i] * input2[i])

        return ret_ciphertext

    
    def query(self, CHT, input):
        key = get_random_bytes(16)
        ret_proj_ciphertexts = []
        ret_bkt_ciphertext = []
        secret_share = Shamir.split(self.ss_threshold, len(self.projection_fns), key)
        secret_shares = []
        ### we need the dhf vectors here
        dhf_vec = []
        for i in range(len(self.projection_fns)):
            dhf_vec.append(get_random_bytes(16))
        dhf_vec_encrypted = []  
        
        ids = []
        for idx, share in secret_share:

            dhf_coeff_key = get_random_bytes(16)
            
            ### encrypt the DHF
            for i in range(len(dhf_vec)):
                nonce, ciphertext, tag = Utils.encrypt_aes_eax(get_random_bytes(16), dhf_coeff_key)    
                pad = str(Utils.conv_bytes_to_binary_string(ciphertext))
                dhf_vec_encrypted.append(Utils.xor_binary_strings(pad, Utils.conv_bytes_to_binary_string(dhf_vec[i])))                 

            share = str(Utils.conv_bytes_to_binary_string(dhf_coeff_key)) + str(Utils.conv_bytes_to_binary_string(share)) 
            secret_shares.append(share)
            ids.append(idx)
        
        projections = Utils.compute_projections(input, self.projection_fns)
        i = 0
        for proj in projections:
            query_ret = CHT.find(Utils.hash_func(proj))
            if query_ret != None:
                subtracted_proj_ciphertext =  self.homomorphic_substract_vec(proj, query_ret['proj_ciphertext'])
                ret_proj_ciphertexts.append(self.homomorphic_add_vec(secret_shares[i], subtracted_proj_ciphertext))
                subtracted_cipher = subtracted_proj_ciphertext[0]
                for ct in subtracted_proj_ciphertext:
                    subtracted_cipher = subtracted_cipher * ct
                ret_bkt_ciphertext.append(subtracted_cipher * query_ret['bkt_ciphertext'])
            else:
                return None, None, None, None, None
            i += 1
            
        return ret_proj_ciphertexts, dhf_vec_encrypted, ret_bkt_ciphertext, key, ids
  