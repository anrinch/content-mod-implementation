import random
import constants
import Utils
from oblivious import ristretto
from oblivious.ristretto import point, scalar,python
from rbloom import Bloom
import math


class ExactMatchServer:

    def __init__(self, list_size, num_items_per_partition, bf_fpr, input_file):
       self.blinding_factor = scalar.random()
       self.list_size = list_size 
       self.input_values = []
       self.num_items_per_partition = num_items_per_partition
       self.fpr = bf_fpr
       self.bloom_filters = {}
       self.bf_key = Utils.get_rand_bytes(16)

       try:
            with open(input_file, "r") as file:
                self.input_values = file.read().splitlines()
       except FileNotFoundError:
            print("File not found.")
      
        
    def blind(self):
       blinded_inputs = []
       for input in self.input_values:
          blinded_inputs.append(self.blinding_factor * point.hash(input.encode()))
       return blinded_inputs
    
    def deblind(self, oprf_responses):
        return_values = []
        elmt_to_bf_dict = {}
        num_partitions = math.ceil(len(oprf_responses)/self.num_items_per_partition)
        blocklist_partition = {}
        i = 0
        total_storage = 0
  
        ### Initialize the bloom filters 
        for k in range(num_partitions):
            self.bloom_filters[k] = Bloom(2*self.num_items_per_partition, self.fpr, Utils.bf_hash_func)
        
        ### Add elements and PRF evaluations to BF
        for i in range(len(self.input_values)):  
            oprf_response = scalar.__invert__(self.blinding_factor) * oprf_responses[i]
            dh_oprf_val = Utils.get_hash_digest(self.input_values[i].encode() + oprf_response.to_bytes())
            _dh_oprf_val = [x for x in dh_oprf_val]
            bucket_num = _dh_oprf_val[0] % num_partitions
            self.bloom_filters[bucket_num].add(Utils.get_hash_digest(self.input_values[i].encode()))
            self.bloom_filters[bucket_num].add(dh_oprf_val)
            return_values.append(dh_oprf_val)
            elmt_to_bf_dict[dh_oprf_val] = bucket_num


        ### Bloom filter encryption and stats 
        bf_dict = {}
        for k in range(num_partitions):
            bf_dict[k] = {}
            total_storage = total_storage + self.bloom_filters[k].size_in_bits / 8 + 8
            bf = self.bloom_filters[k].save_bytes()
            nonce, ciphertext, tag = Utils.encrypt_aes_eax(bf, self.bf_key)
            bf_dict[k]['nonce'] = nonce
            bf_dict[k]['tag'] = tag
            bf_dict[k]['ciphertext'] = ciphertext
           
            if(constants.VERBOSE): print(num_partitions, "Bloom filters created with total storage: ", (total_storage)/math.pow(2,20), "MB and FPR:", self.fpr * num_partitions)

        return return_values, (total_storage)/math.pow(2,20), bf_dict, elmt_to_bf_dict

    
    def query(self,query_list, query_bf_dict):
        num_matches = 0
        max_false_pos = 0
        total_false_pos = 0
        elements_in_match_bloom_filter = []
        
        for val in query_list:
            detected = 0
            false_pos = 0
            
            try:
                decrypted_data = Utils.decrypt_aes_eax(query_bf_dict[val]['nonce'], query_bf_dict[val]['ciphertext'], query_bf_dict[val]['tag'], self.bf_key)
            #    #print(f"Decrypted data: {decrypted_data.decode()}")
            except ValueError as e:
                print(f"Decryption failed: {e}")
          
            test_bf = Bloom.load_bytes(decrypted_data, Utils.bf_hash_func)

            if (test_bf.__contains__(val)):
                if(constants.VERBOSE): print("match found in Bloom filter")
                for input_element in self.input_values:
                    if test_bf.__contains__(input_element):
                        elements_in_match_bloom_filter.append(input_element)
                num_matches += 1
                
                ### This is where the content verification token will be verified with the elemnts in elements_in_match_bloom_filter

        if(constants.TEST_MATCH == True): 
            if(num_matches != len(query_list)):
                print("ERROR in matching", num_matches, len(query_list))

        return max_false_pos, total_false_pos


