import random
import time
import constants
import Utils
from oblivious import ristretto
from hashlib import sha256
from oblivious.ristretto import point, scalar,python
from rbloom import Bloom



class ExactMatchClient:


    def __init__(self, set_size):
        self.set_size = set_size
        self.private_key = scalar.random()


    def response(self,blinded_inputs):
        return_values = []
        for input in blinded_inputs:
            return_values.append(self.private_key * input)
        return return_values
    
    def query(self, inputs, return_values, bf_dict, elmt_to_bf_dict):
        num_partitions = len(bf_dict)
        query_list = []
        query_bf_dict = {}
        for input in inputs:
            val = Utils.get_hash_digest(input.encode() + (self.private_key * point.hash(input.encode())).to_bytes())
            query_list.append(val)
            _bucket_num = [x for x in val]
            bucket_num = _bucket_num[0] % num_partitions
            query_bf_dict[val] = {}
            query_bf_dict[val]['bkt_num'] = bucket_num
            query_bf_dict[val]['nonce'] = bf_dict[bucket_num]['nonce']
            query_bf_dict[val]['tag'] = bf_dict[bucket_num]['tag']
            query_bf_dict[val]['ciphertext'] = bf_dict[bucket_num]['ciphertext']
            if(constants.DEBUG==True and constants.TEST_MATCH==True): 
                assert val in return_values
                assert elmt_to_bf_dict[val] == bucket_num
        return query_list, query_bf_dict



