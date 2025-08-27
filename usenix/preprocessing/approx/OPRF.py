
import random
import time
from oblivious import ristretto
from oblivious.ristretto import point, scalar,python
from rbloom import Bloom
import math
import sys
import pandas as pd
import csv 

DEBUG = 0
LOG_RESULTS = True
CONSOLE_OUTPUT = False
TEST_RAND = False
TEST_QUERY = True




class OPRFReceiver:

    
    def __init__(self):
        self.blinding_factor = scalar.random()

    def blind(self, inputs):
        blinded_inputs = []
      
        for input in inputs:
            blinded_inputs.append(self._blind(point.hash(input.encode())))
        return blinded_inputs

    def _blind(self, input):
        return self.blinding_factor * input

    def deblind(self, oprf_responses):
        return_values = []
        for i in range(oprf_responses):
            return_values.append(scalar.__invert__(self.blinding_factor) * oprf_responses[i])
        return return_values

class OPRFSender:

    def __init__(self):
        self.private_key = scalar.random()


    def response(self,blinded_inputs):
        return_values = []
        for input in blinded_inputs:
            return_values.append(self.private_key * input)
        return return_values
    
    def _response(self, inputs):
        return_values = []
        for input in inputs:
            return_values.append(self.private_key * point.hash(input.encode()))
        return return_values
    