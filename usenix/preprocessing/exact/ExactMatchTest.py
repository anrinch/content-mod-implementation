import random
import time
import constants
from ExactMatchClient import ExactMatchClient
from ExactMatchServer import ExactMatchServer
from pympler import asizeof
import math
import sys
import pandas as pd
import csv 




def main(argv):

    if len(argv) > 1:
        num_inputs = int(argv[0])
        bf_fpr = float(argv[1])
        input_file = argv[2]
        if(constants.TEST_MATCH): 
            test_file = input_file
        else:
            test_file = argv[3]
        if(constants.LOG_RESULTS): log_file = argv[4]

    perf = {}
    perf['DB Size'] = num_inputs
#    if(num_inputs < math.pow(2,20)): 
    partition_size = math.ceil(math.pow(2,6))
 #   else:
  #      partition_size = math.ceil(math.pow(2,10))
    if(constants.CONSOLE_OUTPUT):
        print("Starting test for", num_inputs, "random inputs")
        print("Partition size:", partition_size)
        print("Per partition Bloom filter FPR:", bf_fpr)

    client = ExactMatchClient(num_inputs)
    server = ExactMatchServer(num_inputs, partition_size, bf_fpr, input_file)


    ### Auditor blinds the blocklist elements
    start_time = time.time()    
    blinded_elements = server.blind()
    end_time = time.time()
    if(constants.CONSOLE_OUTPUT): print("Auditor: blinding time:", (end_time - start_time), "s")
    perf['Auditor preprocess time'] = (end_time - start_time)

    ### Client computes the PRF with the key
    start_time = time.time()    
    oprf_evaluations = client.response(blinded_elements)
    end_time = time.time()
    if(constants.CONSOLE_OUTPUT): print("Client: evaluation time:", (end_time - start_time), "s")
    perf['Client preprocess time'] = (end_time - start_time)


    ### Server deblinds and initializes the Bloom filters
    start_time = time.time()    
    return_values, total_storage, bf_dict, elmt_to_bf_dict = server.deblind(oprf_evaluations)
    end_time = time.time()
    if(constants.CONSOLE_OUTPUT): print("Server: deblinding and BF creation time:", (end_time - start_time), "s")
    perf['Server preprocess time'] = (end_time - start_time)
    
    ### Query the bloom filters
    if(constants.TEST_QUERY):
        inputs = []
        num_test_queries = 100
        file_inputs = []
        try:
            with open(test_file, "r") as file:
                file_inputs = file.read().splitlines()
        except FileNotFoundError:
                print("File not found.")
        for i in range(num_test_queries): 
            inputs.append(file_inputs[random.randint(0, num_inputs-1)])


    start_time = time.time()
    query_prf_vals, query_bf_dict = client.query(inputs, return_values, bf_dict, elmt_to_bf_dict)
    end_time = time.time()
    time_per_query = (end_time - start_time)/num_test_queries
    if(constants.CONSOLE_OUTPUT): print("Client: Query time:", time_per_query, "seconds")
    perf['Client query time'] = time_per_query

    start_time = time.time()
    max_false_pos, total_false_pos = server.query(query_prf_vals, query_bf_dict)
    end_time = time.time()
    time_per_query = (end_time - start_time)/num_test_queries
    if(constants.CONSOLE_OUTPUT): print("Server: Query time:", time_per_query, "seconds")
    perf['Server query time'] = time_per_query
    perf['Max false positives'] = max_false_pos
    perf['Total false positives'] = total_false_pos
    perf['Server storage cost'] = total_storage
    perf['Comm'] = ((asizeof.asizeof(query_prf_vals)) + asizeof.asizeof(query_bf_dict))/(num_test_queries*1000)

    try:
        with open(log_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, perf.keys())
            
            # If the file is empty, write the header
            if csvfile.tell() == 0:
                writer.writeheader()
            
            writer.writerow(perf)

    except Exception as e:
        print(f"An error occurred: {e}")



if __name__=="__main__":
    main(sys.argv[1:])