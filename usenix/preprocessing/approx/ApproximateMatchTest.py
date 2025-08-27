import Utils
import pickle
import time
import constants
import math
import random
import sys
import csv
from pympler import asizeof
from ApproximateMatchClient import ApproximateMatchClient
from ApproximateMatchServer import ApproximateMatchServer
TEST_DECRYPT_TABLE = 1
TEST_ENCRYT = 1

def main(argv):

    ### Temporary files 
    decryptFile = "temp/decryptFile.txt"
    inFile = "temp/inFile.txt"
    testFile = "temp/testFile.txt"
    keyFile = "temp/keyFile.txt"
    auxFile = "temp/auxFile.txt"
    CHTFile = "temp/CHTFile.txt"
    projFile = "temp/projFile.txt"
    params = {}

    ### Set parameters 
    if len(argv) > 1:
        params['num_inputs'] = int(argv[0])
        params['vec_len'] = int(argv[1])
        params['num_projections'] = int(argv[2])
        params['ss_threshold'] = int(argv[3])       
        if(constants.TEST_MATCH): 
            test_file = inFile
        else:
            test_file = testFile
        if(constants.LOG_RESULTS): log_file = argv[4]
        
         

    perf = {}
    perf['DB Size'] = params['num_inputs']
    partition_size = math.ceil(math.pow(2,8))
    if(constants.CONSOLE_OUTPUT):
        print("Starting test for", params['num_inputs'], "random inputs")
        print("Partition size:", partition_size)

    start_time = time.time()
    server = ApproximateMatchServer(params, keyFile, decryptFile, auxFile, inFile, CHTFile, projFile, True, True)
    end_time = time.time()
    server_setup_time = end_time - start_time
    perf['server setup time'] = server_setup_time

    client = ApproximateMatchClient(params, keyFile, server.get_proj_funcs(), server.get_public_key(), server.get_generator())



    ### Test Query 
    num_test_queries = 10
    file_inputs = []
    test_inputs = []
    try:
        with open(test_file, "r") as file:
            file_inputs = file.read().splitlines()
    except FileNotFoundError:
        print("File not found.")
    for i in range(num_test_queries):
        test_inputs.append(file_inputs[random.randint(0, params['num_inputs']-1)])



    with open(CHTFile, "rb") as file:
        CHT = pickle.load(file)

    start_time = time.time()
    for input in test_inputs:
        ret, dhf, bkt, key, ids = client.query(CHT,input)
        if ret == None:
            print("could not find entry")
        else:
            perf['Comm'] = ((asizeof.asizeof(ret)) + asizeof.asizeof(dhf) + asizeof.asizeof(bkt) + asizeof.asizeof(ids))/(num_test_queries*1000)
            server.query(ret, dhf, bkt, key, ids)
    end_time = time.time()
    time_per_query = (end_time - start_time)/len(test_inputs)
    if(constants.CONSOLE_OUTPUT): print("Client: Query time:", time_per_query, "sec")
    perf['query time'] = time_per_query



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
    