### Requirements

This the implementation of the preprocessing of a blocklist for exact matching of uploaded content. The python code requires the following modules 

- oblivious (https://pypi.org/project/oblivious/) for the oblivious PRF
- Bloom (https://github.com/KenanHanke/rbloom) for the Bloom filters 
- pycryptodome (https://www.pycryptodome.org) for the symmetric key cipher 
- rbloom
- pandas

### Testing
- "run_all_experiments.sh"

The "run_all_experiments.sh" is the top level script that tests the code with different sized blocklists. The blocklist size can be specified in the "test_array" variable. To run the script. You do not have to call run_experiments.sh directly

````
./run_all_script.sh <number of runs for each test>
````

### Results

The results of the experiment will be available in the file "experiments.log" after the experiments conclude. The code has been tested with Python version 3.11.1
