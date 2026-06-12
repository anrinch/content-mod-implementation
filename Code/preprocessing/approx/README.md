### Requirements 
Install the NTL as a shared object library
* The NTL requires GMP, make sure that it is also installed
* NTL must be installed as a shared object, otherwise pybind11 will not work
* This can be done by calling ./configure SHARED=on before compilation
* Since we are building a custom module, make a python virtual environment
* pybind11 (use a virtual python environment if possible)

Install the following python modules

1. LightPHE (https://github.com/serengil/LightPHE) for the homomorphic encryption 
2. pycryptodome (https://www.pycryptodome.org) for secret sharing and encryption 
3. json, pickle, random, hashlib



### Building the module

Compile the C library with python bindings
the bindings allow the DHF to be called as a module

make a build dir
* call cmake path/to/project
* call make

### Install the custom python module
* cp build/dhf.cpython-310-x86_64-linux-gnu.so into approx/ e.g:
```
cp build/<dhf>.so ..

```
* call pip install .



### Testing the code
The code can be tested using run_all_experiments.sh
```` 
./run_all_experiments <number of runs>
````



The size of the database and the number of projections can be set in "run_all_experiments ". Note that for large database, the set up time is significant due to the encryption and creation of the cuckoo hash table. 
