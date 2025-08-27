### ORGANIZATION

Both the approximate and exact versions are built by the same make file in this directory.
When the build is complete, the shell scripts in the scripts/ directory can be used to run
the executables and record results.

### Requirements

* download and install Cryptopp v8.9 library on your system (https://github.com/weidai11/cryptopp)
  * Everything else can be built on your system
  * Build may take a long time during the first attempt

### Building the code 
Create a build directory form this directory level.
This /build directory will generate executables called in the /scripts folder.
**Disclaimer: Building the code for the first time may take a while**

```
  $ mkdir build
  $ cd build
  $ cmake ..
  $ make
```

### Running the code

*There should now be two executables that can be called by themselves from shell script in the scripts/ folder:
```
  $ exactmatchtests.sh
```

The results are saved in the server.log folder

The shell will output the server side text in a file named server.log
the time it took will be recorded in the server log


### Running as separate executables

The executables can also be called without the scripts in the /scripts folder.
```
  $ ./networked-aud2048 -b <path/to/file/containing/hashes>
```

GRPC was used to implement communication between a client and server in the
exact matching code.

When running in server mode, you will see a message saying:
  server running @ \<IPv4ADDR:PORT\>

**Only when the server has printed this message is it ready to receive messages from a client.**

./grpc-test help:
```
  $ ./grpc-test -h 
  -h [ --help ]                      produce help message
  -b [ --blocklist ] arg             Blocklist file with pHashes
  -c [ --config ] arg (=config.json) JSON config file to read from
  -a [ --addr ] arg                  \<IPv4 server address\>:\<port\>
  -r [ --role ] arg                  1 for server, 0 for client
  -e [ --einput ] arg                input embedding for the client to send to
                                     the server
  -p [ --pinput ] arg                plaintext value for the client
```

The embedding input is the hash of a string. 
Ensure the that it is a hash string of an appropriate size. By default we use a hash that is 256 bits long:

to run the program as a client you, pass the following inputs:
```
      $ grpc-test -r 0 -a <address:port> \ 
      $ -e <hexstr> \
      $ -p <plaintext> \
      $ -c <path/to/config.json> \
```

to run the program as a server, pass the following inputs:
```
      $ grpc-test -r 1 -a <address:port> \ 
      $ -b <path/to/blocklist> \
      $ -c <path/to/config.json> \
```

It is not recommended to run these executables by themselves. For convenience, exactmatchtests.sh
is provided.

### Running the approximate PSI
All executables are built by the same CMake for the exact matching.
The approximate PSI may take a long time to compute. It will log the output in a .results file.

To call the executable in the build directory, got to the /scripts directory and call
```
$ ./serverfullpsibenchmark.sh
```
To get the maximum possible run time for the approximate version of the protocol, call 
```
$ ./serverfullpsinomatchbenchmark.sh
```

To get the full client run time for the approximate version of the protocol, call
```
$ ./clientfullpsibenchmark.sh
```


