# CS_HE_benchmark

## OpenFHE and SEAL
Go to the openfhe_tests or seal_tests directory and run the following commands to build the executables:
```
mkdir build && cd build
```
```
CC=/usr/bin/clang-11 CXX=/usr/bin/clang++-11 cmake .. -G Ninja
```
```
ninja
```
## Lattigo

Installation instructions: https://go.dev/doc/install

```
tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
```

Edit PATH 

```
export PATH=$PATH:/usr/local/go/bin
```

```
# Running CKKS test bench
go run main_ckks.go
```
