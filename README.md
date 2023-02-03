WAM - Wrapped Authenticated Messages
====================================

WAM is a library to interface with IOTA Tangle.
It can be used to write and read raw data from the _Chrysalis_ version of IOTA Tangle.

You can write data on the Tangle as zero-value transaction. However the data is public and can be read by anybody.
WAM protect the data with symmetric encryption and digital signature.
Moreover it enables to store data of arbitrary size by linking chunks of data across different indexes.


# Features
- Structured data: you pass the raw data as array. The data is automatically fragmented and each chunk is sent to the Tangle;

- Encryption: data is protected with a XSalsa20 encryption;

- Authentication: you can pass a custom key to create a digital signature (Ed25519) for your data.

# Target Architecture 
- x86_64
- riscv64 (look at the README.md in the riscv folder)

# Requirements
You need to install the dependencies for `iota.c`:

`sudo apt install build-essential libcurl4-openssl-dev pkg-config`

**(Optional)** Install `iota.c` library. Note that WAM works with Chrysalis version of `iota.c` library (currently, in branch `dev` on their repository).


# Build
- Clone this repository and its submodules (i.e., `iota.c`)
  ```bash
  git clone --recurse-submodules https://github.com/Cybersecurity-LINKS/WAM.git
  ```
- Build the library
  ```bash
  mkdir build && cd ./build
  cmake -DCMAKE_INSTALL_PREFIX=$PWD -DCryptoUse=libsodium ..
  make
  ```
This will automatically build both the dependencies and WAM itself as a static library.


# How-To
The header file that exposes WAM functions is WAM.h

- Import *that* header file in your project.
  ```
  #include "WAM.h"
  ```

- Use the functions exported there in your application
  ```C
  WAM_init_channel();
  WAM_read();
  WAM_write();
  set_channel_index_read();
  ```

- See `example.c` for an example on how to use the library.


# Limitations
Notice that this is a preliminary version of the protocol. There could be hidden bugs here and there. 


# Contributions
Feel free to open issues and make a pull-requests with your changes. 
Everybody who wants to contribute is more than welcome.
:)


# License
APACHE 2.0


# Authors
Alberto C. --> [@alby0x0c](https://github.com/alby0x0c)

Cybersecurity Research Group at [LINKS Foundation](https://linksfoundation.com/)


