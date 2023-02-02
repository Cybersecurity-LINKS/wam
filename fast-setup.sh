#!/bin/sh

set -e

echo "Starting..."
#echo "Cloning submodule iota.c"

#git submodule sync --recursive
#git submodule update --init --recursive
echo "Building project"


sudo rm -rf build
mkdir build && cd ./build #here we can pass an argument and if not set, use "build"

if [ "$1" = "--riscv" ]; then
    echo "Building for RISCV..."
    if ( $(command -v riscv64-unknown-linux-gnu-gcc > /dev/null) && $(command -v riscv64-unknown-elf-gcc > /dev/null) )
    then
        echo "RISCV tools are already installed"
        cp ./riscv/curl.cmake ./iota.c/cmake/
        cd iota.c
        git apply ../riscv/iota.c_riscv.patch
        # git apply -R iota.c_riscv.patch
        cd .. 
        SDK_FLAGS="-DRISCV=y"
    else
        echo "Error: Read the guide and install a RISCV toolchain!"
        exit 1
    fi
fi

cmake $SDK_FLAGS -DCMAKE_INSTALL_PREFIX=$PWD -DCryptoUse=libsodium ..
make


echo ""
echo "iota.c and WAM have been fully setup"
echo ""
echo " * Note: run the example in the build folder *"
echo ""