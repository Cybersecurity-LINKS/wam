# RISC-V architecture

## Requirements

For cross compiling the project a `riscv-gnu-toolchain` is needed. 
This project has been tested with Linux buildroot 5.7.0-dirty on a riscv64 architecture using QEMU. To set up the test environment, you can follow the Keystone documentation located at this link: https://docs.keystone-enclave.org/en/latest/Getting-Started/Running-Keystone-with-QEMU.html

## Build
Run the command `./fast-setup.sh --riscv` to patch the `iota.c` submodule with the required changes. The script will also build the project automatically, using the proper CMake options.
The library and an usage example can be found in the `build` folder. 

## Execution guidelines for Keystone

Before testing the executable example with Keystone and QEMU, copy it into the `overlay` folder and rebuild the QEMU image.

For instance:
```bash
cp ./build/ExampleWAM <keystone build folder>/overlay/root
cd  <keystone build folder>
make image
```

Ensure that the _ca-certificates_ package is enabled by setting `BR2_PACKAGE_CA_CERTIFICATES=y` in the _buildroot_ configuration file (`keystone/conf/qemu_riscv64_virt_defconfig`), as the application requires a TLS connection with the IOTA node.

Before executing `./ExampleWAM`, set the correct time on the Linux buildroot system with `date -s "2023-02-02"` to ensure a successful TLS handshake with the IOTA node.
