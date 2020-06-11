#!/bin/bash

cd ../build


function idempotent(){
    rm -rf *
    make clean
    cmake ../ \
      -DBUILD_BPF=ON \
      -DBUILD_WARNINGS_AS_ERRORS="OFF" \
      -DCMAKE_BUILD_TYPE="Release" \
      -DCMAKE_INSTALL_PREFIX="/usr" \
      -DFALCO_ETC_DIR="/etc/falco" \
      -DUSE_BUNDLED_DEPS=OFF
}

#idempotent

make all -j32

echo ""
echo ""
echo $?
echo ""
echo ""

# Install module
sudo rmmod falco
sudo insmod driver/falco.ko

# Install falco
sudo cp userspace/falco/falco /usr/bin/falco
