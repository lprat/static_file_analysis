#!/bin/sh
#apt-get install libjson-c-dev
git clone https://github.com/vrtadmin/clamav-devel
cd clamav-devel
./configure --enable-static --with-libjson
make

