#!/bin/sh
#apt-get install libjson-c-dev
git clone https://github.com/Cisco-Talos/clamav-devel
cd clamav-devel
./configure --enable-static --with-libjson
DEB_BUILD_HARDENING=1 make
hardening-check clamscan/.libs/clamscan

