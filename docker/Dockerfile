#Docker Static File Analysis (SFA)
FROM debian:buster
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

RUN apt-get update && apt-get install --no-install-recommends -y libcurl4 libcurl4-gnutls-dev curl hexedit build-essential git python3-pip python-pip libjson-c-dev libxml2-dev libssl-dev libbz2-dev python-dev python-virtualenv xdot openssl vim zlib1g-dbg zlib1g zlib1g-dev cron devscripts libtesseract-dev tesseract-ocr-all procyon-decompiler python3-setuptools python-setuptools libboost-python-dev libboost-all-dev libxslt-dev libtool graphviz-dev automake libffi-dev graphviz libfuzzy-dev libjpeg-dev pkg-config autoconf python-setuptools clang python-backports.functools-lru-cache nano python-m2crypto python-lzma strace ltrace wget bsdmainutils unzip procps python3 python3-venv python3-dev build-essential libboost-dev libboost-system-dev libboost-python-dev mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract squashfs-tools sleuthkit lzop srecord sudo libpcap-dev check libpcre2-dev libncurses-dev libmilter-dev
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN apt-get install --no-install-recommends -y nodejs
RUN rm -rf /var/lib/apt/lists/*
RUN cd /opt/ && git clone https://github.com/lprat/static_file_analysis
RUN cd /opt/static_file_analysis && git clone https://github.com/Cisco-Talos/clamav clamav-devel
RUN pip3 install -U pytest
RUN cd /opt/ && wget https://github.com/Kitware/CMake/releases/download/v3.20.2/cmake-3.20.2.tar.gz && tar -zxf cmake-3.20.2.tar.gz && cd cmake-3.20.2 && ./bootstrap && make && sudo make install && cd  .. && rm -rf cmake-3.20.2*
RUN cd /opt/static_file_analysis/clamav-devel && mkdir build && cd build && CFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" CPPFLAGS="-Wdate-time -D_FORTIFY_SOURCE=2" CXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" FCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" FFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" GCJFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong" LDFLAGS="-Wl,-z,relro -Wl,-z,now" OBJCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" OBJCXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" cmake .. -D CMAKE_BUILD_TYPE="Release" -D ENABLE_STATIC_LIB=ON && CFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" CPPFLAGS="-Wdate-time -D_FORTIFY_SOURCE=2" CXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" FCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" FFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" GCJFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong" LDFLAGS="-Wl,-z,relro -Wl,-z,now" OBJCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" OBJCXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" cmake --build . --config Release && cp ./clamscan/clamscan /opt/static_file_analysis/clamav-devel/clamscan/clamscan
#cmake --build . --config Release --target install
#RUN cd /opt/static_file_analysis/clamav-devel && CC=gcc CXX=c++ CFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" CPPFLAGS="-Wdate-time -D_FORTIFY_SOURCE=2" CXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2" FCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" FFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -D_FORTIFY_SOURCE=2" GCJFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong" LDFLAGS="-Wl,-z,relro -Wl,-z,now" OBJCFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" OBJCXXFLAGS="-g -O2 -fdebug-prefix-map=/opt/static_file_analysis/clamav-devel=. -fstack-protector-strong -Wformat -Werror=format-security" ./configure --enable-static --with-libjson && make

#bug to install hashlib
#RUN rm -f /usr/lib/python2.7/lib-dynload/_hashlib.x86_64-linux-gnu.so

WORKDIR /opt/

#install pygrah & pyv8 for thug (compile with clang because gcc >6 make error segmentation fault
#RUN easy_install -U setuptools pygraphviz==1.3.1
ENV CXX clang++
RUN python /usr/lib/python2.7/dist-packages/easy_install.py -U setuptools==44.1.1 pygraphviz==1.3.1
#ref: https://github.com/ibmdb/node-ibm_db/issues/276
#RUN git clone https://github.com/buffer/pyv8.git
#COPY v8.patch /tmp
#RUN cd pyv8 && python setup.py build || cd build/v8_r19632/ && patch include/v8.h /tmp/v8.patch && cd ../.. && python setup.py build
#RUN cd pyv8 && python setup.py install && cd .. && rm -rf pyv8
#COPY libemu.conf /etc/ld.so.conf.d/libemu.conf
#RUN ldconfig
RUN cd /opt && git clone https://github.com/buffer/libemu.git && \
  cd libemu && \
  autoreconf -v -i && \
  ./configure && \
  make install && \
  cd .. && \
  rm -rf libemu
RUN ldconfig
#RUN cd /opt && git clone https://github.com/area1/stpyv8
RUN cd /opt && wget https://github.com/area1/stpyv8/archive/refs/tags/v8.9.255.20.tar.gz && tar -zxf v8.9.255.20.tar.gz
RUN cd /opt/stpyv8-8.9.255.20 && python setup.py v8
RUN cd /opt/stpyv8-8.9.255.20 && python3 setup.py stpyv8 && python3 setup.py install

#install hashlib pydot yara flask
#RUN pip install -U wheel && pip install setuptools --upgrade
#thug lastest use python 3.x
#RUN pip install -U pydot yara-python hashlib flask gunicorn soupsieve thug==0.10.6 virustotal-api
RUN cd /opt/static_file_analysis && pip3 install -r requirements.txt
#RUN cp -R /usr/local/lib/python2.7/dist-packages/etc/thug /etc/thug && mkdir /etc/thug/plugins/ && mkdir /etc/thug/hooks/

#install vmonkey
RUN pip3 install -U https://github.com/decalage2/ViperMonkey/archive/master.zip

#install cmulator
RUN mkdir -p /opt/Cmulator && wget https://github.com/Coldzer0/Cmulator/releases/download/v0.2.1/Cmulator_linux_x64.zip -O /opt/Cmulator/Cmulator_linux_x64.zip && cd /opt/Cmulator && unzip Cmulator_linux_x64.zip

#install zelos
RUN pip3 install zelos

#install scanr
RUN pip3 install capstone unicorn
RUN pip install capstone unicorn pypcap dpkt
RUN cd /opt && git clone https://github.com/1Project/Scanr

#install IDX
RUN cd /opt && git clone https://github.com/Rurik/Java_IDX_Parser

#install ghidra 
RUN cd /opt && wget https://ghidra-sre.org/ghidra_9.2.3_PUBLIC_20210325.zip -O ghidra.zip && unzip ghidra.zip && rm ghidra.zip
##PLUGINS
##FLIRT
RUN mkdir -p /opt/FLIRT && cd /opt/FLIRT && git clone https://github.com/push0ebp/sig-database && git clone https://github.com/cloudwindby/IDA-PRO-SIG && git clone https://github.com/Maktm/FLIRTDB

#install emulator js
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN curl -0 -L https://npmjs.org/install.sh | sh
RUN npm install box-js --global
RUN npm -g install js-beautify

#install foss - https://github.com/fireeye/flare-floss
RUN wget https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss -O /usr/local/bin/foss && chmod +x /usr/local/bin/foss

#install peepdf
RUN cd /opt && git clone https://github.com/jesparza/peepdf

#install binwalk
RUN cd /opt && git clone https://github.com/ReFirmLabs/binwalk && cd binwalk && python3 setup.py install

#install frida
RUN pip3 install -U frida-tools

#install apktool (https://github.com/iBotPeaches/Apktool) + (https://bitbucket.org/iBotPeaches/apktool/downloads/)
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.4.0.jar -O /usr/local/bin/apktool.jar && chmod +x /usr/local/bin/apktool*

#install mbox (https://github.com/tsgates/mbox)
RUN cd /opt && git clone https://github.com/tsgates/mbox && cd mbox/src && cp .configsbox.h configsbox.h && ./configure && make && make install

#install pyinstaller extractor https://sourceforge.net/projects/pyinstallerextractor/
RUN wget https://freefr.dl.sourceforge.net/project/pyinstallerextractor/dist/pyinstxtractor.py -O /usr/local/bin/pyinstxtractor.py && chmod +x /usr/local/bin/pyinstxtractor.py

#install unpy2exe - https://github.com/matiasb/unpy2exe & uncompyle6 https://github.com/rocky/python-uncompyle6
RUN pip install -U unpy2exe uncompyle6

#quarantine file extract
RUN wget http://hexacorn.com/d/DeXRAY.pl -O /usr/local/bin/DeXRAY.pl && chmod +x /usr/local/bin/DeXRAY.pl

#make auto signed cert
RUN cd /opt/static_file_analysis/api && openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365  -subj '/CN=localdomain/O=SFA/C=FR'

#make install wine & decompiler vb decompiler & decompiler delphi idr https://github.com/crypto2011/IDR/releases
RUN sed -i 's/ main/ main contrib/g' /etc/apt/sources.list 
RUN sed -i 's/ main contrib/ main contrib non-free/' /etc/apt/sources.list
RUN dpkg --add-architecture i386 && apt-get update && apt-get install --no-install-recommends -y wine wine32 winetricks unrar && wine wineboot --init
RUN apt-get install --no-install-recommends -y default-jre
RUN rm -rf /var/lib/apt/lists/*
RUN mkdir /opt/decompiler
COPY tools/vb_decompiler_lite.exe /opt/decompiler/
COPY tools/Exe2Aut.exe /opt/decompiler/
RUN wget https://github.com/crypto2011/IDR/releases/download/27_01_2019/Idr.exe -O /opt/decompiler/Idr.exe
##idr error message: cannot initialize diasm

#install ffdec - https://github.com/jindrapetrik/jpexs-decompiler/releases -- installed by apt
RUN wget https://github.com/jindrapetrik/jpexs-decompiler/releases/download/nightly1933/ffdec_14.4.0_nightly1933.deb -O /tmp/ffdec_14.4.0.deb && dpkg -i /tmp/ffdec_14.4.0.deb && rm /tmp/ffdec_14.4.0.deb

#add script to update git
ADD git_update.sh /opt/git_update.sh
RUN chmod 0755 /opt/git_update.sh
ADD remove_oldfile.sh /opt/remove_oldfile.sh
RUN chmod 0755 /opt/remove_oldfile.sh

# Add crontab file in the cron directory
ADD crontab_update /etc/cron.d/git-update-cron

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/git-update-cron

#add entrypoint
ADD docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 0755 /docker-entrypoint.sh
RUN useradd -ms /bin/bash user && chown -R user:user /opt/static_file_analysis/
RUN adduser user sudo
COPY sudoers /etc/sudoers
RUN chmod 0440 /etc/sudoers
WORKDIR /opt/static_file_analysis/
USER user
RUN wine wineboot --init
EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
#CMD ["git pull;/bin/bash"]
