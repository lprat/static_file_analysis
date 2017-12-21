#Docker Static File Analysis (SFA)
FROM debian:latest
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

RUN apt-get update && apt-get install -y build-essential git python-pip libjson-c-dev libxml2-dev libssl-dev libbz2-dev python-dev python-virtualenv xdot openssl vim zlib1g-dbg zlib1g zlib1g-dev
RUN cd /opt/ && git clone https://github.com/lprat/static_file_analysis
RUN cd /opt/static_file_analysis && git clone https://github.com/vrtadmin/clamav-devel
RUN cd /opt/static_file_analysis/clamav-devel && ./configure --enable-static --with-libjson && make
#bug to install hashlib
RUN rm -f /usr/lib/python2.7/lib-dynload/_hashlib.x86_64-linux-gnu.so
RUN pip install pydot yara-python hashlib
#hashlib

WORKDIR /opt/static_file_analysis/

CMD ["/bin/bash"]
